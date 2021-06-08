"""Wrapper for rpki-client"""
import asyncio
import itertools
import json
import logging
import os
import os.path
from rpkiclientweb.config import Configuration
import time
from dataclasses import dataclass, field
from typing import List, Optional

from prometheus_async.aio import time as time_metric, track_inprogress
from prometheus_client import Counter, Gauge, Histogram

from rpkiclientweb.outputparser import (
    OutputParser,
    WarningSummary,
    missing_labels,
)

LOG = logging.getLogger(__name__)

OUTPUT_BUFFER_SIZE = 8_388_608

# buckets from https://github.com/Netflix/rend/pull/93/files
RPKI_CLIENT_DURATION = Histogram(
    "rpkiclient_duration_seconds",
    "Time spent calling rpki-client",
    buckets=[
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        16,
        21,
        26,
        31,
        36,
        41,
        46,
        51,
        56,
        64,
        85,
        106,
        127,
        148,
        169,
        190,
        211,
        232,
        256,
        341,
        426,
        511,
        596,
        681,
        766,
    ],
)
RPKI_CLIENT_LAST_DURATION = Gauge(
    "rpkiclient_last_duration_seconds",
    "Duration of the last call to rpki-client",
)
RPKI_CLIENT_LAST_UPDATE = Gauge(
    "rpkiclient_last_update",
    "Timestamp of the last successful call to rpki-client",
)
RPKI_CLIENT_UPDATE_COUNT = Counter(
    "rpkiclient_update", "Number of rpki-client updates", ["returncode"]
)
RPKI_CLIENT_RUNNING = Gauge(
    "rpkiclient_running", "Number of running rpki-client instances"
)
RPKI_OBJECTS_COUNT = Gauge("rpki_objects", "Number of objects by type", ["type"])
RPKI_CLIENT_WARNINGS = Gauge(
    "rpkiclient_warnings", "Warnings from rpki-client", ["hostname", "type"]
)
RPKI_CLIENT_PULLING = Gauge(
    "rpkiclient_pulling",
    "Last time pulling from this repository was started (referenced).",
    ["uri"],
)
RPKI_CLIENT_FETCH_ERROR = Counter(
    "rpkiclient_fetch_error",
    "fetch errors encountered by rpki-client.",
    ["uri", "type"],
)
RPKI_CLIENT_PULLED = Gauge(
    "rpkiclient_pulled",
    "Last time repo was pulled (before process ended due to timeout).",
    ["uri"],
)
RPKI_CLIENT_REMOVED_UNREFERENCED = Counter(
    "rpkiclient_removed_unreferenced",
    "Number of removals of repositories that were no longer referenced.",
)


METADATA_LABELS = (
    "elapsedtime",
    "usertime",
    "systemtime",
    "roas",
    "failedroas",
    "invalidroas",
    "certificates",
    "failcertificates",
    "invalidcertificates",
    "manifests",
    "failedmanifests",
    "stalemanifests",
    "crls",
    "repositories",
    "vrps",
    "uniquevrps",
    "cachedir_del_files",
    "cachedir_del_dirs",
)
OPTIONAL_METADATA_LABELS = frozenset(
    [
        "failedroas",
        "invalidroas",
        "failcertificates",
        "invalidcertificates",
        "stalemanifests",
    ]
)


@dataclass
class ExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    duration: float


@dataclass
class RpkiClient:
    """Wrapper for rpki-client."""
    config: Configuration

    warnings: List[WarningSummary] = field(default_factory=list)
    last_update_repos: List[str] = frozenset()

    @property
    def args(self) -> List[str]:
        """Build rpki-client arguments."""
        if not os.path.isfile(self.config.rpki_client):
            raise ValueError(f"rpki_client: '{self.config.rpki_client}' does not exist")

        if self.config.rsync_command and not os.path.isfile(self.config.rsync_command):
            raise ValueError(f"rsync_command: '{self.config.rsync_command}' does not exist")

        if not os.path.isdir(self.config.cache_dir):
            raise ValueError(f"cache_dir: '{self.config.cache_dir}' is not a directory.")

        if not os.path.isdir(self.config.output_dir):
            raise ValueError(f"output_dir: '{self.config.output_dir}' is not a directory.")

        if not (not self.config.timeout or self.config.timeout >= -1):
            raise ValueError(f"illegal timeout: {self.config.timeout} -- should be >= -1")

        # Not using `-s [timeout]` for now because the timeout is managed from
        # this wrapping code.
        args = [
            "-v",  # verbose
            "-j",  # JSON output
            "-d",
            self.config.cache_dir,
        ]

        # Add additional options - ensure they are strings
        if self.config.additional_opts:
            args.extend(map(str, self.config.additional_opts))

        # Set rsync command if supplied
        if self.config.rsync_command:
            args.extend(["-e", self.config.rsync_command])

        for tal in zip(itertools.repeat("-t"), self.config.trust_anchor_locators):
            args.extend(tal)

        args.append(self.config.output_dir)

        return args

    @track_inprogress(RPKI_CLIENT_RUNNING)
    @time_metric(RPKI_CLIENT_DURATION)
    async def run(self) -> ExecutionResult:
        """Execute rpki-client."""
        LOG.info("executing %s %s", self.config.rpki_client, self.args)

        env = dict(os.environ)
        if self.config.deadline and self.config.deadline > 0:
            # Calculate and set deadline
            env["DEADLINE"] = str(time.time() + self.config.deadline)

        t0 = time.monotonic()

        proc = await asyncio.create_subprocess_exec(
            self.config.rpki_client.name,
            *self.args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=OUTPUT_BUFFER_SIZE,
            env=env,
        )

        try:
            if self.config.timeout > 0:
                await asyncio.wait_for(proc.wait(), self.config.timeout)
            else:
                await proc.wait()
        except asyncio.TimeoutError:
            LOG.error("timeout (%ds): killing %d", self.config.timeout, proc.pid)
            proc.kill()

        stdout, stderr = await proc.communicate()
        duration = time.monotonic() - t0
        LOG.info(
            "[%d] exited with %d in %f seconds", proc.pid, proc.returncode, duration
        )

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("stdout: %s", stdout)
            LOG.debug("stderr: %s", stderr)

        RPKI_CLIENT_UPDATE_COUNT.labels(returncode=proc.returncode).inc()
        RPKI_CLIENT_LAST_DURATION.set(duration)

        self.update_warning_metrics(stderr, proc.returncode == 0)

        asyncio.create_task(self.update_validated_objects_gauge(proc.returncode))

        return ExecutionResult(
            returncode=proc.returncode,
            stdout=stdout.decode(),
            stderr=stderr.decode(),
            duration=duration,
        )

    def update_warning_metrics(self, stderr: bytes, was_successful_run: bool) -> None:
        """Update the warning gauges."""
        parsed = OutputParser(stderr.decode("utf8"))

        # Delete labels for repos not included anymore (unreferenced)
        new_pulling = parsed.pulling

        if was_successful_run:
            for unreferenced_repo in self.last_update_repos - new_pulling:
                LOG.info("Removing unreferenced repository %s", unreferenced_repo)
                RPKI_CLIENT_REMOVED_UNREFERENCED.inc()
                try:
                    RPKI_CLIENT_PULLING.remove(unreferenced_repo)
                    RPKI_CLIENT_PULLED.remove(unreferenced_repo)
                except KeyError:
                    pass
        # Update pulling & pulled
        for repo in new_pulling:
            RPKI_CLIENT_PULLING.labels(repo).set_to_current_time()
        for repo in parsed.pulled:
            RPKI_CLIENT_PULLED.labels(repo).set_to_current_time()

        for fetch_status in parsed.fetch_status:
            RPKI_CLIENT_FETCH_ERROR.labels(uri=fetch_status.uri, type=fetch_status.type).inc(fetch_status.count)

        RPKI_OBJECTS_COUNT.labels(type="vanished_files").set(len(parsed.vanished_files))
        RPKI_OBJECTS_COUNT.labels(type="vanished_directories").set(
            len(parsed.vanished_directories)
        )

        new_warnings = parsed.statistics_by_host()
        # Set 'missing' metric-label values to 0 since missing values are
        # confusing (they disappear in prometheus and grafana)
        for missing in missing_labels(self.warnings, new_warnings):
            RPKI_CLIENT_WARNINGS.labels(
                type=missing.warning_type, hostname=missing.hostname
            ).set(0)

        # Set new values
        for warning in new_warnings:
            RPKI_CLIENT_WARNINGS.labels(
                type=warning.warning_type, hostname=warning.hostname
            ).set(warning.count)
        # And store
        self.warnings = new_warnings
        self.last_update_repos = new_pulling

    async def update_validated_objects_gauge(self, returncode: int) -> None:
        """
        Get statistics from `.metadata` of validated objects. Example output:
        ```
        {
          "buildmachine": "localhost.localdomain",
          "buildtime": "2020-05-28T09:45:59Z",
          "elapsedtime": "223",
          "usertime": "46",
          "systemtime": "57",

          "roas": 16245,
          "failedroas": 0,
          "invalidroas": 0,
          "certificates": 11835,
          "failcertificates": 0,
          "invalidcertificates": 0,
          "tals": 1,
          "talfiles": "/etc/pki/tals/ripe.tal",
          "manifests": 11835,
          "failedmanifests": 2,
          "stalemanifests": 0,
          "crls": 11833,
          "repositories": 13,
          "vrps": 87978,
          "uniquevrps": 87978,
          "cachedir_del_files": 105,
          "cachedir_del_dirs": 31
        }
        ```
        """
        json_path = self.config.output_dir / "json"

        if not json_path.is_file():
            LOG.warning("json output file (%s) is missing", json_path)
            return

        with open(json_path, "r") as json_res:
            metadata = json.load(json_res)["metadata"]
            missing_keys = set()

            for key in METADATA_LABELS:
                value = metadata.get(key, None)

                RPKI_OBJECTS_COUNT.labels(type=key).set(value)
                if key not in OPTIONAL_METADATA_LABELS and value is None:
                    missing_keys.add(key)

            if missing_keys:
                LOG.info(
                    "keys (%s) missing in json .metadata (%s)",
                    ", ".join(missing_keys),
                    json.dumps(metadata),
                )

        # Any error before this point will cause the last_update to fail and thus be visible in metrics.
        if returncode == 0:
            RPKI_CLIENT_LAST_UPDATE.set_to_current_time()
