"""Wrapper for rpki-client"""
import asyncio
import itertools
import json
import logging
import os.path
import time
from dataclasses import dataclass, field
from typing import List, Optional

from prometheus_async.aio import time as time_metric, track_inprogress
from prometheus_client import Counter, Gauge, Histogram

from .outputparser import (
    parse_rpki_client_output,
    statistics_by_host,
    WarningSummary,
    missing_labels,
)

LOG = logging.getLogger(__name__)

OUTPUT_BUFFER_SIZE = 8_388_608

RPKI_CLIENT_DURATION = Histogram(
    "rpkiclient_duration_seconds",
    "Time spent calling rpki-client",
    buckets=[1, 3, 6, 12, 18, 24, 30, 44, 60, 72, 84, 96, 108, 120, 150, 180, 240, 300],
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


METADATA_LABELS = (
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
    """Maps onto the config.yml"""

    rpki_client: str
    cache_dir: str
    output_dir: str
    trust_anchor_locators: List[str] = field(default_factory=list)
    timeout: Optional[int] = None

    warnings: List[WarningSummary] = field(default_factory=list)

    @property
    def args(self) -> List[str]:
        if not os.path.isfile(self.rpki_client):
            raise ValueError(f"rpki_client: '{self.rpki_client}' does not exist")

        if not os.path.isdir(self.cache_dir):
            raise ValueError(f"cache_dir: '{self.cache_dir}' is not a directory.")

        if not os.path.isdir(self.output_dir):
            raise ValueError(f"output_dir: '{self.output_dir}' is not a directory.")

        if not (not self.timeout or self.timeout >= -1):
            raise ValueError(f"illegal timeout: {self.timeout} -- should be >= -1")

        args = [
            "-v",  # verbose
            "-j",  # JSON output
            "-d",
            os.path.abspath(self.cache_dir),
        ]

        for tal in zip(itertools.repeat("-t"), self.trust_anchor_locators):
            args.extend(tal)

        args.append(os.path.abspath(self.output_dir))

        return args

    @track_inprogress(RPKI_CLIENT_RUNNING)
    @time_metric(RPKI_CLIENT_DURATION)
    async def run(self) -> ExecutionResult:
        LOG.info("executing %s %s", self.rpki_client, " ".join(self.args))
        t0 = time.monotonic()

        proc = await asyncio.create_subprocess_exec(
            self.rpki_client,
            *self.args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=OUTPUT_BUFFER_SIZE,
        )

        try:
            if self.timeout > 0:
                await asyncio.wait_for(proc.wait(), self.timeout)
            else:
                await proc.wait()
        except asyncio.TimeoutError:
            LOG.error("timeout (%ds): killing %d", self.timeout, proc.pid)
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

        self.update_warning_metrics(stderr)

        asyncio.create_task(self.update_validated_objects_gauge(proc.returncode))

        return ExecutionResult(
            returncode=proc.returncode,
            stdout=stdout.decode(),
            stderr=stderr.decode(),
            duration=duration,
        )

    def update_warning_metrics(self, stderr: bytes) -> None:
        """Update the warning gauges."""
        warnings = parse_rpki_client_output(stderr.decode("utf8"))
        new_warnings = statistics_by_host(warnings)

        LOG.debug("new_warnings: %s", new_warnings)

        # Remove labels that are missing
        for missing_label in missing_labels(self.warnings, new_warnings):
            LOG.debug("Removing label %s", missing_label)
            RPKI_CLIENT_WARNINGS.remove(
                type=missing_label.warning_type, hostname=missing_label.hostname
            )

        # Set new values
        for warning in new_warnings:
            RPKI_CLIENT_WARNINGS.labels(
                type=warning.warning_type, hostname=warning.hostname
            ).set(warning.count)
        # And store
        self.warnings = new_warnings

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
          "uniquevrps": 87978
        }
        ```
        """
        json_path = os.path.join(self.output_dir, "json")

        if not os.path.isfile(json_path):
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

        if returncode == 0:
            RPKI_CLIENT_LAST_UPDATE.set_to_current_time()
