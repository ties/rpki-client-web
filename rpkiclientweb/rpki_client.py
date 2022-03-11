"""Wrapper for rpki-client"""
import asyncio
import datetime
import itertools
import json
import logging
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List

from prometheus_async.aio import time as time_metric
from prometheus_async.aio import track_inprogress

from rpkiclientweb.config import Configuration
from rpkiclientweb.metrics import (
    RPKI_CLIENT_DURATION,
    RPKI_CLIENT_FETCH_STATUS,
    RPKI_CLIENT_LAST_DURATION,
    RPKI_CLIENT_LAST_UPDATE,
    RPKI_CLIENT_PULLED,
    RPKI_CLIENT_PULLING,
    RPKI_CLIENT_REMOVED_UNREFERENCED,
    RPKI_CLIENT_RUNNING,
    RPKI_CLIENT_UPDATE_COUNT,
    RPKI_CLIENT_WARNINGS,
    RPKI_OBJECTS_VRPS_BY_TA,
    RPKI_OBJECTS_BUILD_TIME,
    RPKI_OBJECTS_COUNT,
    RPKI_OBJECTS_MIN_EXPIRY,
    RPKI_OBJECTS_VRPS_BY_TA,
)
from rpkiclientweb.outputparser import OutputParser, WarningSummary, missing_labels
from rpkiclientweb.util import json_dumps

LOG = logging.getLogger(__name__)
LOG_STDOUT = LOG.getChild("stdout")
LOG_STDERR = LOG.getChild("stderr")

OUTPUT_BUFFER_SIZE = 8_388_608

#
# Authoratitive source for what labels exist:
# http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.sbin/rpki-client/output-json.c
#

BUILDTIME_KEY = "buildtime"
METADATA_LABELS = (
    # ignore "buildmachine"
    "buildtime",
    "elapsedtime",
    "usertime",
    "systemtime",
    "roas",
    "failedroas",
    "invalidroas",
    "bgpsec_router_keys",
    "invalidbgpsec_router_keys",
    "bgpsec_pubkeys",
    "certificates",
    "failcertificates",
    "invalidcertificates",
    "tals",
    # ignore "talfiles" strings
    "manifests",
    "failedmanifests",
    "stalemanifests",
    "crls",
    "gbrs",
    "repositories",
    "vrps",
    "uniquevrps",
    "cachedir_del_files",
    "cachedir_superfluous_files",
    "cachedir_del_dirs",
)
OPTIONAL_METADATA_LABELS = frozenset(
    [
        # recent attribute (2022-03-11)
        "bgpsec_pubkeys",
        "failedroas",
        "invalidroas",
        "failcertificates",
        "invalidcertificates",
        "stalemanifests",
        # not present on 7.3 on fedora:
        "bgpsec_router_keys",
        "invalidbgpsec_router_keys",
        "gbrs",
        "cachedir_del_files",
        "cachedir_del_dirs",
        # recent attribute (2022-03-11)
        "cachedir_superfluous_files",
    ]
)


@dataclass
class ExecutionResult:
    """Execution result (exit code + output)."""

    returncode: int
    stdout: str
    stderr: str
    duration: float


@dataclass
class RpkiClient:
    """Wrapper for rpki-client."""

    config: Configuration

    warnings: List[WarningSummary] = field(default_factory=list)
    last_update_repos: FrozenSet[str] = frozenset()

    @property
    def args(self) -> List[str]:
        """Build rpki-client arguments."""
        if not self.config.rpki_client.is_file():
            raise ValueError(f"rpki_client: '{self.config.rpki_client}' does not exist")

        if self.config.rsync_command and not self.config.rsync_command.is_file():
            raise ValueError(
                f"rsync_command: '{self.config.rsync_command}' does not exist"
            )

        if not self.config.cache_dir.is_dir():
            raise ValueError(
                f"cache_dir: '{self.config.cache_dir}' is not a directory."
            )

        if not self.config.output_dir.is_dir():
            raise ValueError(
                f"output_dir: '{self.config.output_dir}' is not a directory."
            )

        if not (not self.config.timeout or self.config.timeout >= -1):
            raise ValueError(
                f"illegal timeout: {self.config.timeout} -- should be >= -1"
            )

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
        LOG.info(
            "executing %s %s",
            self.config.rpki_client,
            json_dumps(self.args, indent=None),
        )

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

        # log lines to separate lines - requested feature because some setups
        # truncate log output.
        if LOG_STDOUT.isEnabledFor(logging.DEBUG):
            for line in stdout.decode(errors="replace").splitlines():
                LOG_STDOUT.debug(line)
        if LOG_STDERR.isEnabledFor(logging.DEBUG):
            for line in stderr.decode(errors="replace").splitlines():
                LOG_STDERR.debug(line)

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
            RPKI_CLIENT_FETCH_STATUS.labels(
                uri=fetch_status.uri, type=fetch_status.type
            ).inc(fetch_status.count)

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

    # TODO: Update to TypedDict when only supporting 3.8+
    def __update_object_expiry(self, roas: List[Dict]) -> None:
        # roas may not be sorted by ta. Using `itertools.groupby` would require
        # a sort - so just do this in code.
        # ta name -> timestamp
        min_expires_by_ta: Dict[str, int] = dict()
        vrps_by_ta: Dict[str, int] = Counter()

        for roa in roas:
            ta = roa.get("ta", None)
            expires = roa.get("expires", None)
            if ta is not None:
                vrps_by_ta[ta] += 1
                if expires is not None:
                    # take expires when not found, otherwise, min value.
                    min_expires_by_ta[ta] = min(
                        min_expires_by_ta.get(ta, expires), expires
                    )

        for ta, vrp_count in vrps_by_ta.items():
            RPKI_OBJECTS_VRPS_BY_TA.labels(ta=ta).set(vrp_count)

        # Might be an empty loop - which is no problem
        for ta, min_expires in min_expires_by_ta.items():
            RPKI_OBJECTS_MIN_EXPIRY.labels(ta=ta).set(min_expires)

    async def update_validated_objects_gauge(self, returncode: int) -> None:
        """
        Get statistics from `.metadata` of validated objects. Example output:
        ```
        {
          "buildmachine": "fedora35.localdomain",
          "buildtime": "2022-03-11T10:42:02Z",
          "elapsedtime": "139",
          "usertime": "129",
          "systemtime": "9",
          "roas": 62544,
          "failedroas": 1,
          "invalidroas": 0,
          "bgpsec_pubkeys": 2,
          "certificates": 27355,
          "invalidcertificates": 0,
          "tals": 4,
          "invalidtals": 0,
          "talfiles": [
            "/etc/pki/tals/afrinic.tal",
            "/etc/pki/tals/apnic.tal",
            "/etc/pki/tals/lacnic.tal",
            "/etc/pki/tals/ripe.tal"
          ],
          "manifests": 27353,
          "failedmanifests": 5,
          "stalemanifests": 7,
          "crls": 27341,
          "gbrs": 2,
          "repositories": 44,
          "vrps": 270611,
          "uniquevrps": 267623,
          "cachedir_del_files": 28,
          "cachedir_superfluous_files": 4965,
          "cachedir_del_dirs": 1346
        }
        ```
        """
        json_path = self.config.output_dir / "json"

        if not json_path.is_file():
            LOG.warning("json output file (%s) is missing", json_path)
            return

        with json_path.open("r") as json_res:
            data = json.load(json_res)

            self.__update_object_expiry(data["roas"])

            metadata = data["metadata"]
            missing_keys = set()

            for key in METADATA_LABELS:
                value = metadata.get(key, None)

                if key == BUILDTIME_KEY and value is not None:
                    # format from
                    # https://github.com/rpki-client/rpki-client-openbsd/blob/92e173c2a0accb425e1130192655d1b57928d986/src/usr.sbin/rpki-client/output-json.c#L36
                    buildtime = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
                    RPKI_OBJECTS_BUILD_TIME.set(buildtime.timestamp())
                elif value is not None:
                    RPKI_OBJECTS_COUNT.labels(type=key).set(value)
                elif key not in OPTIONAL_METADATA_LABELS:
                    missing_keys.add(key)

            if missing_keys:
                LOG.info(
                    "keys (%s) missing in json .metadata (%s)",
                    ", ".join(missing_keys),
                    json.dumps(metadata),
                )

        # Any error before this point will cause the last_update to fail and
        # thus be visible in metrics.
        if returncode == 0:
            RPKI_CLIENT_LAST_UPDATE.set_to_current_time()
