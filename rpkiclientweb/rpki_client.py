import asyncio
import itertools
import json
import logging
import os.path
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import List, Optional

from prometheus_async.aio import time as time_metric
from prometheus_client import Counter, Gauge, Histogram, Summary
from yaml import dump, load

try:
    from yaml import CDumper as Dumper
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Dumper, Loader


LOG = logging.getLogger(__name__)

OUTPUT_BUFFER_SIZE = 8_388_608

RPKI_CLIENT_TIME = Histogram(
    "rpki_client_seconds",
    "Time spent calling rpki-client",
    buckets=[1, 6, 30, 60, 120, 180, 240, 300],
)
RPKI_OBJECTS_COUNT = Gauge("rpki_objects", "Number of objects by type", ["type"])
RPKI_CLIENT_UPDATE_COUNT = Counter(
    "rpki_client_update", "Number of rpki-client updates", ["returncode"]
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
    trust_anchor_locators: List[str] = list
    timeout: Optional[int] = None

    @property
    def args(self) -> List[str]:
        assert os.path.isfile(self.rpki_client)
        assert os.path.isdir(self.cache_dir)
        assert os.path.isdir(self.output_dir)
        assert not self.timeout or self.timeout >= -1

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

    @time_metric(RPKI_CLIENT_TIME)
    async def run(self) -> ExecutionResult:
        LOG.debug("executing %s %s", self.rpki_client, " ".join(self.args))
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
        LOG.info("[%d] exited with %d", proc.pid, proc.returncode)

        RPKI_CLIENT_UPDATE_COUNT.labels(returncode=proc.returncode).inc()

        if proc.returncode == 0:
            asyncio.create_task(self.update_validated_objects_gauge())

        return ExecutionResult(
            returncode=proc.returncode,
            stdout=stdout.decode(),
            stderr=stderr.decode(),
            duration=time.monotonic() - t0,
        )

    async def update_validated_objects_gauge(self) -> None:
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
        LABELS = (
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
        with open(os.path.join(self.output_dir, "json"), "r") as f:
            metadata = json.load(f)["metadata"]

            for key in LABELS:
                RPKI_OBJECTS_COUNT.labels(type=key).set(metadata.get(key, None))
