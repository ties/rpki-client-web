import asyncio
import itertools
import logging
import os.path
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import List, Optional

from yaml import dump, load

try:
    from yaml import CDumper as Dumper
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Dumper, Loader


LOG = logging.getLogger(__name__)

OUTPUT_BUFFER_SIZE = 8_388_608


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

        return ExecutionResult(
            returncode=proc.returncode,
            stdout=stdout.decode(),
            stderr=stderr.decode(),
            duration=time.monotonic() - t0,
        )
