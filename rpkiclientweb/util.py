import asyncio
import logging

from typing import Callable

LOG = logging.getLogger(__name__)


async def repeat(interval: int, func: Callable, *args, **kwargs):
    """Run func every interval seconds.

    If func has not finished before *interval*, will run again
    immediately when the previous iteration finished.

    *args and **kwargs are passed as the arguments to func.
    """
    LOG.info("Running %s every %d seconds", func, interval)
    while True:
        await asyncio.gather(
            func(*args, **kwargs),
            asyncio.sleep(interval),
        )
