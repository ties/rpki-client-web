"""Utilities."""
import asyncio
import json
import logging
import urllib.parse
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict, TextIO
from yaml import Loader, load

LOG = logging.getLogger(__name__)


async def repeat(
    interval: int,
    func: Callable[[Any], Awaitable[None]],
    *args,
    initial_delay: float = 0.0,
    **kwargs,
):
    """Await func every interval seconds.

    If func has not finished before *interval*, will run again
    immediately when the previous iteration finished.

    *args and **kwargs are passed as the arguments to func.
    """
    if initial_delay > 0:
        LOG.debug("Initial delay: %f seconds", initial_delay)
        await asyncio.sleep(initial_delay)
    LOG.info("Running %s every %d seconds", func, interval)
    while True:
        t_0 = time.time()
        try:
            await asyncio.wait_for(func(*args, **kwargs), interval)
            elapsed = time.time() - t_0
            await asyncio.sleep(interval - elapsed)
        except asyncio.TimeoutError:
            LOG.debug("Timeout waiting for %s", func)


def parse_host(incomplete_uri: str) -> str:
    """
    Get netloc/host from path uri.

    There are three possible structures:
    ```
    rpki.example.org/dir/file.ext
    rrdp/hex(sha256(rrdp_notification_url))/rrdp.example.org/file.ext
    rsync/rpki.example.org/file.ext
    ```

    """
    tokens = incomplete_uri.split("/")
    uri_tokens = ["unknown"]
    if len(tokens) < 2:
        raise ValueError(
            f"Expect at least one slash in path: rejected '{incomplete_uri}'"
        )

    if tokens[0] == "rrdp":
        uri_tokens = tokens[2:]
    elif tokens[0] == "rsync":
        uri_tokens = tokens[1:]
    else:
        uri_tokens = tokens

    # without // it is interpreted as relative
    return urllib.parse.urlparse(f"//{'/'.join(uri_tokens)}").netloc


def validate(should_be_true: bool, message: str, *args: str) -> None:
    """Validate that an assertion holds."""
    if not should_be_true:
        raise ValueError(message.format(*args))


def load_yaml(config_file: TextIO) -> Dict:
    """load a yaml file."""
    return load(config_file, Loader=Loader)


class CustomJSONEncoder(json.JSONEncoder):
    """JSON encoder for configuration objects."""

    def default(self, obj: Any) -> Any:
        """Encode object"""
        # Encode paths as their full name
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, Path):
            return str(obj)
        # Let the base class default method raise the TypeError if otherwise
        # unknown)
        return json.JSONEncoder.default(self, obj)


def json_dumps(obj: Any) -> str:
    """Dump configuration object to JSON string."""
    return json.dumps(obj, indent=2, cls=CustomJSONEncoder)
