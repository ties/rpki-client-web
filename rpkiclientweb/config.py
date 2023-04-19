"""
Config file support.

TODO: Consider using https://pypi.org/project/voluptuous/ or
https://docs.python-cerberus.org/en/stable/
"""
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .util import validate

LOG = logging.getLogger(__name__)


@dataclass
class Configuration:
    """Configuration object."""

    jitter: int
    """verbosity."""
    verbosity: int

    """ Cache directory for rpki-client. """
    cache_dir: Path
    """ Output directory. """
    output_dir: Path

    """ Interval between rpki-client runs. """
    interval: int
    """ Timeout before rpki-client is killed. """
    timeout: int

    """ port to listen on. """
    port: int

    """ Path to rpki-client. """
    rpki_client: Path

    """
    deadline: DEADLINE environment variable is passed to process with Unix
    timestamp of [deadline] seconds after run starts.
    Can be used to, for example, exit rsync early.

    This environment variable is not set if the configuration property is not
    set.
    """
    deadline: int

    """
    host to listen on.

    Leave empty to listen on all interfaces on both IPv4 and IPv6
    """
    host: Optional[str] = None

    """Optional path to rsync binary or wrapper. """
    rsync_command: Optional[Path] = None

    """ Additional rpki-client options. """
    additional_opts: List[str] = field(default_factory=list)

    """ Paths of Trust Anchor Locator files. """
    trust_anchor_locators: List[Path] = field(default_factory=list)

    def __init__(
        self, conf: Dict, jitter: Optional[int] = None, verbosity: Optional[int] = None
    ) -> None:
        LOG.info("Configuration: %s", conf)

        if jitter is not None:
            self.jitter = 0 if jitter == -1 else jitter
        else:
            self.jitter = conf.get("jitter", 600)

        self.verbosity = int(conf.get("verbosity", 1) if not verbosity else verbosity)

        self.cache_dir = Path(conf["cache_dir"]).resolve()
        validate(
            self.cache_dir.is_dir(),
            "Cache directory '{}' is not a directory",
            str(self.cache_dir),
        )

        self.output_dir = Path(conf["output_dir"]).resolve()
        validate(
            self.output_dir.is_dir(),
            "Output directory '{}' is not a directory",
            str(self.output_dir),
        )

        self.interval = conf.get("interval", None)
        validate(self.interval is not None, "interval needs to be set")
        validate(self.interval > 0, "Interval needs to be a positive integer")

        self.deadline = conf.get("deadline", -1)
        validate(
            self.deadline <= self.interval,
            f"deadline needs to be below interval ({self.interval}) or use "
            "missing or -1 to disable",
        )

        self.timeout = conf.get("timeout", None)
        validate(self.timeout is not None, "timeout needs to be set")
        validate(self.timeout <= self.interval, "timeout needs to be below interval")

        self.host = conf.get("host", None)
        self.port = conf.get("port", 8888)
        validate(self.port > 0, "Port should be > 0")

        self.rpki_client = Path(conf["rpki_client"]).resolve()
        validate(
            self.rpki_client.is_file(),
            "rpki-client binary should be a file - {} is not.",
            str(self.rpki_client),
        )

        if conf.get("rsync_command", None):
            self.rsync_command = Path(conf["rsync_command"]).resolve()
            validate(
                self.rsync_command.is_file(),
                "rsync command ({}) should be a file",
                str(self.rsync_command),
            )

        self.additional_opts = conf.get("additional_opts", [])

        self.trust_anchor_locators = [
            Path(ta).resolve() for ta in conf.get("trust_anchor_locators", [])
        ]
        validate(
            len(self.trust_anchor_locators) > 0, "trust_anchor_locators are required."
        )
        for ta in self.trust_anchor_locators:
            validate(ta.is_file(), "trust anchor locator ({}) should be a file", ta)
