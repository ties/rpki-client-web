"""rpki-client wrapper with webserver and metrics."""
import argparse
import asyncio
import dataclasses
import logging
import os
import sys

from .config import Configuration
from .util import load_yaml
from .web import RpkiClientWeb

LOG = logging.getLogger("rpkiclientweb.__main__")


def main():
    """rpki-client wrapper."""
    parser = argparse.ArgumentParser("rpki-client wrapper")
    parser.add_argument(
        "-c", "--config", default="config.yml", type=argparse.FileType("r")
    )
    parser.add_argument("-v", "--verbose", action="count", default=1)
    # -1: interval from config, 0 = zero delay
    parser.add_argument(
        "-j",
        "--jitter",
        default=-1 if sys.stdin.isatty() else None,
        type=int,
        help="random delay of up to [jitter] before starting rpki-client for "
        "the first time. Defaults to 0 when in an interactive terminal, "
        "600 when non-interactive.",
    )

    args = parser.parse_args()
    config_file = load_yaml(args.config)

    conf = Configuration(config_file, jitter=args.jitter, verbosity=args.verbose)

    logging.basicConfig(handlers=[logging.StreamHandler(sys.stdout)])

    if conf.verbosity > 1:
        logging.getLogger().setLevel(logging.DEBUG)
        # Only log rpki-client output when very verbose.
        level = logging.INFO
        if conf.verbosity > 2:
            level = logging.DEBUG

        logging.getLogger("rpkiclientweb.rpki_client").setLevel(level)
    else:
        logging.getLogger().setLevel(logging.INFO)

    LOG.debug("Configuration: %s", dataclasses.asdict(conf))

    web = RpkiClientWeb(conf)
    asyncio.run(web.run())

    return 0


if __name__ == "__main__":
    sys.exit(main())
