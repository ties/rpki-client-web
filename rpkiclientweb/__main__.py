import argparse
import asyncio
import logging
import os
import sys

from yaml import Loader, dump, load

from .web import RpkiClientWeb

LOG = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser("rpki-client wrapper")
    parser.add_argument(
        "-c", "--config", default="config.yml", type=argparse.FileType("r")
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    # -1: interval from config, 0 = zero delay
    parser.add_argument(
        "-j",
        "--jitter",
        default=0 if os.isatty(sys.stdout.fileno()) else 600,
        type=int,
        help="random delay of up to [jitter] before starting rpki-client for the first time. Defaults to 0 when in an interactive terminal, 600 when non-interactive.",
    )

    args = parser.parse_args()

    logging.basicConfig(handlers=[logging.StreamHandler(sys.stdout)])

    if args.verbose > 0:
        logging.getLogger().setLevel(logging.DEBUG)
        # Only log rpki-client output when very verbose.
        level = logging.INFO
        if args.verbose > 1:
            level = logging.DEBUG

        logging.getLogger("rpkiclientweb.rpki_client").setLevel(level)
    else:
        logging.getLogger().setLevel(logging.INFO)

    conf = load(args.config, Loader=Loader)
    conf["jitter"] = args.jitter
    LOG.debug("Configuration: %s", conf)

    web = RpkiClientWeb(conf)
    asyncio.run(web.run())

    return 0


if __name__ == "__main__":
    sys.exit(main())
