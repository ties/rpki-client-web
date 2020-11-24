import argparse
import asyncio
import logging
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
    LOG.debug("Configuration: %s", conf)

    web = RpkiClientWeb(conf)
    asyncio.run(web.run())

    return 0


if __name__ == "__main__":
    sys.exit(main())
