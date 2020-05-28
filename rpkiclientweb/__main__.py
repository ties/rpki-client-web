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
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    logging.basicConfig()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    conf = load(args.config, Loader=Loader)
    LOG.debug("Configuration: %s", conf)

    # interval = conf.pop('interval')
    # client = RpkiClient(**conf)

    # asyncio.run(repeat(interval, client.run))
    web = RpkiClientWeb(conf)
    asyncio.run(web.run())

    return 0


if __name__ == "__main__":
    sys.exit(main())
