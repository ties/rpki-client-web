import asyncio
import dataclasses
import json
import logging
import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from aiohttp import web

from rpki_client.rpki_client import ExecutionResult, RpkiClient

LOG = logging.getLogger(__name__)

OUTPUT_BUFFER_SIZE = 8_388_608


async def repeat(interval: int, func: Callable, *args, **kwargs):
    """Run func every interval seconds.

    If func has not finished before *interval*, will run again
    immediately when the previous iteration finished.

    *args and **kwargs are passed as the arguments to func.
    """
    LOG.info("Running %s every %d seconds", func, interval)
    while True:
        await asyncio.gather(
            func(*args, **kwargs), asyncio.sleep(interval),
        )


class RpkiClientWeb:
    result: Optional[ExecutionResult] = None
    conf: Dict
    app: web.Application

    host: str
    port: int

    interval: int

    def __init__(self, conf: Dict) -> None:
        self.app = web.Application()

        self.interval = conf.pop("interval")
        self.host = conf.pop("host", "localhost")
        self.port = conf.pop("port", 8080)
        self.conf = conf

        self.app.add_routes(
            [
                web.get("/result", self.json_result),
                web.get("/objects/validated", self.validated_objects),
                web.static(
                    "/cache",
                    os.path.abspath(conf["cache_dir"]),
                    follow_symlinks=False,
                    show_index=True,
                ),
            ]
        )

    async def validated_objects(self, req) -> web.FileResponse:
        path = os.path.join(os.path.abspath(self.conf["output_dir"]), "json")
        return web.FileResponse(path)

    async def call_client(self) -> None:
        client = RpkiClient(**self.conf)

        self.result = await client.run()

    async def json_result(self, req) -> web.Response:
        if self.result:
            return web.Response(text=json.dumps(dataclasses.asdict(self.result)))

        return web.Response(status=500)

    async def run(self):
        LOG.info("starting webserver on %s:%d", self.host, self.port)
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)

        # await site.start()
        return await asyncio.gather(
            repeat(self.interval, self.call_client), site.start()
        )
