import asyncio
import dataclasses
import json
import logging
import os
import random
from dataclasses import dataclass
from typing import Dict, List, Optional

from aiohttp import web
from prometheus_async import aio

from rpkiclientweb.rpki_client import ExecutionResult, RpkiClient
from rpkiclientweb.util import repeat

LOG = logging.getLogger(__name__)

OUTPUT_BUFFER_SIZE = 8_388_608


class RpkiClientWeb:
    result: Optional[ExecutionResult] = None
    conf: Dict
    app: web.Application

    host: str
    port: int

    interval: int
    jitter: int

    def __init__(self, conf: Dict) -> None:
        self.app = web.Application()

        self.interval = conf.pop("interval")
        # default to the interval for jitter value
        self.jitter = conf.pop("jitter")
        self.host = conf.pop("host", "localhost")
        self.port = conf.pop("port", 8080)
        self.conf = conf

        self.client = RpkiClient(**self.conf)

        self.app.add_routes(
            [
                web.get("/", self.index),
                web.get("/config", self.config_response),
                web.get("/metrics", aio.web.server_stats),
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

    async def index(self, req) -> web.Response:
        return web.Response(
            text="""<html>
            <head><title>rpki-client wrapper</title></head>
            <body>
                <h1>rpki-client wrapper</h1>
                <p><a href="/cache">Cache directory</a></p>
                <p><a href="/config">Configuration</a></p>
                <p><a href="/metrics">Metrics</a></p>
                <p><a href="/objects/validated">Validated objects</a></p>
                <p><a href="/result">Result</a></p>
            </body>
        </html>""",
            content_type="text/html",
        )

    async def config_response(self, req) -> web.Response:
        return web.json_response(self.conf)

    async def validated_objects(self, req) -> web.FileResponse:
        path = os.path.join(os.path.abspath(self.conf["output_dir"]), "json")
        return web.FileResponse(path)

    async def call_client(self) -> None:
        """Run the rpki-client wrapper again."""
        self.result = await self.client.run()

    async def json_result(self, req) -> web.Response:
        if self.result:
            return web.json_response(dataclasses.asdict(self.result))

        return web.json_response(None, status=500)

    async def run(self):
        LOG.info("starting webserver on %s:%d", self.host, self.port)
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)

        asyncio.create_task(site.start())

        if self.jitter:
            jitter_delay = random.uniform(0, self.jitter)
            LOG.info(
                "delaying by random delay of [0, %d] seconds of %f seconds",
                self.jitter,
                jitter_delay,
            )

            await asyncio.sleep(jitter_delay)

        # Start the scheduling loop
        return await repeat(self.interval, self.call_client)
