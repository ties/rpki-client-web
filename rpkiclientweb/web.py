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

from rpkiclientweb.config import Configuration
from rpkiclientweb.rpki_client import ExecutionResult, RpkiClient
from rpkiclientweb.util import json_dumps, repeat

LOG = logging.getLogger(__name__)

OUTPUT_BUFFER_SIZE = 8_388_608


class RpkiClientWeb:
    """rpki client wrapper webserver and orchestrator."""

    result: Optional[ExecutionResult] = None
    config: Configuration
    app: web.Application

    finished_initial_run: bool = False

    def __init__(self, config: Configuration) -> None:
        self.app = web.Application()

        self.config = config

        self.client = RpkiClient(self.config)

        self.app.add_routes(
            [
                web.get("/", self.index),
                web.get("/config", self.config_response),
                web.get("/metrics", aio.web.server_stats),
                web.get("/result", self.json_result),
                web.get("/objects/validated", self.validated_objects),
                web.static(
                    "/cache",
                    self.config.cache_dir,
                    follow_symlinks=False,
                    show_index=True,
                ),
            ]
        )

    async def index(self, req) -> web.Response:
        return web.Response(
            text=f"""<html>
            <head><title>rpki-client wrapper</title></head>
            <body>
                <h1>rpki-client wrapper</h1>
                <p><a href="/cache">Cache directory</a></p>
                <p><a href="/config">Configuration</a></p>
                <p><a href="/metrics">Metrics</a></p>
                <p><a href="/objects/validated">Validated objects</a></p>
                <p><a href="/result">Result</a></p>
                <p>{f"Process exited with {self.result.returncode} in {self.result.duration}s" if self.result else "No output available (yet)"}</p>
                {f"<p><h3>stdout</h3></p><p><pre>{self.result.stdout}</pre></p>" if self.result else ""}
                {f"<p><h3>stderr</h3></p><p><pre>{self.result.stderr}</pre></p>" if self.result else ""}
            </body>
        </html>""",
            content_type="text/html",
        )

    async def config_response(self, req) -> web.Response:
        """return the configuration."""
        return web.json_response(self.config, dumps=json_dumps)

    async def validated_objects(self, req) -> web.FileResponse:
        """return the validated objects json."""
        path = self.config.output_dir / "json"
        if path.is_file():
            return web.FileResponse(path, headers={"Content-Type": "application/json"})

        status = (
            "validated objects JSON file is not available at the moment."
            if self.finished_initial_run
            else "initial validation run has not finished yet.",
        )
        raise web.HTTPServiceUnavailable(
            text=json_dumps(
                {
                    "status": status,
                    "output": self.result,
                }
            ),
            content_type="application/json",
        )

    async def call_client(self) -> None:
        """Run the rpki-client wrapper again."""
        self.result = await self.client.run()
        self.finished_initial_run = True

    async def json_result(self, req) -> web.Response:
        if self.result:
            return web.json_response(self.result, dumps=json_dumps)

        return web.json_response(None, status=500)

    async def run(self):
        """Run rpki-client in loop."""
        listening_on = self.config.host if self.config.host else "[all interfaces]"
        LOG.info("starting webserver on %s:%d", listening_on, self.config.port)
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.host, self.config.port)

        site_task = asyncio.create_task(site.start())

        if self.config.jitter:
            jitter_delay = random.uniform(0, self.config.jitter)
            LOG.info(
                "delaying by random delay of [0, %d] seconds of %f seconds",
                self.config.jitter,
                jitter_delay,
            )

            await asyncio.sleep(jitter_delay)

        # Start the scheduling loop
        return await asyncio.gather(
            repeat(self.config.interval, self.call_client), site_task
        )
