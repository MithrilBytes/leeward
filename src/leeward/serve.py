# SPDX-License-Identifier: Apache-2.0
"""Assembling the surfaces into one application, and running it.

The MCP, fetch and model surfaces share a listener because they share everything
behind it: one cache, one set of breakers, one ledger of runs, one event log. The
forward proxy is a different kind of server, tunnelling rather than answering, and
gets a port of its own.

`/leeward/status` and `/leeward/forecast` are mounted first and answer from local
state, so they still work when everything they describe is unreachable.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncGenerator

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from leeward.api import forecast, status
from leeward.config import LoadedConfig
from leeward.policy import CallTarget
from leeward.proxy import Proxy
from leeward.surfaces.fetch import mount_routes, refusal


def build_app(proxy: Proxy, *, close_with_app: bool = True) -> Starlette:
    """The application for every surface that shares a listener."""

    async def status_endpoint(_request: Request) -> Response:
        return JSONResponse(status(proxy))

    async def forecast_endpoint(request: Request) -> Response:
        asked = request.query_params.get("url") or request.query_params.get("tool")
        if not asked:
            return refusal(400, "GET /leeward/forecast needs a url or tool parameter")
        try:
            target = CallTarget.parse(asked)
        except ValueError as exc:
            return refusal(400, str(exc))
        return JSONResponse(forecast(proxy, target).as_dict())

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncGenerator[None]:
        yield
        if close_with_app:
            await proxy.aclose()

    routes = [
        Route("/leeward/status", status_endpoint, methods=["GET"]),
        Route("/leeward/forecast", forecast_endpoint, methods=["GET"]),
    ]
    if proxy.config.surfaces.fetch.enabled:
        routes += mount_routes(proxy)
    return Starlette(routes=routes, lifespan=lifespan)


def listen_address(loaded: LoadedConfig) -> tuple[str, int]:
    """The one address the shared surfaces listen on."""
    surfaces = loaded.config.surfaces
    for surface in (surfaces.fetch, surfaces.mcp, surfaces.llm):
        if surface.enabled:
            host, _, port = surface.listen.rpartition(":")
            return host, int(port)
    host, _, port = surfaces.fetch.listen.rpartition(":")
    return host, int(port)


async def run(loaded: LoadedConfig) -> None:
    """Run the proxy until it is stopped."""
    proxy = Proxy(loaded)
    host, port = listen_address(loaded)
    config = uvicorn.Config(
        build_app(proxy), host=host, port=port, log_level="warning", access_log=False
    )
    await uvicorn.Server(config).serve()
