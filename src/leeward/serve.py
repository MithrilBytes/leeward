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

import asyncio
import contextlib
from collections.abc import AsyncGenerator

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Route

from leeward.api import forecast, status
from leeward.config import LoadedConfig
from leeward.policy import CallTarget
from leeward.proxy import Proxy
from leeward.surfaces.fetch import mount_routes, refusal
from leeward.surfaces.llm import mount_routes as model_routes
from leeward.surfaces.mcp import Mounted, mount_servers


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

    mcp: Mounted | None = mount_servers(proxy) if proxy.config.surfaces.mcp.enabled else None

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncGenerator[None]:
        # A mounted Starlette app does not get a lifespan of its own, and the MCP
        # session manager needs one, so each mounted app's is entered here.
        async with contextlib.AsyncExitStack() as stack:
            for mounted in mcp.apps if mcp is not None else []:
                await stack.enter_async_context(mounted.router.lifespan_context(mounted))
            yield
            if mcp is not None:
                await mcp.aclose()
        if close_with_app:
            await proxy.aclose()

    routes: list[BaseRoute] = [
        Route("/leeward/status", status_endpoint, methods=["GET"]),
        Route("/leeward/forecast", forecast_endpoint, methods=["GET"]),
    ]
    if mcp is not None:
        routes += mcp.routes
    if proxy.config.surfaces.llm.enabled:
        # Before the fetch mounts: a mount named v1 must not shadow the model endpoint.
        routes += model_routes(proxy)
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
    """Run the proxy until it is stopped.

    The forward proxy gets a port of its own because it is a different kind of server:
    it tunnels rather than answers, and a client points `HTTPS_PROXY` at it.
    """
    from leeward.surfaces.forward import ForwardProxy

    proxy = Proxy(loaded)
    host, port = listen_address(loaded)
    config = uvicorn.Config(
        build_app(proxy), host=host, port=port, log_level="warning", access_log=False
    )
    shared = uvicorn.Server(config)
    forward = loaded.config.surfaces.forward
    if not forward.enabled:
        await shared.serve()
        return
    tunnel = ForwardProxy(proxy)
    tunnel_host, _, tunnel_port = forward.listen.rpartition(":")
    await tunnel.start(tunnel_host, int(tunnel_port))
    try:
        async with asyncio.TaskGroup() as group:
            group.create_task(shared.serve())
            group.create_task(tunnel.serve_forever())
    finally:
        await tunnel.aclose()
