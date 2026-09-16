# SPDX-License-Identifier: Apache-2.0
"""The HTTP surface: point a tool's base URL at leeward and change nothing else.

A mount maps a name to an origin, so a tool that called `https://origin/path` calls
`http://127.0.0.1:8787/<mount>/path` instead. Method, headers and body go through
untouched; what comes back is the origin's response with leeward's own headers
added, or a copy of an earlier one, or a failure written as JSON that says what
happened and whether waiting will help.

`GET /fetch?url=` exists for tools that take a whole URL rather than a base. It is
restricted to an allowlist, because a proxy that will fetch anything for anyone is
an open proxy even on loopback.

TLS terminates on leeward's own outbound connection, so an https origin is cached
here without anything intercepting the agent's own traffic.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from fnmatch import fnmatchcase
from urllib.parse import urlsplit, urlunsplit

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from leeward.budget import resolve_run
from leeward.proxy import HOP_BY_HOP, HttpRequest, Proxy, Served
from leeward.vocab import Surface

RUN_HEADER = "x-leeward-run"
ACCEPT_STALE_HEADER = "x-leeward-accept-stale"
NOT_FORWARDED = HOP_BY_HOP | {"host", "content-length", RUN_HEADER, ACCEPT_STALE_HEADER}


def refusal(status: int, message: str) -> Response:
    """leeward's own refusal, marked as leeward's rather than dressed as an origin's."""
    body = json.dumps({"error": "leeward", "message": message}, ensure_ascii=False, indent=2)
    return Response(
        content=body.encode("utf-8"),
        status_code=status,
        media_type="application/json",
        headers={"X-Leeward-Outcome": "DOWN"},
    )


def _forwarded(request: Request) -> tuple[tuple[str, str], ...]:
    return tuple(
        (name.decode("latin-1"), value.decode("latin-1"))
        for name, value in request.headers.raw
        if name.decode("latin-1").lower() not in NOT_FORWARDED
    )


def _run_of(request: Request) -> object:
    client = request.client
    connection = f"{client.host}:{client.port}" if client is not None else None
    return resolve_run(header=request.headers.get(RUN_HEADER), connection=connection)


def _respond(served: Served) -> Response:
    response = Response(content=served.body, status_code=served.status)
    keep = [
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in served.headers
        if name.lower() not in {"content-length"}
    ]
    response.raw_headers = [*keep, (b"content-length", str(len(served.body)).encode("latin-1"))]
    return response


def _allowed(host: str | None, patterns: Sequence[str]) -> bool:
    lowered = (host or "").lower()
    return bool(lowered) and any(fnmatchcase(lowered, pattern.lower()) for pattern in patterns)


def mount_routes(proxy: Proxy) -> list[Route]:
    """One route for the generic fetch, one for everything under a mount."""
    surface = proxy.config.surfaces.fetch

    async def generic(request: Request) -> Response:
        if not surface.generic_fetch.enabled:
            return refusal(404, "generic fetch is not enabled")
        target = request.query_params.get("url")
        if not target:
            return refusal(400, "GET /fetch needs a url parameter")
        parts = urlsplit(target)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return refusal(400, f"{target} is not an http or https URL")
        if not _allowed(parts.hostname, surface.generic_fetch.allow_hosts):
            return refusal(
                403,
                f"{parts.hostname} is not in surfaces.fetch.generic_fetch.allow_hosts,"
                " which is the list of hosts this proxy will fetch for you",
            )
        return await _call(request, target)

    async def mounted(request: Request) -> Response:
        name = request.path_params["mount"]
        origin = surface.mounts.get(str(name))
        if origin is None:
            known = ", ".join(sorted(surface.mounts)) or "none"
            return refusal(404, f"no mount named {name}; configured mounts: {known}")
        path = str(request.path_params.get("path", ""))
        base = urlsplit(origin)
        joined = f"{base.path.rstrip('/')}/{path}".replace("//", "/") if path else base.path or "/"
        target = urlunsplit((base.scheme, base.netloc, joined, request.url.query, ""))
        return await _call(request, target)

    async def _call(request: Request, target: str) -> Response:
        body = await request.body()
        served = await proxy.fetch(
            HttpRequest(
                method=request.method,
                url=target,
                headers=_forwarded(request),
                body=body,
                accept_stale=request.headers.get(ACCEPT_STALE_HEADER, "") == "1",
            ),
            _run_of(request),  # pyright: ignore[reportArgumentType]
            surface=Surface.FETCH,
        )
        return _respond(served)

    return [
        Route("/fetch", generic, methods=["GET", "HEAD"]),
        Route(
            "/{mount}/{path:path}",
            mounted,
            methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
        ),
    ]
