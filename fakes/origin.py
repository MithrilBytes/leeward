# SPDX-License-Identifier: Apache-2.0
"""A configurable HTTP origin on real sockets, shared by the tests and the demo.

It is written by hand rather than on a framework because the interesting behaviours
are the ones a framework hides: a connection accepted and never answered, a body
that stops halfway, a reply that arrives after the deadline has passed. Those are
what leeward exists to survive, so the tests have to produce them over a real
socket, with a real timeout, rather than by patching a client.

It also counts what it served and how many connections are open, which is how a
test can show that a cancelled call released its connection instead of leaving it
to a garbage collector.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from urllib.parse import unquote

CRLF = b"\r\n"
HEADER_LIMIT = 64 * 1024
REASONS = {
    200: "OK",
    204: "No Content",
    304: "Not Modified",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


@dataclass(frozen=True, slots=True)
class Request:
    method: str
    target: str
    path: str
    query: str
    headers: Mapping[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass(frozen=True, slots=True)
class Reply:
    status: int = 200
    headers: Mapping[str, str] = field(default_factory=dict[str, str])
    body: bytes = b""
    delay_s: float = 0.0
    hang: bool = False
    truncate_after: int | None = None
    stall_after: int | None = None
    close: bool = False


Handler = Callable[[Request], Awaitable[Reply]]


def constant(reply: Reply) -> Handler:
    async def handler(_request: Request) -> Reply:
        return reply

    return handler


def document(
    body: bytes, *, cache_control: str = "max-age=60", content_type: str = "text/html"
) -> Handler:
    """A cacheable document with an ETag, answering a conditional request with 304."""
    etag = f'"{hashlib.sha256(body).hexdigest()[:16]}"'

    async def handler(request: Request) -> Reply:
        headers = {
            "Content-Type": content_type,
            "Cache-Control": cache_control,
            "ETag": etag,
        }
        if request.header("if-none-match") == etag:
            return Reply(status=304, headers=headers)
        return Reply(status=200, headers=headers, body=body)

    return handler


def flaky(failures: int, body: bytes = b"ok") -> Handler:
    """Fails with 503 the first few times, then succeeds: transient, and recoverable."""
    seen = 0

    async def handler(_request: Request) -> Reply:
        nonlocal seen
        seen += 1
        if seen <= failures:
            return Reply(status=503, headers={"Content-Type": "text/plain"}, body=b"try again")
        return Reply(status=200, headers={"Content-Type": "text/plain"}, body=body)

    return handler


def rate_limited(retry_after_s: int) -> Handler:
    async def handler(_request: Request) -> Reply:
        return Reply(
            status=429,
            headers={"Retry-After": str(retry_after_s), "Content-Type": "application/json"},
            body=b'{"error": {"code": "rate_limited"}}',
        )

    return handler


class FakeOrigin:
    """One HTTP/1.1 origin. Routes are matched in order by a glob over the path."""

    def __init__(self) -> None:
        self._routes: list[tuple[str, Handler]] = []
        self._server: asyncio.Server | None = None
        self.host = "127.0.0.1"
        self.port = 0
        self.requests: list[Request] = []
        self.hits: dict[str, int] = {}
        self.open_connections = 0
        self.accepted = 0
        self.bytes_served = 0

    def route(self, pattern: str, handler: Handler) -> None:
        self._routes.append((pattern, handler))

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def start(self) -> str:
        self._server = await asyncio.start_server(self._serve, self.host, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.base_url

    async def stop(self) -> None:
        server = self._server
        if server is None:
            return
        server.close()
        await server.wait_closed()
        self._server = None

    async def __aenter__(self) -> FakeOrigin:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    def _handler(self, path: str) -> Handler | None:
        for pattern, handler in self._routes:
            if fnmatchcase(path, pattern):
                return handler
        return None

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.accepted += 1
        self.open_connections += 1
        try:
            while True:
                request = await self._read_request(reader)
                if request is None:
                    return
                self.requests.append(request)
                self.hits[request.path] = self.hits.get(request.path, 0) + 1
                handler = self._handler(request.path)
                if handler is None:
                    await self._write(writer, Reply(status=404, body=b"no route"), request.method)
                    continue
                reply = await handler(request)
                if reply.delay_s:
                    await asyncio.sleep(reply.delay_s)
                if reply.hang:
                    # Hold the connection open and answer nothing, which is what a
                    # wedged origin does. It ends when the client goes away.
                    await reader.read()
                    return
                await self._write(writer, reply, request.method)
                if reply.stall_after is not None:
                    # Headers and part of the body, then silence: a stream that stalls.
                    await reader.read()
                    return
                if reply.close or reply.truncate_after is not None:
                    return
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            return
        finally:
            self.open_connections -= 1
            writer.close()
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> Request | None:
        try:
            head = await reader.readuntil(CRLF + CRLF)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionResetError):
            return None
        if len(head) > HEADER_LIMIT:
            return None
        lines = head.decode("latin-1").split("\r\n")
        method, _, rest = lines[0].partition(" ")
        target = rest.rpartition(" ")[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        length = int(headers.get("content-length", "0") or 0)
        body = await reader.readexactly(length) if length else b""
        path, _, query = target.partition("?")
        return Request(
            method=method.upper(),
            target=target,
            path=unquote(path),
            query=query,
            headers=headers,
            body=body,
        )

    async def _write(self, writer: asyncio.StreamWriter, reply: Reply, method: str) -> None:
        body = b"" if method == "HEAD" or reply.status in (204, 304) else reply.body
        headers = dict(reply.headers)
        headers.setdefault("Content-Length", str(len(reply.body)))
        headers.setdefault("Connection", "close" if reply.close else "keep-alive")
        reason = REASONS.get(reply.status, "Unknown")
        head = f"HTTP/1.1 {reply.status} {reason}\r\n"
        head += "".join(f"{name}: {value}\r\n" for name, value in headers.items())
        writer.write(head.encode("latin-1") + CRLF)
        limit = reply.truncate_after if reply.truncate_after is not None else reply.stall_after
        if limit is not None:
            # Fewer bytes than Content-Length promised, then a drop or a long silence.
            writer.write(body[:limit])
            self.bytes_served += min(limit, len(body))
        else:
            writer.write(body)
            self.bytes_served += len(body)
        await writer.drain()
