# SPDX-License-Identifier: Apache-2.0
"""The client side of the MCP surface: the servers leeward calls, and one call each.

A session is a live thing with a process or a socket under it, so it is opened on
first use, held by a task of its own, and dropped whole when it breaks. `ToolCaller`
turns one `tools/call` into the same kind of attempt every other surface makes, which
is what lets the attempt engine, the breakers and the budgets treat a tool like a URL.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
from collections.abc import Callable, Mapping
from fnmatch import fnmatchcase
from typing import Any, Literal

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, CallToolResult, TextContent, Tool

from leeward.canonical import canonical_sha256
from leeward.classify import (
    CLASSIFY_SAMPLE_BYTES,
    JSONRPC_INTERNAL_ERROR,
    JSONRPC_INVALID_PARAMS,
    Response,
    ToolAbsent,
    ToolError,
    unknown_tool,
)
from leeward.config import HttpServer, StdioServer
from leeward.deadlines import Deadline
from leeward.policy import ResolvedPolicy
from leeward.transport import Call, Counters, Fetched

MAX_LIST_PAGES = 100
"""The most pages of tools/list followed, so a server that always hands back a cursor
cannot keep a listing open."""

CONFIRM_CLOSED_S = 1.0
"""The longest the request confirming a closed connection may take, within the call's deadline."""


def shape_of(tool: Tool) -> str:
    """A tool's call signature, as a hash, so a change to it can be recognised.

    Only what a caller has to get right is in here. A reworded description is not a
    different tool; a renamed or retyped argument is.
    """
    return canonical_sha256([tool.input_schema, tool.output_schema])


class Upstream:
    """One configured MCP server, connected when it is first needed.

    The set of tool names it has listed is kept, because that is what makes a
    vanished tool recognisable: a name that was there and is not.
    """

    def __init__(
        self,
        name: str,
        spec: StdioServer | HttpServer,
        *,
        environment: Mapping[str, str] | None = None,
        server: object | None = None,
    ) -> None:
        self.name = name
        self.spec = spec
        self.known_tools: set[str] = set()
        self.seen_tools: set[str] = set()
        self.gone: set[str] = set()
        self.changed: set[str] = set()
        self.drifted: set[str] = set()
        self.shapes: dict[str, str] = {}
        self.output_schemas: dict[str, dict[str, Any] | None] = {}
        """Each listed tool's declared output schema, or None where it declares none."""
        self._environment = environment if environment is not None else os.environ
        self._server = server
        self._client: Client | None = None
        self._session: asyncio.Task[None] | None = None
        self._closing: asyncio.Event | None = None
        self._lock = asyncio.Lock()

    def _target(self) -> object:
        if self._server is not None:
            return self._server
        if isinstance(self.spec, StdioServer):
            command, *args = self.spec.command
            patterns = self.spec.env_from
            passed = {
                name: value
                for name, value in self._environment.items()
                if any(fnmatchcase(name, pattern) for pattern in patterns)
            }
            # A value written into the configuration is more specific than one inherited.
            return StdioServerParameters(
                command=command, args=args, env={**passed, **self.spec.env}, cwd=self.spec.cwd
            )
        return self.spec.url

    async def client(self) -> Client:
        """The live session, opened on first use and held open by a task of its own.

        The session has to be closed by the task that opened it, which cannot be the
        task of whichever tool call happened to be first. So one task owns it from
        open to close, and every caller borrows it.
        """
        async with self._lock:
            if self._client is None:
                ready: asyncio.Future[Client] = asyncio.get_running_loop().create_future()
                self._closing = asyncio.Event()
                self._session = asyncio.create_task(self._hold(ready))
                self._client = await ready
            return self._client

    async def _hold(self, ready: asyncio.Future[Client]) -> None:
        try:
            client = Client(self._target())  # pyright: ignore[reportArgumentType]
            async with client:
                ready.set_result(client)
                await self._wait_for_close()
        except BaseException as error:  # noqa: BLE001
            if not ready.done():
                ready.set_exception(error)
            elif not isinstance(error, asyncio.CancelledError):
                self._client = None

    async def _wait_for_close(self) -> None:
        if self._closing is not None:
            await self._closing.wait()

    async def list_tools(self) -> list[Tool]:
        """Ask the server what it offers now, every page of it, not what the client remembers.

        `cache_mode="refresh"` matters here: the SDK client caches listings, and a
        cached listing is exactly what hides a tool that has gone. A listing cut off at
        the page limit is kept but not used to decide that anything has gone.
        """
        client = await self.client()
        listed: list[Tool] = []
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            page = await client.list_tools(cursor=cursor, cache_mode="refresh")
            listed += page.tools
            cursor = page.next_cursor
            if cursor is None:
                break
        names = {tool.name for tool in listed}
        complete = cursor is None
        shapes = {tool.name: shape_of(tool) for tool in listed}
        self.changed = {
            name
            for name, shape in shapes.items()
            if name in self.shapes and self.shapes[name] != shape
        }
        self.drifted |= self.changed
        self.shapes = shapes if complete else {**self.shapes, **shapes}
        self.gone = self.known_tools - names if complete else set()
        self.known_tools = names if complete else self.known_tools | names
        schemas = {tool.name: tool.output_schema for tool in listed}
        self.output_schemas = schemas if complete else {**self.output_schemas, **schemas}
        self.seen_tools |= names
        return listed

    async def still_listed(self, tool: str) -> bool:
        """Re-ask, and say whether the tool is still there. Confirms before condemning."""
        try:
            await self.list_tools()
        except (ConnectionError, BrokenPipeError, EOFError, OSError, MCPError):
            return False
        return tool in self.known_tools

    @property
    def exit_reason(self) -> Literal["server_exited", "session_closed"]:
        """What a closed connection means: a process that ended, or a session that did."""
        return "server_exited" if isinstance(self.spec, StdioServer) else "session_closed"

    async def closed(self, within_s: float) -> bool:
        """Whether the session has really closed, confirmed with a second request.

        The SDK reports a closed connection as error -32000, a code MCP leaves without
        a fixed meaning and servers use for errors of their own, so the code alone is
        not enough to give up on a server that may still be answering. A request on a
        closed connection fails at once; one that has not been answered within
        `within_s` is given the benefit of the doubt. The request is tools/list rather
        than ping, which the 2026-07-28 revision removed.
        https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes
        """
        client = self._client
        if client is None:
            return True
        try:
            async with asyncio.timeout(within_s):
                await client.list_tools(cache_mode="bypass")
        except MCPError as error:
            return error.code == CONNECTION_CLOSED
        except TimeoutError:
            # Ahead of OSError, which TimeoutError subclasses: slow is not closed.
            return False
        except (ConnectionError, BrokenPipeError, EOFError, OSError):
            return True
        return False

    async def call(self, tool: str, arguments: dict[str, Any], timeout_s: float) -> CallToolResult:
        client = await self.client()
        return await client.call_tool(tool, arguments, read_timeout_seconds=timeout_s)

    async def forget(self) -> None:
        """Drop the session, so the next call builds a new one."""
        session, closing = self._session, self._closing
        self._session, self._closing, self._client = None, None, None
        if closing is not None:
            closing.set()
        if session is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await session

    async def aclose(self) -> None:
        await self.forget()


class ToolCaller:
    """Runs one tool call as an attempt, so the engine can treat it like any other."""

    def __init__(
        self,
        upstream: Upstream,
        tool: str,
        arguments: dict[str, Any],
        clock: Callable[[], float] = time.monotonic,
        on_refresh: Callable[[set[str]], None] | None = None,
    ) -> None:
        self.upstream = upstream
        self.tool = tool
        self.arguments = arguments
        self.clock = clock
        self.on_refresh = on_refresh

    async def fetch(
        self,
        call: Call,
        policy: ResolvedPolicy,
        deadline: Deadline,
        *,
        fresh: bool = False,
        idle_s: float | None = None,
        counters: Counters | None = None,
    ) -> Fetched:
        marks = counters if counters is not None else Counters()
        started = self.clock()
        marks.connected = True
        marks.sent = 1
        try:
            result = await self.upstream.call(
                self.tool, self.arguments, deadline.remaining(started)
            )
        except MCPError as error:
            # The session is dropped, not kept for the next call to fail on too: other
            # tools start a new one, and the breaker keeps this tool from asking again.
            confirm_s = min(CONFIRM_CLOSED_S, max(deadline.remaining(self.clock()), 0.0))
            if error.code == CONNECTION_CLOSED and await self.upstream.closed(confirm_s):
                await self.upstream.forget()
                return self._failed(ToolAbsent(self.upstream.exit_reason), started)
            return self._failed(
                ToolError(
                    code=error.code,
                    message=error.message,
                    listed_before=self.tool in self.upstream.known_tools,
                ),
                started,
            )
        except (ConnectionError, BrokenPipeError, EOFError, OSError):
            await self.upstream.forget()
            return self._failed(ToolAbsent(self.upstream.exit_reason), started)
        if result.is_error:
            return await self._refused(result, started)
        body = result.model_dump_json(by_alias=True).encode("utf-8")
        return Fetched(
            evidence=Response(200, {}, body[:CLASSIFY_SAMPLE_BYTES]),
            body=body,
            elapsed_s=self.clock() - started,
            connected=True,
            bytes_sent=True,
            payload=result,
        )

    async def _refused(self, result: CallToolResult, started: float) -> Fetched:
        """An error the server put in the result rather than in the protocol.

        MCP servers report a tool that raised, and a tool they have never heard of,
        the same way: `isError` with the reason in the content. The two need opposite
        answers, so a claim that the tool is unknown is checked against a fresh
        tools/list before it is believed.
        """
        message = describe(result) or "the tool reported an error"
        if not unknown_tool(message):
            return self._failed(
                ToolError(
                    code=JSONRPC_INTERNAL_ERROR,
                    message=message,
                    listed_before=True,
                    in_band=True,
                ),
                started,
            )
        listed = await self.upstream.still_listed(self.tool)
        if self.on_refresh is not None and self.upstream.gone:
            self.on_refresh(set(self.upstream.gone))
        if not listed and self.tool in self.upstream.seen_tools:
            return self._failed(ToolAbsent("delisted"), started)
        return self._failed(
            ToolError(code=JSONRPC_INVALID_PARAMS, message=message, listed_before=False), started
        )

    def _failed(self, evidence: ToolError | ToolAbsent, started: float) -> Fetched:
        return Fetched(
            evidence=evidence,
            elapsed_s=self.clock() - started,
            connected=True,
            bytes_sent=True,
        )


class ResourceCaller:
    """Reads one resource as an attempt, so the engine treats it like any other call."""

    def __init__(
        self, upstream: Upstream, uri: str, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.upstream = upstream
        self.uri = uri
        self.clock = clock

    async def fetch(
        self,
        call: Call,
        policy: ResolvedPolicy,
        deadline: Deadline,
        *,
        fresh: bool = False,
        idle_s: float | None = None,
        counters: Counters | None = None,
    ) -> Fetched:
        marks = counters if counters is not None else Counters()
        started = self.clock()
        marks.connected = True
        marks.sent = 1
        try:
            client = await self.upstream.client()
            result = await client.read_resource(self.uri, cache_mode="bypass")
        except MCPError as error:
            return Fetched(
                evidence=ToolError(
                    code=error.code, message=error.message, listed_before=True, in_band=True
                ),
                elapsed_s=self.clock() - started,
                connected=True,
                bytes_sent=True,
            )
        except (ConnectionError, BrokenPipeError, EOFError, OSError):
            await self.upstream.forget()
            return Fetched(
                evidence=ToolAbsent(self.upstream.exit_reason),
                elapsed_s=self.clock() - started,
                connected=True,
                bytes_sent=True,
            )
        body = result.model_dump_json(by_alias=True).encode("utf-8")
        return Fetched(
            evidence=Response(200, {}, body[:CLASSIFY_SAMPLE_BYTES]),
            body=body,
            elapsed_s=self.clock() - started,
            connected=True,
            bytes_sent=True,
            payload=result,
        )


def describe(result: CallToolResult) -> str:
    """The text a person would read out of a tool result, for the CLI and for tests."""
    parts = [
        item.text
        for item in result.content
        if isinstance(item, TextContent)  # pyright: ignore[reportUnnecessaryIsInstance]
    ]
    return "\n".join(parts) or json.dumps(result.structured_content or {}, ensure_ascii=False)
