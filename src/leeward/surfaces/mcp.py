# SPDX-License-Identifier: Apache-2.0
"""The MCP surface: point an MCP client at leeward and it sees the same tools.

Each configured server gets its own endpoint here, so tool names are not renamed
and nothing in the agent's prompt has to change. What changes is what a failure
looks like. A tool that has vanished from its server comes back as one refusal that
says it is permanent for this run, instead of three retries and an error string.

A result that came from the cache carries a note block ahead of the content and the
outcome in `structuredContent.leeward`, so the model reading the text and the
program reading the structure are told the same thing.

Only `tools/call` is treated this way. Everything else an MCP client asks for is
answered by the upstream server as usual.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult, TextContent, Tool
from starlette.applications import Starlette
from starlette.routing import Mount

from leeward.budget import resolve_run
from leeward.cache.freshness import (
    ServeFresh,
    ServeStale,
    Situation,
    StoredResponse,
    Withhold,
    decide,
)
from leeward.cache.store import tool_key
from leeward.events import CacheInfo, RunRef
from leeward.outcome import CallOutcome, build
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.proxy import Proxy
from leeward.surfaces.upstream import ToolCaller, Upstream
from leeward.surfaces.upstream import describe as describe
from leeward.transport import Call
from leeward.vocab import Outcome, Surface

ACCEPT_STALE_ARGUMENT = "accept_stale"
ACCEPT_STALE_SCHEMA: dict[str, object] = {
    "type": "boolean",
    "description": (
        "Set by the caller to accept a stored copy that is older than this endpoint"
        " normally allows. leeward adds this argument and removes it before the call"
        " reaches the tool."
    ),
}


def note_block(outcome: CallOutcome) -> TextContent:
    return TextContent(type="text", text=outcome.note)


def with_outcome(result: CallToolResult | None, outcome: CallOutcome) -> CallToolResult:
    """The upstream result, unchanged, with leeward's note ahead of it and its outcome beside it."""
    content = list(result.content) if result is not None else []
    if outcome.note:
        content.insert(0, note_block(outcome))
    structured = dict(cast("dict[str, Any]", result.structured_content or {})) if result else {}
    structured["leeward"] = outcome.as_dict()
    failed = outcome.outcome is Outcome.DOWN or bool(result is not None and result.is_error)
    return CallToolResult(
        content=content,  # pyright: ignore[reportArgumentType]
        structured_content=structured,
        is_error=failed,
    )


def stored_result(body: bytes) -> CallToolResult:
    return CallToolResult.model_validate_json(body)


class ServerFront(MCPServer):
    """leeward's view of one upstream server: the same tools, different failures."""

    def __init__(self, proxy: Proxy, upstream: Upstream) -> None:
        super().__init__(name=f"leeward-{upstream.name}")
        self.proxy = proxy
        self.upstream = upstream

    @property
    def _accepts_stale_argument(self) -> bool:
        return self.upstream.spec.accept_stale_argument

    async def list_tools(self) -> list[Tool]:
        """The upstream's tools, and a record of any that have gone."""
        listed = await self.upstream.list_tools()
        run = RunRef.internal(f"tools-list-{self.upstream.name}")
        if self.upstream.gone:
            self._refreshed(set(self.upstream.gone))
        for tool in listed:
            endpoint = f"{self.upstream.name}/{tool.name}"
            cleared = self.proxy.breakers.clear("endpoint", endpoint)
            if cleared is not None:
                self.proxy.events.emit(
                    "breaker",
                    run,
                    {
                        "endpoint": endpoint,
                        "message": "the tool is listed again",
                        "breaker": {
                            "scope": "endpoint",
                            "from_state": str(cleared.before.state),
                            "to_state": str(cleared.after.state),
                        },
                    },
                )
        return [self._augment(tool) for tool in listed] if self._accepts_stale_argument else listed

    def _refreshed(self, gone: set[str]) -> None:
        """Record a tools/list that came back short, since it is what makes the case."""
        self.proxy.events.emit(
            "tools_refresh",
            RunRef.internal(f"tools-list-{self.upstream.name}"),
            {
                "surface": str(Surface.MCP),
                "endpoint": self.upstream.name,
                "message": f"gone from tools/list: {', '.join(sorted(gone))}",
            },
        )

    def _augment(self, tool: Tool) -> Tool:
        """Add the opt-in argument, where the operator asked for it."""
        schema = cast("dict[str, Any]", dict(tool.input_schema or {"type": "object"}))
        properties = dict(cast("dict[str, Any]", schema.get("properties", {})))
        properties[ACCEPT_STALE_ARGUMENT] = dict(ACCEPT_STALE_SCHEMA)
        schema["properties"] = properties
        return tool.model_copy(update={"input_schema": schema})

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: object = None
    ) -> CallToolResult:
        """One tool call, with the same treatment any other call through leeward gets."""
        proxy = self.proxy
        now = proxy.clock()
        asked = dict(arguments)
        accept_stale = bool(asked.pop(ACCEPT_STALE_ARGUMENT, False))
        target = CallTarget.tool(self.upstream.name, name)
        policy = resolve(proxy.config, target)
        run = self._run_of(context)
        ledger = proxy.runs.ledger(run, now)
        key = tool_key(self.upstream.name, name, asked) if policy.cacheable else None
        entry = proxy.cache.get(key, now) if key else None
        allowance = policy.stale_allowance()

        decision = decide(entry, allowance, Situation.START, now, accept_stale=accept_stale)
        if isinstance(decision, ServeFresh | ServeStale):
            return self._from_cache(decision, policy, ledger, run)

        report = await proxy.engine.call(
            Call("TOOL", f"mcp://{self.upstream.name}/{name}"),
            policy,
            ledger,
            request_key=key,
            caller=ToolCaller(self.upstream, name, asked, on_refresh=self._refreshed),
        )
        after = proxy.clock()
        if report.ok and report.fetched is not None:
            result = cast("CallToolResult", report.fetched.payload)
            if key is not None:
                proxy.cache.put(
                    key=key,
                    url=f"mcp://{self.upstream.name}/{name}",
                    method="TOOL",
                    endpoint=policy.endpoint,
                    status=200,
                    headers=(),
                    body=report.fetched.body,
                    requested_at=now,
                    received_at=after,
                    volatility=policy.volatility,
                    now=after,
                )
            outcome = build(Outcome.FRESH, policy, report=report, ledger=ledger, now=after)
            proxy.record(outcome, report, Surface.MCP, run, ledger, cache=CacheInfo(hit=False))
            return with_outcome(result, outcome)

        failed = decide(entry, allowance, Situation.ORIGIN_FAILED, after, accept_stale=accept_stale)
        if isinstance(failed, ServeStale):
            return self._from_cache(failed, policy, ledger, run, report_note=True)
        withheld = failed if isinstance(failed, Withhold) else None
        outcome = build(
            Outcome.DOWN,
            policy,
            report=report,
            withheld=withheld,
            ledger=ledger,
            breaker=proxy.breakers.get("endpoint", policy.endpoint),
            accept_stale_via="argument" if self._accepts_stale_argument else None,
            now=after,
        )
        proxy.record(
            outcome,
            report,
            Surface.MCP,
            run,
            ledger,
            cache=CacheInfo(
                hit=False, withheld=str(withheld.reason) if withheld is not None else None
            ),
        )
        return with_outcome(None, outcome)

    def _from_cache(
        self,
        decision: ServeFresh | ServeStale,
        policy: ResolvedPolicy,
        ledger: object,
        run: RunRef,
        *,
        report_note: bool = False,
    ) -> CallToolResult:
        proxy = self.proxy
        entry: StoredResponse = decision.entry
        body = proxy.cache.read_body(entry)
        stale = decision if isinstance(decision, ServeStale) else None
        outcome = build(
            Outcome.STALE if stale is not None else Outcome.FRESH,
            policy,
            served=entry,
            served_stale=stale,
            ledger=cast("Any", ledger),
            known_failure=proxy.known_failure(policy.endpoint),
            now=proxy.clock(),
        )
        proxy.record(
            outcome,
            None,
            Surface.MCP,
            run,
            cast("Any", ledger),
            cache=CacheInfo(hit=True, age_s=int(decision.age_s), bytes_served=len(body)),
        )
        return with_outcome(stored_result(body), outcome)

    def _run_of(self, context: object) -> RunRef:
        """Run identity from the session when the transport gives one, else the server."""
        session = getattr(context, "session_id", None)
        return resolve_run(
            mcp_session=session if isinstance(session, str) else None,
            connection=f"mcp:{self.upstream.name}",
        )


def upstreams_from(proxy: Proxy) -> dict[str, Upstream]:
    return {name: Upstream(name, spec) for name, spec in proxy.config.surfaces.mcp.servers.items()}


@dataclass(frozen=True, slots=True)
class Mounted:
    """The configured servers, each on its own path, and what has to be shut down."""

    routes: list[Mount]
    apps: list[Starlette]
    upstreams: list[Upstream]

    async def aclose(self) -> None:
        for upstream in self.upstreams:
            await upstream.aclose()


def mount_servers(proxy: Proxy) -> Mounted:
    """One streamable HTTP endpoint per configured server, at /mcp/<name>.

    A client points at the path for the server it wants and sees that server's tools
    under their own names, which is the whole of the wiring.
    """
    routes: list[Mount] = []
    apps: list[Starlette] = []
    upstreams: list[Upstream] = []
    for name, upstream in upstreams_from(proxy).items():
        front = ServerFront(proxy, upstream)
        app = front.streamable_http_app(streamable_http_path="/")
        routes.append(Mount(f"/mcp/{name}", app=app))
        apps.append(app)
        upstreams.append(upstream)
    return Mounted(routes, apps, upstreams)
