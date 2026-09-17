# SPDX-License-Identifier: Apache-2.0
"""The MCP surface: point an MCP client at leeward and it sees the same tools.

Each configured server gets its own endpoint here, so tool names are not renamed
and nothing in the agent's prompt has to change. What changes is what a failure
looks like. A tool that has vanished from its server comes back as one refusal that
says it is permanent for this run, instead of three retries and an error string.

A result that came from the cache, or a failure, carries a note block ahead of the
content. Every result carries the outcome in `_meta`, and a stale or failed one also
in `structuredContent.leeward` wherever the tool's output schema leaves room, so the
model reading the text and the program reading the structure are told the same thing.

Only `tools/call` is treated this way. Prompts and resources are passed to the
upstream server and its answers come back unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp_types import (
    CallToolResult,
    GetPromptRequestParams,
    GetPromptResult,
    ListPromptsResult,
    ListResourcesResult,
    ListResourceTemplatesResult,
    PaginatedRequestParams,
    ReadResourceRequestParams,
    ReadResourceResult,
    TextContent,
    Tool,
)
from starlette.applications import Starlette
from starlette.routing import Mount

from leeward.attempt import CallReport
from leeward.budget import RunLedger, resolve_run
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

OUTCOME_META_KEY = "io.github.mithrilbytes.leeward/outcome"
"""Where every tool result carries leeward's outcome.

`_meta` is always safe to add to. `structuredContent.leeward` carries the outcome as
well where a client will accept it, which `with_outcome` decides. The key has a reverse
DNS vendor prefix, as the protocol asks of anyone adding to `_meta`.
https://modelcontextprotocol.io/specification/2026-07-28/basic/index#_meta
"""

SCHEMA_KEYWORDS_LEFT_ALONE = frozenset(
    {"$ref", "$dynamicRef", "allOf", "anyOf", "oneOf", "not", "if", "then", "else"}
    | {"dependentSchemas", "patternProperties", "propertyNames"}
)
"""Output schemas too involved to be sure an extra key still matches them."""

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


def room_for_outcome(schema: Mapping[str, Any] | None, structured: object) -> bool:
    """Whether structured content can gain a `leeward` key and still match the tool's
    declared output schema, which clients check a result that is not an error against.

    With no schema there is nothing to match. With one, only a plain object schema that
    does not close itself to extra keys, or define `leeward`, is known to accept it.
    https://modelcontextprotocol.io/specification/2026-07-28/server/tools#output-schema
    """
    if schema is None:
        return structured is None or isinstance(structured, dict)
    if not isinstance(structured, dict) or schema.get("type") != "object":
        return False
    if SCHEMA_KEYWORDS_LEFT_ALONE & schema.keys():
        return False
    if any(
        schema.get(key, True) is not True
        for key in ("additionalProperties", "unevaluatedProperties")
    ):
        return False
    return "leeward" not in cast("Mapping[str, Any]", schema.get("properties") or {})


def with_outcome(
    result: CallToolResult | None, outcome: CallOutcome, *, structured_room: bool = False
) -> CallToolResult:
    """The upstream result, unchanged, with leeward's note ahead of its content and its
    outcome in `_meta`.

    A failure has no result to carry, so leeward's own is marked as an error and holds the
    outcome in `structuredContent.leeward`, which clients do not check against an output
    schema. A stale result holds it there too when `structured_room` says the schema has
    room. A fresh result's structured content is never touched.
    """
    failed = outcome.outcome is Outcome.DOWN or bool(result is not None and result.is_error)
    decision = outcome.as_dict()
    meta = {**(result.meta or {})} if result is not None else {}
    meta[OUTCOME_META_KEY] = decision
    content = list(result.content) if result is not None else []
    if outcome.note:
        content.insert(0, note_block(outcome))
    if result is None:
        return CallToolResult(
            content=content,  # pyright: ignore[reportArgumentType]
            structured_content={"leeward": decision},
            is_error=failed,
            _meta=meta,  # pyright: ignore[reportCallIssue]
        )
    update: dict[str, object] = {"content": content, "meta": meta, "is_error": failed}
    if structured_room and outcome.outcome is Outcome.STALE:
        structured = cast("dict[str, Any]", result.structured_content or {})
        update["structured_content"] = {**structured, "leeward": decision}
    return result.model_copy(update=update)


def stored_result(body: bytes) -> CallToolResult:
    return CallToolResult.model_validate_json(body)


class ServerFront(MCPServer):
    """leeward's view of one upstream server: the same tools, different failures."""

    def __init__(self, proxy: Proxy, upstream: Upstream, *, connection: str | None = None) -> None:
        super().__init__(name=f"leeward-{upstream.name}")
        self.proxy = proxy
        self.upstream = upstream
        self.connection = connection or f"mcp:{upstream.name}"

    # Prompts and resources go through the SDK's request handlers rather than the
    # public list_prompts and read_resource hooks, which rebuild each result from
    # parts: that would lose the upstream's page cursors and the URI of every part
    # of a multi-part read.

    async def _handle_list_prompts(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListPromptsResult:
        client = await self.upstream.client()
        if client.server_capabilities.prompts is None:
            return ListPromptsResult(prompts=[])
        cursor = params.cursor if params is not None else None
        return await client.list_prompts(cursor=cursor, cache_mode="bypass")

    async def _handle_get_prompt(
        self, ctx: ServerRequestContext[Any], params: GetPromptRequestParams
    ) -> GetPromptResult:
        client = await self.upstream.client()
        return await client.get_prompt(params.name, params.arguments)

    async def _handle_list_resources(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListResourcesResult:
        client = await self.upstream.client()
        if client.server_capabilities.resources is None:
            return ListResourcesResult(resources=[])
        cursor = params.cursor if params is not None else None
        return await client.list_resources(cursor=cursor, cache_mode="bypass")

    async def _handle_list_resource_templates(
        self, ctx: ServerRequestContext[Any], params: PaginatedRequestParams | None
    ) -> ListResourceTemplatesResult:
        client = await self.upstream.client()
        if client.server_capabilities.resources is None:
            return ListResourceTemplatesResult(resource_templates=[])
        cursor = params.cursor if params is not None else None
        return await client.list_resource_templates(cursor=cursor, cache_mode="bypass")

    async def _handle_read_resource(
        self, ctx: ServerRequestContext[Any], params: ReadResourceRequestParams
    ) -> ReadResourceResult:
        client = await self.upstream.client()
        return await client.read_resource(str(params.uri), cache_mode="bypass")

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
            return self._from_cache(name, decision, policy, ledger, run)

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
            return self._from_cache(name, failed, policy, ledger, run, report=report)
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
        tool: str,
        decision: ServeFresh | ServeStale,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        run: RunRef,
        *,
        report: CallReport | None = None,
    ) -> CallToolResult:
        """A stored result. After a failed call, `report` is that call, so the note can
        say what failed and the attempts and breaker changes behind it are recorded."""
        proxy = self.proxy
        entry: StoredResponse = decision.entry
        body = proxy.cache.read_body(entry)
        stale = decision if isinstance(decision, ServeStale) else None
        outcome = build(
            Outcome.STALE if stale is not None else Outcome.FRESH,
            policy,
            report=report,
            served=entry,
            served_stale=stale,
            ledger=ledger,
            known_failure=proxy.known_failure(policy.endpoint),
            now=proxy.clock(),
        )
        proxy.record(
            outcome,
            report,
            Surface.MCP,
            run,
            ledger,
            cache=CacheInfo(hit=True, age_s=int(decision.age_s), bytes_served=len(body)),
        )
        stored = stored_result(body)
        schemas = self.upstream.output_schemas
        room = tool in schemas and room_for_outcome(schemas[tool], stored.structured_content)
        return with_outcome(stored, outcome, structured_room=room)

    def _run_of(self, context: object) -> RunRef:
        """Run identity from the session when the transport gives one, else the connection."""
        session = getattr(context, "session_id", None)
        return resolve_run(
            mcp_session=session if isinstance(session, str) else None,
            connection=self.connection,
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
