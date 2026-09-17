# SPDX-License-Identifier: Apache-2.0
"""The MCP surface end to end: an MCP client pointed at leeward, and a tool that vanishes.

The client here is the SDK's own, connected to leeward's server in process, which is
the same protocol path a real client takes over a socket.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import pytest
import uvicorn
from fakes.mcp_server import Journal, build_server, vanish
from mcp.client.client import Client
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED

from leeward.config import parse_config
from leeward.events import read_events
from leeward.proxy import Proxy
from leeward.serve import build_app
from leeward.surfaces.mcp import ServerFront, Upstream, describe
from leeward.vocab import BreakerState
from tests.support import REPO_ROOT, assert_valid

CONFIG = """
profile: dev
data_dir: {data}
surfaces:
  mcp:
    enabled: true
    listen: 127.0.0.1:8787
    servers:
      notes:
        transport: stdio
        command: ["python", "-m", "fakes.mcp_server"]
        accept_stale_argument: true
rules:
  - name: notes-tools
    match: {{tool: "notes/*"}}
    class: volatile
    pure: true
    stale_on_error: 6h
"""


@pytest.fixture
def upstream() -> tuple[MCPServer, Journal]:
    return build_server()


@pytest.fixture
async def front(
    tmp_path: Path, upstream: tuple[MCPServer, Journal]
) -> AsyncIterator[tuple[ServerFront, Proxy, Journal]]:
    server, journal = upstream
    loaded = parse_config(CONFIG.format(data=tmp_path / "data"), tmp_path / "leeward.yaml")
    proxy = Proxy(loaded)
    fronted = Upstream("notes", loaded.config.surfaces.mcp.servers["notes"], server=server)
    yield ServerFront(proxy, fronted), proxy, journal
    await fronted.aclose()
    await proxy.aclose()


def leeward_field(result: object) -> dict[str, Any]:
    structured = cast("Any", result).structured_content
    assert isinstance(structured, dict)
    return cast("dict[str, Any]", structured["leeward"])


async def test_a_client_sees_the_same_tools_through_leeward(
    front: tuple[ServerFront, Proxy, Journal],
) -> None:
    fronted, _proxy, _journal = front
    async with Client(fronted) as client:
        listed = (await client.list_tools()).tools
    assert {tool.name for tool in listed} == {"incident_notes", "threat_intel_lookup"}
    schema = listed[0].input_schema
    assert "accept_stale" in cast("dict[str, Any]", schema["properties"])


async def test_a_tool_result_comes_back_with_the_outcome_beside_it(
    front: tuple[ServerFront, Proxy, Journal],
) -> None:
    fronted, _proxy, journal = front
    async with Client(fronted) as client:
        result = await client.call_tool("incident_notes", {"query": "blackout"})
    assert not result.is_error
    assert "3 incident notes mention blackout" in describe(result)
    outcome = leeward_field(result)
    assert outcome["outcome"] == "FRESH"
    assert outcome["advice"] == "PROCEED"
    assert outcome["endpoint"] == "notes/incident_notes"
    assert outcome["note"] == ""
    assert_valid("outcome", outcome)
    assert journal.hits("incident_notes") == 1


async def test_the_opt_in_argument_never_reaches_the_tool(
    front: tuple[ServerFront, Proxy, Journal],
) -> None:
    fronted, _proxy, journal = front
    async with Client(fronted) as client:
        await client.call_tool("incident_notes", {"query": "blackout", "accept_stale": True})
    assert journal.calls[-1] == ("incident_notes", {"query": "blackout"})


async def test_a_vanished_tool_is_refused_once_and_says_it_is_permanent(
    front: tuple[ServerFront, Proxy, Journal], upstream: tuple[MCPServer, Journal]
) -> None:
    fronted, proxy, journal = front
    server, _journal = upstream
    async with Client(fronted) as client:
        await client.list_tools()
        first = await client.call_tool("threat_intel_lookup", {"ioc": "198.51.100.4"})
        assert not first.is_error

        vanish(server)
        gone = await client.call_tool("threat_intel_lookup", {"ioc": "203.0.113.9"})

    assert gone.is_error
    outcome = leeward_field(gone)
    assert outcome["failure"]["class"] == "TOOL_GONE"
    assert outcome["failure"]["attempts"] == 1
    assert outcome["advice"] == "DO_NOT_RETRY"
    assert "is gone from its MCP server" in describe(gone)
    assert "permanent for this run" in describe(gone)
    assert_valid("outcome", outcome)
    assert journal.hits("threat_intel_lookup") == 1

    breaker = proxy.breakers.get("endpoint", "notes/threat_intel_lookup")
    assert breaker.state is BreakerState.OPEN
    assert breaker.opened_by is not None


async def test_a_second_call_to_a_vanished_tool_costs_nothing(
    front: tuple[ServerFront, Proxy, Journal], upstream: tuple[MCPServer, Journal]
) -> None:
    fronted, _proxy, journal = front
    server, _journal = upstream
    async with Client(fronted) as client:
        await client.list_tools()
        await client.call_tool("threat_intel_lookup", {"ioc": "198.51.100.4"})
        vanish(server)
        await client.call_tool("threat_intel_lookup", {"ioc": "203.0.113.9"})
        refused = await client.call_tool("threat_intel_lookup", {"ioc": "192.0.2.7"})

    outcome = leeward_field(refused)
    assert outcome["failure"]["class"] == "BREAKER_OPEN"
    assert outcome["failure"]["underlying_class"] == "TOOL_GONE"
    assert outcome["advice"] == "DO_NOT_RETRY"
    assert journal.hits("threat_intel_lookup") == 1


async def test_a_live_server_sending_the_closed_connection_code_is_not_taken_for_gone(
    front: tuple[ServerFront, Proxy, Journal], upstream: tuple[MCPServer, Journal]
) -> None:
    fronted, proxy, _journal = front
    server, _other = upstream

    @server.tool()
    def overloaded() -> str:
        """Fails with -32000, a code JSON-RPC leaves to servers and the SDK also uses locally."""
        raise MCPError(code=CONNECTION_CLOSED, message="Connection closed")

    async with Client(fronted) as client:
        result = await client.call_tool("overloaded", {})
        still = await client.call_tool("incident_notes", {"query": "blackout"})

    outcome = leeward_field(result)
    assert outcome["failure"]["class"] == "SERVER_ERROR"
    assert outcome["failure"]["disposition"] == "TRANSIENT"
    assert proxy.breakers.get("endpoint", "notes/overloaded").state is BreakerState.CLOSED
    assert leeward_field(still)["outcome"] == "FRESH"


async def test_a_tool_that_starts_failing_falls_back_to_its_last_answer(
    front: tuple[ServerFront, Proxy, Journal],
) -> None:
    fronted, _proxy, journal = front
    journal.notes_fail_after = 1
    async with Client(fronted) as client:
        first = await client.call_tool("incident_notes", {"query": "blackout"})
        assert not first.is_error
        second = await client.call_tool("incident_notes", {"query": "blackout"})

    assert not second.is_error
    outcome = leeward_field(second)
    assert outcome["outcome"] == "STALE"
    assert outcome["advice"] == "PROCEED_WITH_CAUTION"
    assert outcome["age_s"] is not None
    text = describe(second)
    assert text.startswith("[leeward] STALE: served a copy stored")
    assert "3 incident notes mention blackout" in text
    assert_valid("outcome", outcome)


async def test_every_tool_call_is_recorded(
    front: tuple[ServerFront, Proxy, Journal], tmp_path: Path, upstream: tuple[MCPServer, Journal]
) -> None:
    fronted, proxy, _journal = front
    server, _other = upstream
    async with Client(fronted) as client:
        await client.list_tools()
        await client.call_tool("incident_notes", {"query": "blackout"})
        vanish(server)
        await client.call_tool("threat_intel_lookup", {"ioc": "203.0.113.9"})
        await client.list_tools()
    proxy.events.close()

    events = list(read_events(tmp_path / "data" / "events"))
    for event in events:
        assert_valid("event", event)
        assert not (event.get("volatility") == "live" and event.get("outcome") == "STALE")
    calls = [event for event in events if event["event"] == "call"]
    assert [event["outcome"] for event in calls] == ["FRESH", "DOWN"]
    assert all(event["surface"] == "mcp" for event in calls)
    assert any(event["event"] == "tools_refresh" for event in events)


SERVED = """
profile: dev
data_dir: {data}
surfaces:
  mcp:
    enabled: true
    listen: 127.0.0.1:8787
    servers:
      notes:
        transport: stdio
        command: {command}
        cwd: {cwd}
rules:
  - name: notes-tools
    match: {{tool: "notes/*"}}
    class: volatile
    pure: true
    stale_on_error: 6h
"""


@pytest.fixture
async def served(tmp_path: Path) -> AsyncIterator[str]:
    """leeward on a real port, with the fake server as a real subprocess behind it."""
    command = json.dumps([sys.executable, "-m", "fakes.mcp_server"])
    loaded = parse_config(
        SERVED.format(data=tmp_path / "data", command=command, cwd=json.dumps(str(REPO_ROOT))),
        tmp_path / "leeward.yaml",
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(build_app(Proxy(loaded)), log_level="warning", access_log=False)
    )
    running = asyncio.create_task(server.serve(sockets=[listener]))
    # uvicorn reports readiness with a flag rather than an event, so this waits on it.
    while not server.started:  # noqa: ASYNC110
        await asyncio.sleep(0.01)
    yield f"http://127.0.0.1:{port}/mcp/notes/"
    server.should_exit = True
    await running


async def test_a_client_reaches_a_stdio_server_over_the_mounted_endpoint(served: str) -> None:
    async with Client(served) as client:
        listed = (await client.list_tools()).tools
        result = await client.call_tool("incident_notes", {"query": "blackout"})
    assert {tool.name for tool in listed} == {"incident_notes", "threat_intel_lookup"}
    assert "3 incident notes mention blackout" in describe(result)
    assert leeward_field(result)["outcome"] == "FRESH"
