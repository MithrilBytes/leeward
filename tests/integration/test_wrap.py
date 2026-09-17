# SPDX-License-Identifier: Apache-2.0
"""`leeward wrap` as an MCP client starts it: a real process, over stdio, in front of
another real process that is killed partway through the session.

The client is the SDK's own, and nothing here reaches into either process. What
happened is read from the tool results and from the event log leeward wrote.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import Any, cast

import pytest
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp_types import CallToolResult, TextContent, TextResourceContents

from leeward.events import read_events
from leeward.surfaces.mcp import OUTCOME_META_KEY
from leeward.surfaces.upstream import describe
from tests.support import REPO_ROOT, assert_valid

SESSION_LIMIT_S = 60.0
"""A wrapped session that has not finished by now is hung, and the test says so."""

Wrapped = Callable[..., AbstractAsyncContextManager[Client]]


def outcome_of(result: CallToolResult) -> dict[str, Any]:
    return cast("dict[str, Any]", cast("dict[str, Any]", result.meta)[OUTCOME_META_KEY])


def origin_content(result: CallToolResult) -> list[str]:
    """The content blocks that came from the server, without leeward's note ahead of them."""
    return [
        block.text
        for block in result.content
        if isinstance(block, TextContent) and not block.text.startswith("[leeward]")
    ]


def pid_in(path: Path) -> int:
    return int(path.read_text(encoding="utf-8"))


async def gone(pid: int, within_s: float = 10.0) -> bool:
    """Whether the process has exited and been reaped within the time allowed."""
    for _ in range(int(within_s / 0.05)):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        await asyncio.sleep(0.05)
    return False


def calls(data: Path) -> list[dict[str, object]]:
    events = list(read_events(data / "events"))
    for event in events:
        assert_valid("event", event)
    return [event for event in events if event["event"] == "call"]


@pytest.fixture
def pid_file(tmp_path: Path) -> Path:
    return tmp_path / "server.pid"


@pytest.fixture
def data(tmp_path: Path) -> Path:
    return tmp_path / "data"


@pytest.fixture
def wrapped(pid_file: Path, data: Path) -> Wrapped:
    """Start `leeward wrap` around the fake server, the way a client's config would."""

    @asynccontextmanager
    async def start(*options: str) -> AsyncGenerator[Client]:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "leeward",
                "wrap",
                "--name",
                "notes",
                "--data-dir",
                str(data),
                *options,
                "--",
                sys.executable,
                "-m",
                "fakes.mcp_server",
            ],
            # Only this reaches leeward, so the server can only see it if wrap passes
            # its environment on.
            env={"LEEWARD_FAKE_PID_FILE": str(pid_file)},
            cwd=REPO_ROOT,
        )
        async with Client(parameters) as client:
            yield client

    return start


async def test_wrap_passes_the_server_through_and_stops_it_on_close(
    wrapped: Wrapped, pid_file: Path
) -> None:
    async with asyncio.timeout(SESSION_LIMIT_S), wrapped() as client:
        tools = (await client.list_tools()).tools
        prompts = (await client.list_prompts()).prompts
        prompt = await client.get_prompt("summarize_incident", {"incident": "blackout"})
        resources = (await client.list_resources()).resources
        read = await client.read_resource("notes://index")
        result = await client.call_tool("incident_notes", {"query": "blackout"})
        server = pid_in(pid_file)

    assert {tool.name for tool in tools} == {"incident_notes", "threat_intel_lookup"}
    assert [item.name for item in prompts] == ["summarize_incident"]
    assert "Summarize incident blackout" in cast("TextContent", prompt.messages[0].content).text
    assert [str(item.uri) for item in resources] == ["notes://index"]
    assert cast("TextResourceContents", read.contents[0]).text == "blackout\nbrownout\nfailover"
    assert describe(result) == "3 incident notes mention blackout"
    assert outcome_of(result)["outcome"] == "FRESH"
    assert await gone(server), "the wrapped server outlived the session"


async def test_a_killed_server_costs_one_refusal_and_the_rest_carry_on(
    wrapped: Wrapped, pid_file: Path, data: Path
) -> None:
    async with asyncio.timeout(SESSION_LIMIT_S), wrapped() as client:
        await client.call_tool("incident_notes", {"query": "blackout"})
        first = pid_in(pid_file)
        os.kill(first, signal.SIGKILL)
        refused = await client.call_tool("incident_notes", {"query": "brownout"})
        again = await client.call_tool("incident_notes", {"query": "brownout"})
        other = await client.call_tool("threat_intel_lookup", {"ioc": "198.51.100.4"})
        second = pid_in(pid_file)

    assert refused.is_error
    outcome = outcome_of(refused)
    assert_valid("outcome", outcome)
    assert (outcome["outcome"], outcome["advice"]) == ("DOWN", "DO_NOT_RETRY")
    assert outcome["failure"]["class"] == "TOOL_GONE"
    assert outcome["failure"]["disposition_reason"] == "the MCP server process exited"
    assert describe(refused).startswith("[leeward] DOWN: the tool `incident_notes` is gone")

    assert outcome_of(again)["failure"]["class"] == "BREAKER_OPEN"
    assert outcome_of(again)["failure"]["underlying_class"] == "TOOL_GONE"

    assert not other.is_error
    assert outcome_of(other)["outcome"] == "FRESH"
    assert second != first, "the other tool should have started the server again"

    recorded = calls(data)
    assert [(event["outcome"], event["attempts"]) for event in recorded] == [
        ("FRESH", 1),
        ("DOWN", 1),
        ("DOWN", 0),
        ("FRESH", 1),
    ]
    runs = {cast("dict[str, str]", event["run"])["id"] for event in recorded}
    assert len(runs) == 1
    assert runs.pop().startswith("conn-stdio:notes:")


async def test_a_cached_tool_answers_with_its_last_result_after_the_server_dies(
    wrapped: Wrapped, pid_file: Path, data: Path
) -> None:
    async with asyncio.timeout(SESSION_LIMIT_S), wrapped("--cache", "incident_notes") as client:
        fresh = await client.call_tool("incident_notes", {"query": "blackout"})
        os.kill(pid_in(pid_file), signal.SIGKILL)
        stale = await client.call_tool("incident_notes", {"query": "blackout"})

    assert not stale.is_error
    outcome = outcome_of(stale)
    assert_valid("outcome", outcome)
    assert outcome["outcome"] == "STALE"
    assert outcome["failure"]["class"] == "TOOL_GONE"
    assert origin_content(stale) == origin_content(fresh) == ["3 incident notes mention blackout"]
    note = describe(stale).splitlines()[0]
    assert note.startswith("[leeward] STALE: served a copy stored")
    assert "(TOOL_GONE)" in note
    assert len(note) < 400

    recorded = calls(data)
    assert [event["outcome"] for event in recorded] == ["FRESH", "STALE"]
    assert recorded[1]["failure_class"] == "TOOL_GONE"
    assert any(event["event"] == "breaker" for event in read_events(data / "events"))


async def test_a_client_that_stops_wrap_with_sigterm_stops_the_server_too(
    pid_file: Path, data: Path
) -> None:
    """Closing stdin is the polite way to stop a stdio server; SIGTERM is what follows it."""
    process = await asyncio.create_subprocess_exec(
        *(sys.executable, "-m", "leeward", "wrap", "--data-dir", str(data)),
        *("--", sys.executable, "-m", "fakes.mcp_server"),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env={**os.environ, "LEEWARD_FAKE_PID_FILE": str(pid_file)},
        cwd=REPO_ROOT,
    )

    async def exchange(message: dict[str, object]) -> dict[str, Any]:
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        await process.stdin.drain()
        if "id" not in message:
            return {}
        return cast("dict[str, Any]", json.loads(await process.stdout.readline()))

    try:
        async with asyncio.timeout(SESSION_LIMIT_S):
            hello = {"name": "test", "version": "0"}
            params = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": hello}
            await exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})
            await exchange({"jsonrpc": "2.0", "method": "notifications/initialized"})
            listed = await exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            server = pid_in(pid_file)
            process.send_signal(signal.SIGTERM)
            code = await process.wait()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()

    assert len(listed["result"]["tools"]) == 2
    assert code == 0
    assert await gone(server), "the wrapped server outlived leeward"
