# SPDX-License-Identifier: Apache-2.0
"""Surface C end to end: a CONNECT tunnel, and what happens when it cannot open.

The tests speak the proxy's own protocol over a socket rather than through a client
library, since the interesting part is the handshake and the one message leeward is
allowed to send before a tunnel exists.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import pytest

from leeward.config import parse_config
from leeward.events import read_events
from leeward.proxy import Proxy
from leeward.surfaces.forward import TUNNEL_WARNING, ForwardProxy
from tests.support import assert_valid

CONFIG = """
profile: dev
data_dir: {data}
surfaces:
  forward:
    enabled: true
    listen: 127.0.0.1:8788
defaults:
  soft_deadline: 2s
  hard_deadline: 5s
"""


@pytest.fixture
async def echo() -> AsyncIterator[tuple[str, int]]:
    """A plain TCP server, standing in for whatever is on the other side of a tunnel."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while chunk := await reader.read(1024):
            writer.write(b"echo:" + chunk)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    async with server:
        yield str(host), int(port)


@pytest.fixture
async def forward(tmp_path: Path) -> AsyncIterator[tuple[ForwardProxy, Proxy, tuple[str, int]]]:
    loaded = parse_config(CONFIG.format(data=tmp_path / "data"), tmp_path / "leeward.yaml")
    proxy = Proxy(loaded)
    tunnel = ForwardProxy(proxy)
    address = await tunnel.start("127.0.0.1", 0)
    yield tunnel, proxy, address
    await tunnel.aclose()
    await proxy.aclose()


async def speak(
    address: tuple[str, int], request: bytes
) -> tuple[bytes, asyncio.StreamReader, asyncio.StreamWriter]:
    """Send a request head and read the response head, leaving the socket open."""
    reader, writer = await asyncio.open_connection(*address)
    writer.write(request)
    await writer.drain()
    head = await reader.readuntil(b"\r\n\r\n")
    return head, reader, writer


def status_of(head: bytes) -> int:
    return int(head.split(b" ")[1])


async def body_of(head: bytes, reader: asyncio.StreamReader) -> dict[str, object]:
    length = 0
    for line in head.decode("latin-1").split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1])
    raw = await reader.readexactly(length)
    return cast("dict[str, object]", json.loads(raw))


async def test_a_tunnel_opens_and_carries_bytes_both_ways(
    forward: tuple[ForwardProxy, Proxy, tuple[str, int]], echo: tuple[str, int]
) -> None:
    _tunnel, proxy, address = forward
    host, port = echo
    head, reader, writer = await speak(address, f"CONNECT {host}:{port} HTTP/1.1\r\n\r\n".encode())
    assert status_of(head) == 200
    assert b"Connection Established" in head

    writer.write(b"hello")
    await writer.drain()
    assert await reader.readexactly(len(b"echo:hello")) == b"echo:hello"
    writer.close()

    # Opening a tunnel is a call like any other, and it is in the log as one.
    proxy.events.close()
    calls = [
        event for event in read_events(proxy.loaded.data_dir / "events") if event["event"] == "call"
    ]
    assert [event["outcome"] for event in calls] == ["FRESH"]
    assert calls[0]["surface"] == "forward"


async def test_a_host_that_refuses_gets_one_answer_naming_the_failure(
    forward: tuple[ForwardProxy, Proxy, tuple[str, int]],
) -> None:
    _tunnel, _proxy, address = forward
    closed = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = closed.sockets[0].getsockname()[1]
    closed.close()
    await closed.wait_closed()

    head, reader, _writer = await speak(
        address, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode()
    )
    assert status_of(head) in (502, 504)
    assert b"X-Leeward-Outcome: DOWN" in head
    body = await body_of(head, reader)
    assert body["outcome"] == "DOWN"
    failure = body["failure"]
    assert isinstance(failure, dict)
    assert failure["class"] in ("CONNECT_REFUSED", "CONNECT_TIMEOUT")
    assert "returned nothing" in str(body["note"])
    assert_valid("outcome", body)


async def test_the_cache_warning_is_given_once_per_endpoint_per_run(
    forward: tuple[ForwardProxy, Proxy, tuple[str, int]], echo: tuple[str, int]
) -> None:
    _tunnel, proxy, address = forward
    host, port = echo
    for _ in range(3):
        _head, _reader, writer = await speak(
            address, f"CONNECT {host}:{port} HTTP/1.1\r\n\r\n".encode()
        )
        writer.close()
    proxy.events.close()

    warnings = [
        event
        for event in read_events(proxy.loaded.data_dir / "events")
        if event["event"] == "warning" and event["message"] == TUNNEL_WARNING
    ]
    # Three tunnels, three runs, since each connection is its own run: one warning each,
    # and never twice for the same one.
    assert len(warnings) == 3
    assert all(event["endpoint"] == f"{host}:{port}" for event in warnings)


async def test_anything_but_connect_says_where_caching_lives(
    forward: tuple[ForwardProxy, Proxy, tuple[str, int]],
) -> None:
    _tunnel, _proxy, address = forward
    head, reader, _writer = await speak(
        address, b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )
    assert status_of(head) == 501
    body = await body_of(head, reader)
    assert "fetch surface" in str(body["message"])
