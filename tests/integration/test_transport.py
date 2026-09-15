# SPDX-License-Identifier: Apache-2.0
"""The transport against a real origin on a real socket, which is the only way the
timing, the cancellation and the byte counting mean anything."""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import AsyncIterator

import pytest
from fakes.origin import FakeOrigin, Reply, constant, document

from leeward.classify import (
    ConnectRefused,
    Malformed,
    ReadTimedOut,
    ResolutionFailed,
    Response,
    TooLarge,
)
from leeward.config import Config, parse_config
from leeward.deadlines import Deadline
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.transport import Call, HostMemory, Transport

POLICY = resolve(Config(), CallTarget.http("http://127.0.0.1/doc"))


def small_body_policy(limit: int) -> ResolvedPolicy:
    config = parse_config(f"rules:\n  - match: {{url: '*'}}\n    max_body_bytes: {limit}\n").config
    return resolve(config, CallTarget.http("http://127.0.0.1/doc"))


def in_(seconds: float) -> Deadline:
    return Deadline(at=time.monotonic() + seconds)


@pytest.fixture
async def origin() -> AsyncIterator[FakeOrigin]:
    async with FakeOrigin() as running:
        yield running


@pytest.fixture
async def transport() -> AsyncIterator[Transport]:
    made = Transport()
    yield made
    await made.aclose()


def closed_port() -> int:
    """A port nothing is listening on, so a connection to it is refused at once."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def test_a_fetch_carries_the_status_headers_and_body(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/doc", document(b"<html>hello</html>", cache_control="max-age=60"))
    fetched = await transport.fetch(Call("GET", f"{origin.base_url}/doc"), POLICY, in_(5))
    assert isinstance(fetched.evidence, Response)
    assert fetched.evidence.status == 200
    assert fetched.body == b"<html>hello</html>"
    assert fetched.headers["cache-control"] == "max-age=60"
    assert fetched.headers["etag"]
    assert (fetched.connected, fetched.bytes_sent) == (True, True)
    assert fetched.elapsed_s >= 0


async def test_a_second_fetch_reuses_the_connection_and_a_hedge_does_not(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/doc", document(b"hello"))
    call = Call("GET", f"{origin.base_url}/doc")
    await transport.fetch(call, POLICY, in_(5))
    await transport.fetch(call, POLICY, in_(5))
    assert origin.accepted == 1
    await transport.fetch(call, POLICY, in_(5), fresh=True)
    assert origin.accepted == 2


async def test_a_refused_connection_says_so(transport: Transport) -> None:
    fetched = await transport.fetch(
        Call("GET", f"http://127.0.0.1:{closed_port()}/doc"), POLICY, in_(5)
    )
    assert isinstance(fetched.evidence, ConnectRefused)
    assert not fetched.connected


async def test_a_name_that_does_not_resolve_carries_the_response_code(
    transport: Transport,
) -> None:
    async def refuse(host: str, port: int) -> list[tuple[int, str]]:
        raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")

    async def probe(name: str) -> int | None:
        return 3

    memory = HostMemory()
    resolving = Transport(resolver=refuse, memory=memory, probe=probe)
    try:
        fetched = await resolving.fetch(Call("GET", "http://nothing.invalid/doc"), POLICY, in_(5))
        assert fetched.evidence == ResolutionFailed(rcode=3, resolved_before=False)
        memory.note("nothing.invalid", time.monotonic())
        again = await resolving.fetch(Call("GET", "http://nothing.invalid/doc"), POLICY, in_(5))
        assert again.evidence == ResolutionFailed(rcode=3, resolved_before=True)
    finally:
        await resolving.aclose()


async def test_the_next_address_is_tried_when_the_first_refuses(origin: FakeOrigin) -> None:
    origin.route("/doc", document(b"hello"))

    async def two_addresses(host: str, port: int) -> list[tuple[int, str]]:
        return [(socket.AF_INET, "127.0.0.2"), (socket.AF_INET, "127.0.0.1")]

    transport = Transport(resolver=two_addresses)
    try:
        call = Call("GET", f"http://localhost:{origin.port}/doc")
        fetched = await transport.fetch(call, POLICY, in_(5))
        assert isinstance(fetched.evidence, Response)
        assert fetched.body == b"hello"
    finally:
        await transport.aclose()


async def test_a_body_over_the_cap_is_refused_rather_than_read(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/big", constant(Reply(body=b"x" * 5000)))
    fetched = await transport.fetch(
        Call("GET", f"{origin.base_url}/big"), small_body_policy(1024), in_(5)
    )
    assert fetched.evidence == TooLarge(limit_bytes=1024)
    assert fetched.body == b""


async def test_a_body_that_stops_halfway_is_a_protocol_error(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/torn", constant(Reply(body=b"y" * 100, truncate_after=10)))
    fetched = await transport.fetch(Call("GET", f"{origin.base_url}/torn"), POLICY, in_(5))
    assert isinstance(fetched.evidence, Malformed)


async def test_a_stream_that_stalls_mid_body_is_a_read_timeout(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/stall", constant(Reply(body=b"z" * 4000, stall_after=16)))
    started = time.monotonic()
    fetched = await transport.fetch(
        Call("GET", f"{origin.base_url}/stall"), POLICY, in_(5), idle_s=0.2
    )
    assert isinstance(fetched.evidence, ReadTimedOut)
    assert fetched.evidence.bytes_received >= 0
    assert time.monotonic() - started < 2


async def test_a_hang_cancelled_at_the_deadline_releases_the_connection(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/slow", constant(Reply(hang=True)))
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.3):
            await transport.fetch(Call("GET", f"{origin.base_url}/slow"), POLICY, in_(30))
    for _ in range(50):
        if origin.open_connections == 0:
            break
        await asyncio.sleep(0.02)
    assert origin.open_connections == 0


async def test_a_post_sends_its_body_and_reports_that_bytes_left(
    origin: FakeOrigin, transport: Transport
) -> None:
    origin.route("/write", constant(Reply(status=200, body=b"stored")))
    call = Call(
        "POST",
        f"{origin.base_url}/write",
        headers=(("Content-Type", "application/json"),),
        body=b'{"note": "blackout"}',
    )
    fetched = await transport.fetch(call, POLICY, in_(5))
    assert isinstance(fetched.evidence, Response)
    assert fetched.bytes_sent
    assert origin.requests[-1].body == b'{"note": "blackout"}'
    assert origin.requests[-1].header("content-type") == "application/json"
