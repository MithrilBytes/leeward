# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import pytest

from leeward.dnsprobe import (
    DnsProbeError,
    ask,
    build_query,
    encode_name,
    probe_rcode,
    read_rcode,
    system_resolvers,
)

NXDOMAIN = 3
SERVFAIL = 2
NOERROR = 0


class FakeResolver(asyncio.DatagramProtocol):
    """Answers with one response code, or says nothing at all."""

    def __init__(self, rcode: int | None) -> None:
        self.rcode = rcode
        self.questions = 0
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # Before 3.12 the selector's datagram transport is not a DatagramTransport
        # subclass, so this takes the loop at its word rather than asking isinstance.
        self._transport = cast("asyncio.DatagramTransport", transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.questions += 1
        if self.rcode is None or self._transport is None:
            return
        flags = struct.pack("!H", 0x8180 | self.rcode)
        self._transport.sendto(data[:2] + flags + data[4:], addr)


async def resolver_at(rcode: int | None) -> tuple[FakeResolver, str, asyncio.DatagramTransport]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: FakeResolver(rcode), local_addr=("127.0.0.1", 0)
    )
    host, port = transport.get_extra_info("sockname")[:2]
    return protocol, f"{host}:{port}", transport


@pytest.fixture
async def silent_resolver() -> AsyncIterator[tuple[FakeResolver, str]]:
    protocol, address, transport = await resolver_at(None)
    yield protocol, address
    transport.close()


@pytest.mark.parametrize(
    ("name", "wire"),
    [
        ("en.wikipedia.org", b"\x02en\twikipedia\x03org\x00"),
        ("example.com.", b"\x07example\x03com\x00"),
        ("localhost", b"\tlocalhost\x00"),
    ],
)
def test_names_become_length_prefixed_labels(name: str, wire: bytes) -> None:
    assert encode_name(name) == wire


@pytest.mark.parametrize("name", ["", "a..b", "x" * 300])
def test_names_that_cannot_be_asked_about_are_refused(name: str) -> None:
    with pytest.raises(DnsProbeError):
        encode_name(name)


def test_a_query_carries_the_question_and_asks_for_recursion() -> None:
    query = build_query("example.com", identifier=0x1234)
    identifier, flags, questions = struct.unpack_from("!3H", query)
    assert (identifier, flags, questions) == (0x1234, 0x0100, 1)
    assert query[12:].startswith(encode_name("example.com"))


@pytest.mark.parametrize("rcode", [NOERROR, SERVFAIL, NXDOMAIN])
def test_the_response_code_is_read_back(rcode: int) -> None:
    answer = struct.pack("!2H", 0x1234, 0x8180 | rcode) + b"\x00" * 8
    assert read_rcode(answer, 0x1234) == rcode


def test_an_answer_to_a_different_question_is_ignored() -> None:
    answer = struct.pack("!2H", 0x9999, 0x8183) + b"\x00" * 8
    assert read_rcode(answer, 0x1234) is None
    question = struct.pack("!2H", 0x1234, 0x0100) + b"\x00" * 8
    assert read_rcode(question, 0x1234) is None
    assert read_rcode(b"\x12", 0x1234) is None


def test_resolvers_are_read_from_the_system_file(tmp_path: Path) -> None:
    path = tmp_path / "resolv.conf"
    path.write_text("# comment\nsearch example.com\nnameserver 1.1.1.1\nnameserver fe80::1\n")
    assert system_resolvers(path) == ["1.1.1.1", "fe80::1"]
    assert system_resolvers(tmp_path / "missing") == []


async def test_a_resolver_that_says_no_such_name_is_believed() -> None:
    protocol, address, transport = await resolver_at(NXDOMAIN)
    try:
        assert await ask("nothing.invalid", address, timeout_s=1.0) == NXDOMAIN
        assert protocol.questions == 1
    finally:
        transport.close()


async def test_a_resolver_that_says_nothing_gives_no_answer(
    silent_resolver: tuple[FakeResolver, str],
) -> None:
    _protocol, address = silent_resolver
    assert await ask("nothing.invalid", address, timeout_s=0.05) is None


async def test_the_probe_moves_on_to_the_next_resolver(
    silent_resolver: tuple[FakeResolver, str],
) -> None:
    _silent, silent_address = silent_resolver
    answering, answering_address, transport = await resolver_at(NXDOMAIN)
    try:
        rcode = await probe_rcode(
            "nothing.invalid", [silent_address, answering_address], timeout_s=0.2, limit=2
        )
        assert rcode == NXDOMAIN
        assert answering.questions == 1
    finally:
        transport.close()


async def test_with_no_resolvers_there_is_no_answer() -> None:
    assert await probe_rcode("nothing.invalid", [], timeout_s=0.05) is None
