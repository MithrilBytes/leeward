# SPDX-License-Identifier: Apache-2.0
"""One DNS question, asked only to tell "no such name" from "no answer".

getaddrinfo reports both the same way on macOS, and the difference decides what
leeward tells the agent: a name that does not exist will not start existing because
the agent waited, while a resolver that cannot be reached during a partition says
nothing about the name at all. Calling the second case permanent would be the worst
mistake this proxy could make, so the answer is confirmed rather than assumed.

The query is one UDP packet with recursion desired, sent to the system resolvers.
RFC 1035 §4.1.1 defines the header this reads: ID, the QR bit, and RCODE, where 3
is Name Error. It follows no referrals, caches nothing, and asks only what the
resolver said.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets
import socket
import struct
from pathlib import Path

RESOLV_CONF = Path("/etc/resolv.conf")
DNS_PORT = 53
QTYPE_A = 1
QCLASS_IN = 1
HEADER = struct.Struct("!6H")
"""RFC 1035 §4.1.1: id, flags, qdcount, ancount, nscount, arcount."""

RCODE_MASK = 0x000F
QR_BIT = 0x8000
RECURSION_DESIRED = 0x0100
MAX_RESPONSE_BYTES = 512
"""RFC 1035 §4.2.1: 512 octets is the most a UDP answer may carry without EDNS."""

_NAMESERVER = re.compile(r"^\s*nameserver\s+(\S+)", re.MULTILINE)


class DnsProbeError(RuntimeError):
    """The question could not be put into a packet."""


def encode_name(name: str) -> bytes:
    """A domain name as length-prefixed labels (RFC 1035 §3.1)."""
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            raise DnsProbeError(f"{name!r} has an empty label")
        try:
            raw = label.encode("idna")
        except UnicodeError as exc:
            raise DnsProbeError(f"{name!r} is not a usable domain name: {exc}") from exc
        encoded += bytes([len(raw)]) + raw
    return bytes(encoded) + b"\x00"


def build_query(name: str, identifier: int, qtype: int = QTYPE_A) -> bytes:
    header = HEADER.pack(identifier, RECURSION_DESIRED, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!2H", qtype, QCLASS_IN)


def read_rcode(packet: bytes, identifier: int) -> int | None:
    """The response code of an answer to this question, or None if it is not one."""
    if len(packet) < HEADER.size:
        return None
    answer_id, flags, *_rest = HEADER.unpack_from(packet)
    if answer_id != identifier or not flags & QR_BIT:
        return None
    return flags & RCODE_MASK


def system_resolvers(path: Path = RESOLV_CONF) -> list[str]:
    """Resolver addresses from resolv.conf, which macOS keeps in step with the active network."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return _NAMESERVER.findall(text)


def split_resolver(address: str) -> tuple[str, int]:
    """A resolver address, which may name a port: 9.9.9.9, [::1]:5353, 127.0.0.1:5353.

    resolv.conf writes bare addresses, but a resolver on another port is what a test
    has, and what a host running its own stub resolver sometimes has too.
    """
    if address.startswith("["):
        host, _, rest = address[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port else DNS_PORT
    if address.count(":") == 1:
        host, _, port = address.partition(":")
        return host, int(port)
    return address, DNS_PORT


async def ask(name: str, resolver: str, timeout_s: float) -> int | None:
    """Put the question to one resolver and return its response code, or None."""
    identifier = secrets.randbelow(1 << 16)
    query = build_query(name, identifier)
    host, port = split_resolver(resolver)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        # Connecting the socket makes the kernel drop answers from anywhere else.
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, query)
        async with asyncio.timeout(timeout_s):
            packet = await loop.sock_recv(sock, MAX_RESPONSE_BYTES)
    except (TimeoutError, OSError):
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return read_rcode(packet, identifier)


async def probe_rcode(
    name: str,
    resolvers: list[str] | None = None,
    *,
    timeout_s: float = 1.0,
    limit: int = 2,
) -> int | None:
    """Ask the first resolvers that answer; None when none of them does.

    Bounded on purpose: this runs while a call is already failing, so it may not
    spend the caller's remaining time hunting for an answer.
    """
    addresses = (resolvers if resolvers is not None else system_resolvers())[:limit]
    for resolver in addresses:
        rcode = await ask(name, resolver, timeout_s)
        if rcode is not None:
            return rcode
    return None
