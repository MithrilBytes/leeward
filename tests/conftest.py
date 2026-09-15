# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures, and the guard that keeps the suite off the network.

leeward says that status, forecast, classify, report and anything served from the
cache work with no network at all. That is only worth saying if a test would catch
the day it stops being true, so every test runs with name resolution and outbound
sockets to anything but loopback wired to raise. Each attempt is recorded, so a
test can also assert that none happened.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from typing import Any, cast

import pytest


class EgressError(RuntimeError):
    """Something tried to reach past loopback."""


class EgressLog:
    def __init__(self) -> None:
        self.attempts: list[tuple[str, str]] = []

    def refuse(self, kind: str, target: str) -> EgressError:
        self.attempts.append((kind, target))
        return EgressError(f"blocked {kind} to {target}: tests must not leave this machine")


def _is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _remote_host(address: object) -> object | None:
    """The host of an internet socket address, or None for a path or anything else local."""
    if isinstance(address, tuple):
        parts = cast("tuple[object, ...]", address)
        return parts[0] if parts else None
    return None


@pytest.fixture(autouse=True)
def egress_guard(monkeypatch: pytest.MonkeyPatch) -> Iterator[EgressLog]:
    log = EgressLog()
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto
    real_getaddrinfo = socket.getaddrinfo

    def connect(self: socket.socket, address: Any) -> None:
        host = _remote_host(address)
        if host is not None and not _is_loopback(host):
            raise log.refuse("connect", repr(address))
        real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> int:
        host = _remote_host(address)
        if host is not None and not _is_loopback(host):
            raise log.refuse("connect", repr(address))
        return real_connect_ex(self, address)

    def sendto(self: socket.socket, data: Any, *rest: Any) -> int:
        host = _remote_host(rest[-1]) if rest else None
        if host is not None and not _is_loopback(host):
            raise log.refuse("sendto", repr(rest[-1]))
        return real_sendto(self, data, *rest)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None and not _is_loopback(host):
            raise log.refuse("getaddrinfo", str(host))
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    yield log
