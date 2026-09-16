# SPDX-License-Identifier: Apache-2.0
"""One HTTP attempt over a real socket, and the evidence it leaves behind.

leeward resolves names itself instead of leaving it to the client library. A
failure can then be explained: a name that does not exist reads differently from a
resolver nobody can reach, and that difference is what stops leeward from telling
an agent to give up during a partition. Owning resolution also lets a host that
resolved earlier be remembered, and lets a test drive resolution without a network.

Addresses are tried the way RFC 8305 §5 recommends, staggered by 250 ms, so a host
whose IPv6 path is a black hole does not cost the whole deadline. Every stream
counts what it sent and received: that is what tells a stalled read from a
connection that never carried a byte, and what makes it safe to retry a request
whose bytes never left this machine.

Nothing here decides anything. It reports what happened; classify.py names it.
"""

from __future__ import annotations

import asyncio
import errno
import socket
import ssl
import time
from collections.abc import (
    AsyncIterable,
    Callable,
    Coroutine,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

import httpcore2

# httpcore2 exports AnyIOBackend from behind a try/except, which leaves the concrete
# class hidden from a type checker, so the real one is imported directly.
from httpcore2._backends.anyio import AnyIOBackend

from leeward.classify import (
    CLASSIFY_SAMPLE_BYTES,
    ConnectRefused,
    ConnectTimedOut,
    Evidence,
    Malformed,
    ReadTimedOut,
    ResolutionFailed,
    Response,
    TlsRejected,
    TooLarge,
)
from leeward.deadlines import Deadline
from leeward.dnsprobe import probe_rcode
from leeward.policy import ResolvedPolicy

HAPPY_EYEBALLS_DELAY_S = 0.25
"""RFC 8305 §5: 250 ms between attempts to successive addresses."""

REFUSED_ERRNOS = frozenset({errno.ECONNREFUSED, errno.ECONNRESET})
"""A refusal is an answer: something is there and it said no. Everything else that
stops a connection (unreachable, unroutable, nothing came back) reads as a timeout,
because from the caller's side the path simply failed."""
RESOLVED_MEMORY_S = 86400.0
"""How long a name that resolved counts as a name that exists. A domain rarely stops
existing during a run, while a resolver disappears the moment the link does."""


async def _default_probe(name: str) -> int | None:
    return await probe_rcode(name)


class EvidenceError(Exception):
    """Carries what the transport saw, so the classifier reads it unchanged."""

    def __init__(self, evidence: Evidence) -> None:
        super().__init__(type(evidence).__name__)
        self.evidence = evidence


@dataclass(slots=True)
class Counters:
    """What one attempt put on the wire and took off it."""

    sent: int = 0
    received: int = 0
    connected: bool = False


_COUNTERS: ContextVar[Counters | None] = ContextVar("leeward_attempt_counters", default=None)


@dataclass(frozen=True, slots=True)
class Call:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class Fetched:
    """The result of one attempt, ready for the classifier."""

    evidence: Evidence
    body: bytes = b""
    header_pairs: tuple[tuple[str, str], ...] = ()
    elapsed_s: float = 0.0
    connected: bool = False
    bytes_sent: bool = False
    payload: object | None = None
    """What a surface got back when the attempt was not HTTP, such as a tool result."""

    @property
    def status(self) -> int | None:
        return self.evidence.status if isinstance(self.evidence, Response) else None

    @property
    def headers(self) -> Mapping[str, str]:
        return self.evidence.headers if isinstance(self.evidence, Response) else {}


class HostMemory:
    """Which names have resolved lately, so today's NXDOMAIN can be read in context."""

    def __init__(self, remember_s: float = RESOLVED_MEMORY_S) -> None:
        self._remember_s = remember_s
        self._seen: dict[str, float] = {}

    def note(self, host: str, now: float) -> None:
        self._seen[host] = now

    def resolved_before(self, host: str, now: float) -> bool:
        seen = self._seen.get(host)
        return seen is not None and now - seen <= self._remember_s


class Resolver(Protocol):
    async def __call__(self, host: str, port: int) -> list[tuple[int, str]]: ...


async def system_resolve(host: str, port: int) -> list[tuple[int, str]]:
    """Addresses in the order the operating system prefers them (RFC 6724)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [(int(family), str(sockaddr[0])) for family, _type, _proto, _canon, sockaddr in infos]


def _chain(exc: BaseException) -> Iterator[BaseException]:
    """Every exception behind this one: causes, contexts, and the members of any group."""
    seen: set[int] = set()
    queue: list[BaseException] = [exc]
    while queue:
        current = queue.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        if isinstance(current, BaseExceptionGroup):
            group = cast("BaseExceptionGroup[BaseException]", current)
            queue.extend(group.exceptions)
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                queue.append(linked)


def _os_error(exc: BaseException) -> OSError | None:
    """The operating system error behind a wrapped one, preferring one with a code.

    A client library may raise a summarising OSError of its own ("all connection
    attempts failed") and put the errors that say what actually happened into an
    exception group, so the whole chain is searched and a code wins over a summary.
    """
    summary: OSError | None = None
    for error in _chain(exc):
        if isinstance(error, OSError):
            if error.errno is not None:
                return error
            summary = summary or error
    return summary


def _ssl_error(exc: BaseException) -> ssl.SSLError | None:
    for error in _chain(exc):
        if isinstance(error, ssl.SSLError):
            return error
    return None


def connect_evidence(exc: BaseException) -> Evidence:
    """What a failed connection says: refused, unreachable, or a handshake that failed."""
    certificate = _ssl_error(exc)
    if certificate is not None:
        code = getattr(certificate, "verify_code", None)
        return TlsRejected(verify_code=code if isinstance(code, int) else None)
    system = _os_error(exc)
    if system is not None and system.errno in REFUSED_ERRNOS:
        return ConnectRefused()
    return ConnectTimedOut()


class CountingStream(httpcore2.AsyncNetworkStream):
    """Passes bytes through and counts them, and names a handshake failure precisely."""

    def __init__(self, inner: httpcore2.AsyncNetworkStream, counters: Counters) -> None:
        self._inner = inner
        self._counters = counters
        counters.connected = True

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        chunk = await self._inner.read(max_bytes, timeout)
        self._counters.received += len(chunk)
        return chunk

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout)
        self._counters.sent += len(buffer)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        try:
            upgraded = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        except Exception as exc:
            raise EvidenceError(connect_evidence(exc)) from exc
        return CountingStream(upgraded, self._counters)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class LeewardBackend(httpcore2.AsyncNetworkBackend):
    """Resolution, address racing and byte counting, under the connection pool."""

    def __init__(
        self,
        inner: httpcore2.AsyncNetworkBackend | None = None,
        *,
        resolver: Resolver | None = None,
        memory: HostMemory | None = None,
        probe: Callable[[str], Coroutine[Any, Any, int | None]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._inner: httpcore2.AsyncNetworkBackend = inner or AnyIOBackend()
        self._resolve: Resolver = resolver or system_resolve
        self.memory = memory or HostMemory()
        self._probe = probe or _default_probe
        self._clock = clock

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        counters = _COUNTERS.get() or Counters()
        addresses = await self._addresses(host, port)
        stream = await self._race(addresses, port, timeout, local_address, socket_options)
        self.memory.note(host, self._clock())
        return CountingStream(stream, counters)

    async def _addresses(self, host: str, port: int) -> list[tuple[int, str]]:
        try:
            addresses = await self._resolve(host, port)
        except OSError as exc:
            rcode = await self._probe(host)
            resolved_before = self.memory.resolved_before(host, self._clock())
            raise EvidenceError(ResolutionFailed(rcode, resolved_before)) from exc
        if not addresses:
            known = self.memory.resolved_before(host, self._clock())
            raise EvidenceError(ResolutionFailed(None, known))
        return addresses

    async def _race(
        self,
        addresses: Sequence[tuple[int, str]],
        port: int,
        timeout: float | None,
        local_address: str | None,
        socket_options: Iterable[Any] | None,
    ) -> httpcore2.AsyncNetworkStream:
        """Open connections to the addresses in turn, 250 ms apart, first one wins."""
        options = list(socket_options) if socket_options is not None else None
        pending: set[asyncio.Task[httpcore2.AsyncNetworkStream]] = set()
        failures: list[BaseException] = []
        winner: httpcore2.AsyncNetworkStream | None = None
        try:
            for index, (_family, address) in enumerate(addresses):
                pending.add(
                    asyncio.create_task(
                        self._inner.connect_tcp(address, port, timeout, local_address, options)
                    )
                )
                last = index == len(addresses) - 1
                winner, failed = await self._settle(
                    pending, None if last else HAPPY_EYEBALLS_DELAY_S
                )
                failures += failed
                if winner is not None:
                    break
            while winner is None and pending:
                winner, failed = await self._settle(pending, None)
                failures += failed
        finally:
            await self._discard(pending)
        if winner is None:
            raise EvidenceError(connect_evidence(failures[0]) if failures else ConnectTimedOut())
        return winner

    async def _settle(
        self, pending: set[asyncio.Task[httpcore2.AsyncNetworkStream]], wait_s: float | None
    ) -> tuple[httpcore2.AsyncNetworkStream | None, list[BaseException]]:
        done, still_pending = await asyncio.wait(
            pending, timeout=wait_s, return_when=asyncio.FIRST_COMPLETED
        )
        pending.clear()
        pending.update(still_pending)
        winner: httpcore2.AsyncNetworkStream | None = None
        failures: list[BaseException] = []
        for task in done:
            error = task.exception()
            if error is not None:
                failures.append(error)
            elif winner is None:
                winner = task.result()
            else:
                await task.result().aclose()
        return winner, failures

    async def _discard(self, pending: set[asyncio.Task[httpcore2.AsyncNetworkStream]]) -> None:
        """Cancel the connections that lost, and close any that opened anyway."""
        for task in pending:
            task.cancel()
        for result in await asyncio.gather(*pending, return_exceptions=True):
            if isinstance(result, httpcore2.AsyncNetworkStream):
                await result.aclose()
        pending.clear()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


def _read_evidence(exc: BaseException, counters: Counters) -> Evidence:
    if isinstance(exc, httpcore2.ReadTimeout | httpcore2.WriteTimeout):
        return ReadTimedOut(bytes_received=counters.received)
    if isinstance(exc, httpcore2.ConnectTimeout | httpcore2.PoolTimeout):
        return ConnectTimedOut()
    if isinstance(exc, httpcore2.ConnectError):
        return connect_evidence(exc)
    return Malformed(detail="the origin's answer could not be read as HTTP")


@dataclass
class Transport:
    """Outbound HTTP for the whole proxy: a pooled client, and a fresh one for hedges."""

    resolver: Resolver | None = None
    memory: HostMemory = field(default_factory=HostMemory)
    probe: Callable[[str], Coroutine[Any, Any, int | None]] | None = None
    clock: Callable[[], float] = time.monotonic
    max_connections: int = 32
    ssl_context: ssl.SSLContext | None = None
    _pool: httpcore2.AsyncConnectionPool = field(init=False)
    _unpooled: httpcore2.AsyncConnectionPool = field(init=False)

    def __post_init__(self) -> None:
        backend = LeewardBackend(
            resolver=self.resolver, memory=self.memory, probe=self.probe, clock=self.clock
        )
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=self.ssl_context,
            max_connections=self.max_connections,
            network_backend=backend,
        )
        self._unpooled = httpcore2.AsyncConnectionPool(
            ssl_context=self.ssl_context,
            max_connections=self.max_connections,
            network_backend=backend,
            keepalive_expiry=0.0,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()
        await self._unpooled.aclose()

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
        """One attempt. Raises nothing about the origin: failures come back as evidence.

        `fresh` opens a connection of its own, which is what makes a hedge worth
        starting: the usual reason a request hangs is the connection it is on. Pass
        `counters` to keep reading them after a cancellation, which is how the engine
        knows whether a call that hit the hard deadline had a connection open.
        """
        counters = counters if counters is not None else Counters()
        token = _COUNTERS.set(counters)
        started = self.clock()
        pool = self._unpooled if fresh else self._pool
        stall = idle_s if idle_s is not None else policy.soft_deadline_s
        try:
            return await self._attempt(pool, call, policy, deadline, counters, started, stall)
        except EvidenceError as failure:
            return self._failed(failure.evidence, counters, started)
        except (httpcore2.ProtocolError, OSError, ssl.SSLError) as exc:
            return self._failed(_read_evidence(exc, counters), counters, started)
        except httpcore2.TimeoutException as exc:
            return self._failed(_read_evidence(exc, counters), counters, started)
        except httpcore2.NetworkError as exc:
            return self._failed(_read_evidence(exc, counters), counters, started)
        finally:
            _COUNTERS.reset(token)

    def _failed(self, evidence: Evidence, counters: Counters, started: float) -> Fetched:
        return Fetched(
            evidence=evidence,
            elapsed_s=self.clock() - started,
            connected=counters.connected,
            bytes_sent=counters.sent > 0,
        )

    async def _attempt(
        self,
        pool: httpcore2.AsyncConnectionPool,
        call: Call,
        policy: ResolvedPolicy,
        deadline: Deadline,
        counters: Counters,
        started: float,
        stall_s: float,
    ) -> Fetched:
        extensions = {"timeout": {"pool": deadline.remaining(self.clock())}}
        async with pool.stream(
            call.method,
            call.url,
            headers=list(call.headers),
            content=call.body or None,
            extensions=extensions,
        ) as response:
            pairs = tuple(
                (name.decode("latin-1"), value.decode("latin-1"))
                for name, value in response.headers
            )
            body, oversized = await self._read_body(response, policy.max_body_bytes, stall_s)
            if oversized:
                return Fetched(
                    evidence=TooLarge(limit_bytes=policy.max_body_bytes),
                    header_pairs=pairs,
                    elapsed_s=self.clock() - started,
                    connected=True,
                    bytes_sent=counters.sent > 0,
                )
            headers = _collapse(pairs)
            return Fetched(
                evidence=Response(response.status, headers, body[:CLASSIFY_SAMPLE_BYTES]),
                body=body,
                header_pairs=pairs,
                elapsed_s=self.clock() - started,
                connected=True,
                bytes_sent=counters.sent > 0,
            )

    async def _read_body(
        self, response: httpcore2.Response, limit: int, stall_s: float
    ) -> tuple[bytes, bool]:
        """Read the body, giving up if it grows past the cap or stops arriving mid-stream."""
        chunks: list[bytes] = []
        total = 0
        source = response.stream
        if not isinstance(source, AsyncIterable):
            raise EvidenceError(Malformed(detail="the origin's body did not arrive as a stream"))
        stream = aiter(source)
        started = True
        while True:
            try:
                if started:
                    chunk = await anext(stream)
                    started = False
                else:
                    async with asyncio.timeout(stall_s):
                        chunk = await anext(stream)
            except StopAsyncIteration:
                break
            except TimeoutError as exc:
                raise EvidenceError(ReadTimedOut(bytes_received=total)) from exc
            total += len(chunk)
            if total > limit:
                return b"", True
            chunks.append(chunk)
        return b"".join(chunks), False


def _collapse(pairs: Sequence[tuple[str, str]]) -> dict[str, str]:
    """Header values by lowercased name, repeats joined as RFC 9110 §5.3 allows."""
    headers: dict[str, str] = {}
    for name, value in pairs:
        key = name.lower()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return headers
