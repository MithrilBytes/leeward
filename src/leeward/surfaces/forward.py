# SPDX-License-Identifier: Apache-2.0
"""Surface C: a forward proxy, for everything else an agent reaches over HTTPS.

A tunnel is the one place leeward cannot help much, and saying so plainly is part of
the design. Once `CONNECT` succeeds the bytes are TLS between the client and the
origin: leeward cannot read them, cannot store them, and cannot serve them back
later. What it can still do is own the deadline, resolve and connect with the same
machinery as every other surface, classify what went wrong, remember it at the right
scope, and answer the one message a proxy is allowed to send before the tunnel opens.

So this surface trades the cache for coverage. The warning that the cache is not
available goes out once per endpoint per run, not on every call, because a model that
is told the same thing five times starts ignoring it.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass

import httpcore2

from leeward.attempt import AttemptRecord, CallReport
from leeward.breaker import Admission
from leeward.budget import RunLedger, resolve_run
from leeward.classify import (
    OK,
    Classification,
    DeadlineReached,
    Evidence,
    RunSnapshot,
    classify,
)
from leeward.deadlines import CallDeadlines
from leeward.events import CacheInfo, RunRef
from leeward.outcome import CallOutcome, build
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.proxy import GATEWAY_TIMEOUT_CLASSES, Proxy
from leeward.transport import EvidenceError, LeewardBackend, connect_evidence
from leeward.vocab import Outcome, Surface

MAX_HEADER_BYTES = 16 * 1024
"""A request head larger than this is not one leeward is going to understand."""

PIPE_CHUNK = 64 * 1024
TUNNEL_WARNING = "cache_unavailable_in_tunnel"


@dataclass(frozen=True, slots=True)
class Tunnel:
    """What a client asked to reach."""

    host: str
    port: int

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return f"https://{self.endpoint}/"


class ForwardProxy:
    """One listener speaking just enough HTTP to open, or refuse, a tunnel."""

    def __init__(self, proxy: Proxy) -> None:
        self.proxy = proxy
        self._server: asyncio.Server | None = None
        # The same resolution, address racing and DNS confirmation the other surfaces
        # get, without a connection pool: a tunnel owns its socket until it closes.
        self.backend = LeewardBackend(
            resolver=proxy.transport.resolver,
            memory=proxy.transport.memory,
            probe=proxy.transport.probe,
            clock=proxy.transport.clock,
        )

    async def start(self, host: str, port: int) -> tuple[str, int]:
        """Listen, and report the address actually bound."""
        self._server = await asyncio.start_server(self._client, host, port)
        bound = self._server.sockets[0].getsockname()
        return str(bound[0]), int(bound[1])

    async def serve_forever(self) -> None:
        if self._server is not None:
            async with self._server:
                await self._server.serve_forever()

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await self._read_head(reader)
            if head is None:
                await self._send(writer, 400, "leeward could not read the request")
                return
            method, target, _rest = head
            if method != "CONNECT":
                await self._send(
                    writer,
                    501,
                    "leeward's forward proxy tunnels with CONNECT. Point the tool's base URL at"
                    " the fetch surface instead, which can cache and serve a stored copy.",
                )
                return
            await self._tunnel(Tunnel(*_split(target)), reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _read_head(self, reader: asyncio.StreamReader) -> tuple[str, str, list[str]] | None:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, ValueError):
            return None
        if len(raw) > MAX_HEADER_BYTES:
            return None
        lines = raw.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) < 2:
            return None
        return parts[0].upper(), parts[1], lines[1:]

    async def _tunnel(
        self, asked: Tunnel, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        proxy = self.proxy
        run = self._run_of(writer)
        ledger = proxy.runs.ledger(run, proxy.clock())
        target = CallTarget.parse(asked.url)
        policy = resolve(proxy.config, target)
        self._warn_once(asked, run, ledger)

        verdict, _opened = proxy.breakers.admit(asked.host, asked.endpoint, proxy.clock())
        if verdict.admission is Admission.REFUSE and verdict.refused_by is not None:
            outcome = self._refusal(asked, policy, ledger, run, verdict.refused_by.opened_by)
            await self._refuse(writer, outcome)
            return

        started = proxy.clock()
        try:
            stream = await asyncio.wait_for(
                self.backend.connect_tcp(asked.host, asked.port, timeout=policy.soft_deadline_s),
                timeout=policy.hard_deadline_s,
            )
        except (EvidenceError, TimeoutError, OSError) as error:
            outcome = self._failed(asked, policy, ledger, run, error, proxy.clock() - started)
            await self._refuse(writer, outcome)
            return

        self._opened(asked, policy, ledger, run, proxy.clock() - started)
        try:
            await self._pipe(stream, reader, writer)
        finally:
            with contextlib.suppress(Exception):
                await stream.aclose()

    async def _pipe(
        self,
        stream: httpcore2.AsyncNetworkStream,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Bytes both ways until either end stops. Nothing here reads what it copies."""
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def to_origin() -> None:
            with contextlib.suppress(Exception):
                while chunk := await reader.read(PIPE_CHUNK):
                    await stream.write(chunk)

        async def to_client() -> None:
            with contextlib.suppress(Exception):
                while chunk := await stream.read(PIPE_CHUNK):
                    writer.write(chunk)
                    await writer.drain()

        tasks = [asyncio.create_task(to_origin()), asyncio.create_task(to_client())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def _warn_once(self, asked: Tunnel, run: RunRef, ledger: RunLedger) -> None:
        if not ledger.first_tunnel_warning(asked.endpoint):
            return
        self.proxy.events.emit(
            "warning",
            run,
            {
                "surface": str(Surface.FORWARD),
                "endpoint": asked.endpoint,
                "message": TUNNEL_WARNING,
            },
        )

    def _refusal(
        self,
        asked: Tunnel,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        run: RunRef,
        behind: Classification | None,
    ) -> CallOutcome:
        known = behind.failure_class if behind is not None else None
        outcome = build(
            Outcome.DOWN,
            policy,
            ledger=ledger,
            breaker=self.proxy.breakers.get("host", asked.host),
            known_failure=known,
            now=self.proxy.clock(),
        )
        self.proxy.record(outcome, None, Surface.FORWARD, run, ledger, cache=_no_cache())
        return outcome

    def _failed(
        self,
        asked: Tunnel,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        run: RunRef,
        error: BaseException,
        elapsed_s: float,
    ) -> CallOutcome:
        snapshot = RunSnapshot(
            now=self.proxy.engine.wall_clock(),
            retry_seconds_remaining=ledger.remaining(policy.endpoint).retry_seconds,
            clock=self.proxy.engine.clock_trust(),
        )
        classification = classify(_evidence(error, policy), policy, snapshot)
        self.proxy.breakers.record(asked.host, asked.endpoint, classification, self.proxy.clock())
        report = _report(classification, policy, self.proxy.clock() - elapsed_s, elapsed_s)
        outcome = build(
            Outcome.DOWN,
            policy,
            report=report,
            ledger=ledger,
            breaker=self.proxy.breakers.get("host", asked.host),
            now=self.proxy.clock(),
        )
        self.proxy.record(outcome, report, Surface.FORWARD, run, ledger, cache=_no_cache())
        return outcome

    def _opened(
        self,
        asked: Tunnel,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        run: RunRef,
        elapsed_s: float,
    ) -> None:
        self.proxy.breakers.record(asked.host, asked.endpoint, OK, self.proxy.clock())
        report = _report(OK, policy, self.proxy.clock() - elapsed_s, elapsed_s)
        outcome = build(Outcome.FRESH, policy, report=report, ledger=ledger, now=self.proxy.clock())
        self.proxy.record(outcome, report, Surface.FORWARD, run, ledger, cache=_no_cache())

    async def _refuse(self, writer: asyncio.StreamWriter, outcome: CallOutcome) -> None:
        """The one message a proxy gets to send before a tunnel exists."""
        timed_out = outcome.failure is not None and (
            outcome.failure.failure_class in GATEWAY_TIMEOUT_CLASSES
        )
        status = 504 if timed_out else 502
        await self._send(writer, status, outcome.note, outcome=outcome)

    async def _send(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        message: str,
        *,
        outcome: CallOutcome | None = None,
    ) -> None:
        body = json.dumps(
            outcome.as_dict() if outcome is not None else {"message": message},
            ensure_ascii=False,
        ).encode("utf-8")
        headers = [
            f"HTTP/1.1 {status} {'Bad Gateway' if status == 502 else 'leeward'}",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        if outcome is not None:
            headers += [
                f"X-Leeward-Outcome: {outcome.outcome}",
                f"X-Leeward-Advice: {outcome.advice}",
                f"X-Leeward-Advice-Note: {outcome.note}",
            ]
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("latin-1") + body)
        with contextlib.suppress(ConnectionError, OSError):
            await writer.drain()

    def _run_of(self, writer: asyncio.StreamWriter) -> RunRef:
        """One client connection is one run: a tunnel carries nothing else to go on."""
        peer = writer.get_extra_info("peername")
        return resolve_run(connection=f"forward:{peer[0]}:{peer[1]}" if peer else "forward")


def _report(
    classification: Classification, policy: ResolvedPolicy, started: float, elapsed_s: float
) -> CallReport:
    """One attempt, already made, in the shape the outcome builder reads."""
    return CallReport(
        classification=classification,
        attempts=(
            AttemptRecord(index=1, classification=classification, latency_ms=int(elapsed_s * 1000)),
        ),
        deadlines=CallDeadlines.start(policy, started),
        deadline_hit="none",
        elapsed_s=elapsed_s,
    )


def _no_cache() -> CacheInfo:
    return CacheInfo(hit=False)


def _split(target: str) -> tuple[str, int]:
    host, _, port = target.rpartition(":")
    if not host:
        return target, 443
    return host.strip("[]"), int(port) if port.isdigit() else 443


def _evidence(error: BaseException, policy: ResolvedPolicy) -> Evidence:
    if isinstance(error, EvidenceError):
        return error.evidence
    if isinstance(error, TimeoutError):
        return DeadlineReached(connected=False, deadline_s=policy.hard_deadline_s)
    return connect_evidence(error)
