# SPDX-License-Identifier: Apache-2.0
"""What every surface shares: one cache, one set of breakers, one ledger of runs.

A call's treatment does not depend on where it came from. The same rules decide its
class, the same cache answers, the same engine attempts it, the same note comes
back. A surface only decides how to carry the answer: a header, a content block, an
error message.

This is also where a call meets the cache, and the order is the whole behaviour of
the proxy in five lines:

1. A stored copy still inside its freshness lifetime is served and the origin is
   left alone.
2. A copy past freshness but inside its revalidation window is served, labeled, and
   refreshed in the background.
3. Otherwise the origin is asked, carrying validators when the copy has them, so an
   unchanged document costs a 304 rather than a body.
4. If the origin fails, the copy is served when its class allows that, and withheld
   with a reason when it does not.
5. Whatever happened, one event is written.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace

from leeward.attempt import AttemptEngine, CallReport
from leeward.breaker import BreakerPolicy, Breakers
from leeward.budget import BudgetLimits, RunLedger, Runs
from leeward.cache.freshness import (
    Decision,
    ServeFresh,
    ServeStale,
    Situation,
    StaleReason,
    StoredResponse,
    Withhold,
    decide,
    may_store,
)
from leeward.cache.store import CacheStore, SingleFlight, cache_key
from leeward.chaos import FaultInjector
from leeward.config import LoadedConfig
from leeward.events import CacheInfo, EventFields, EventLog, RunRef
from leeward.outcome import CallOutcome, build, stale_outcome_guard
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.transport import Call, Fetched, Transport
from leeward.vocab import (
    BreakerState,
    ClockTrust,
    FailureClass,
    Outcome,
    Surface,
    Volatility,
)

STALE_WARNING = '110 leeward "Response is Stale"'
"""RFC 9111 §5.5 retired the Warning field. It costs nothing to send, some clients
still surface it, and a stale response carries the Age header regardless."""

GATEWAY_TIMEOUT_CLASSES = frozenset(
    {FailureClass.WEDGED, FailureClass.READ_TIMEOUT, FailureClass.CONNECT_TIMEOUT}
)
"""These become 504 rather than 503: the origin ran out of time, it did not refuse."""

HOP_BY_HOP = frozenset({"connection", "transfer-encoding", "keep-alive", "upgrade"})

MAX_TRACKED_ENDPOINTS = 5000
"""How many endpoints status remembers. A long-lived proxy must not grow without end."""


@dataclass(frozen=True, slots=True)
class EndpointHealth:
    """The last thing one endpoint did, which is what `leeward status` shows."""

    endpoint: str
    volatility: Volatility
    last_outcome: Outcome
    last_class: FailureClass | None = None
    last_latency_ms: int = 0
    last_seen: float = 0.0
    calls: int = 0
    stale_served: int = 0
    down: int = 0

    def as_dict(self, breaker: BreakerState) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "volatility": str(self.volatility),
            "breaker": str(breaker),
            "last_outcome": str(self.last_outcome),
            "last_class": str(self.last_class) if self.last_class else None,
            "last_latency_ms": self.last_latency_ms,
            "calls": self.calls,
            "stale_served": self.stale_served,
            "down": self.down,
        }


class HttpRequest:
    """One request as a surface hands it over."""

    __slots__ = ("accept_stale", "body", "headers", "method", "url")

    def __init__(
        self,
        method: str,
        url: str,
        headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
        *,
        accept_stale: bool = False,
    ) -> None:
        self.method = method.upper()
        self.url = url
        self.headers = headers
        self.body = body
        self.accept_stale = accept_stale

    @property
    def lowered(self) -> dict[str, str]:
        return {name.lower(): value for name, value in self.headers}


class Served:
    """What the surface should send back, and what leeward said about it."""

    __slots__ = ("body", "from_cache", "headers", "outcome", "status")

    def __init__(
        self,
        outcome: CallOutcome,
        status: int,
        headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
        *,
        from_cache: bool = False,
    ) -> None:
        self.outcome = outcome
        self.status = status
        self.headers = headers
        self.body = body
        self.from_cache = from_cache

    @property
    def is_down(self) -> bool:
        return self.outcome.outcome is Outcome.DOWN


class Proxy:
    """The shared machinery: one per running proxy, or one per test."""

    def __init__(self, loaded: LoadedConfig, *, clock: Callable[[], float] = time.time) -> None:
        config = loaded.config
        data = loaded.data_dir
        self.loaded = loaded
        self.config = config
        self.clock = clock
        self.events = EventLog(data / "events", config.redact_headers())
        self.cache = CacheStore(data / "cache")
        self.breakers = Breakers(BreakerPolicy.from_settings(config.defaults.breaker))
        self.runs = Runs(BudgetLimits.from_settings(config.defaults.run_budget))
        self.injector = FaultInjector(
            data / "chaos.json", enabled=config.chaos.enabled, profile=config.profile
        )
        self.transport = Transport()
        self.engine = AttemptEngine(
            transport=self.transport,
            breakers=self.breakers,
            injector=self.injector,
            wall_clock=clock,
            clock_trust=self.clock_trust,
        )
        self.flights: SingleFlight[CallReport] = SingleFlight()
        self.health: OrderedDict[str, EndpointHealth] = OrderedDict()
        self._background: set[asyncio.Task[object]] = set()

    def clock_trust(self) -> ClockTrust:
        """Until something outside this machine vouches for the clock, it is unchecked."""
        return ClockTrust.UNCHECKED

    async def aclose(self) -> None:
        for task in list(self._background):
            task.cancel()
        if self._background:
            await asyncio.gather(*self._background, return_exceptions=True)
        await self.transport.aclose()
        self.cache.close()
        self.events.close()

    async def fetch(
        self, request: HttpRequest, run: RunRef, *, surface: Surface = Surface.FETCH
    ) -> Served:
        """One HTTP call, from the cache decision through to the event."""
        started = self.clock()
        policy, key, entry = self._lookup(request, started)
        ledger = self.runs.ledger(run, started)
        decision = self._decide(entry, policy, Situation.START, started, request)

        if isinstance(decision, ServeFresh):
            return self._serve_stored(
                Outcome.FRESH, decision.entry, decision.age_s, policy, ledger, run, surface
            )
        if isinstance(decision, ServeStale):
            self._revalidate_later(request, policy, key)
            return self._serve_stored(
                Outcome.STALE,
                decision.entry,
                decision.age_s,
                policy,
                ledger,
                run,
                surface,
                served_stale=decision,
            )

        stale_on_failure = isinstance(
            self._decide(entry, policy, Situation.ORIGIN_FAILED, started, request), ServeStale
        )
        report, joined = await self._to_origin(
            request, policy, ledger, entry, key, stale_available=stale_on_failure
        )
        return self._after_origin(
            report, joined, request, policy, ledger, entry, key, run, surface, started
        )

    def _lookup(
        self, request: HttpRequest, now: float
    ) -> tuple[ResolvedPolicy, str, StoredResponse | None]:
        target = CallTarget.http(request.url, request.method)
        policy = resolve(self.config, target)
        key = cache_key(request.method, request.url, _vary_values(policy, request.lowered))
        entry = self.cache.get(key, now) if policy.cacheable else None
        if entry is not None and policy.rule_index is None:
            # With no rule to decide the class, the origin's own directives do.
            policy = resolve(self.config, target, dict(entry.headers))
        return policy, key, entry

    def _decide(
        self,
        entry: StoredResponse | None,
        policy: ResolvedPolicy,
        situation: Situation,
        now: float,
        request: HttpRequest,
    ) -> Decision:
        return decide(
            entry,
            policy.stale_allowance(),
            situation,
            now,
            request_headers=request.lowered,
            accept_stale=request.accept_stale,
        )

    async def _to_origin(
        self,
        request: HttpRequest,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        entry: StoredResponse | None,
        key: str,
        *,
        stale_available: bool = False,
    ) -> tuple[CallReport, bool]:
        """Ask the origin. Identical requests already in flight share the one call."""
        call = Call(
            method=request.method,
            url=request.url,
            headers=(*request.headers, *_conditional(entry)),
            body=request.body,
        )
        return await self.flights.run(
            key,
            lambda: self.engine.call(
                call, policy, ledger, request_key=key, stale_available=stale_available
            ),
        )

    def _after_origin(
        self,
        report: CallReport,
        joined: bool,
        request: HttpRequest,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        entry: StoredResponse | None,
        key: str,
        run: RunRef,
        surface: Surface,
        started: float,
    ) -> Served:
        now = self.clock()
        if report.abandoned_at_soft:
            return self._after_soft_deadline(report, request, policy, ledger, entry, run, surface)
        fetched = report.fetched
        if report.ok and fetched is not None:
            if fetched.status == 304 and entry is not None:
                refreshed = self.cache.refresh(
                    key, dict(fetched.headers), requested_at=started, received_at=now
                )
                return self._serve_stored(
                    Outcome.FRESH,
                    refreshed or entry,
                    0.0,
                    policy,
                    ledger,
                    run,
                    surface,
                    report=report,
                    revalidated=True,
                )
            self._store(request, policy, fetched, key, started, now)
            outcome = build(Outcome.FRESH, policy, report=report, ledger=ledger, now=now)
            self.record(
                outcome,
                report,
                surface,
                run,
                ledger,
                cache=CacheInfo(hit=False, single_flight_joined=joined),
            )
            return Served(
                outcome=outcome,
                status=fetched.status or 200,
                headers=(*_passable(fetched.header_pairs), *_leeward_headers(outcome, None)),
                body=fetched.body,
            )

        decision = self._decide(entry, policy, Situation.ORIGIN_FAILED, now, request)
        if isinstance(decision, ServeStale):
            return self._serve_stored(
                Outcome.STALE,
                decision.entry,
                decision.age_s,
                policy,
                ledger,
                run,
                surface,
                served_stale=decision,
                report=report,
            )
        withheld = decision if isinstance(decision, Withhold) else None
        outcome = build(
            Outcome.DOWN,
            policy,
            report=report,
            withheld=withheld,
            ledger=ledger,
            breaker=self.breakers.get("endpoint", policy.endpoint),
            accept_stale_via=_accept_stale_via(policy, withheld),
            now=now,
        )
        self.record(
            outcome,
            report,
            surface,
            run,
            ledger,
            cache=CacheInfo(
                hit=False,
                single_flight_joined=joined,
                withheld=str(withheld.reason) if withheld is not None else None,
            ),
        )
        return Served(
            outcome=outcome,
            status=_down_status(outcome),
            headers=_down_headers(outcome),
            body=down_body(outcome),
        )

    def _after_soft_deadline(
        self,
        report: CallReport,
        request: HttpRequest,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        entry: StoredResponse | None,
        run: RunRef,
        surface: Surface,
    ) -> Served:
        """The origin is slow and there is something to serve, so stop waiting for it.

        The request it abandoned keeps running, because the copy it would refresh is
        the one the next caller gets.
        """
        background = report.background
        if background is not None:
            self._background.add(background)
            background.add_done_callback(self._background.discard)
        decision = self._decide(entry, policy, Situation.SOFT_DEADLINE, self.clock(), request)
        if isinstance(decision, ServeStale):
            return self._serve_stored(
                Outcome.STALE,
                decision.entry,
                decision.age_s,
                policy,
                ledger,
                run,
                surface,
                served_stale=decision,
            )
        withheld = decision if isinstance(decision, Withhold) else None
        outcome = build(
            Outcome.DOWN,
            policy,
            report=report,
            withheld=withheld,
            ledger=ledger,
            now=self.clock(),
        )
        self.record(outcome, report, surface, run, ledger, cache=CacheInfo(hit=False))
        return Served(
            outcome=outcome,
            status=_down_status(outcome),
            headers=_down_headers(outcome),
            body=down_body(outcome),
        )

    async def settle(self) -> None:
        """Wait for the background refreshes, which is what a test and a shutdown need."""
        while self._background:
            await asyncio.gather(*list(self._background), return_exceptions=True)

    def _store(
        self,
        request: HttpRequest,
        policy: ResolvedPolicy,
        fetched: Fetched,
        key: str,
        started: float,
        now: float,
    ) -> StoredResponse | None:
        """Write the response down, unless policy, origin or credentials say otherwise."""
        if fetched.status is None or not policy.cacheable:
            return None
        allowed, _reason = may_store(
            fetched.status,
            dict(fetched.headers),
            request.lowered,
            policy.stale_allowance(),
            policy.vary_on,
            self.config.redact_headers(),
        )
        if not allowed:
            return None
        return self.cache.put(
            key=key,
            url=request.url,
            method=request.method,
            endpoint=policy.endpoint,
            status=fetched.status,
            headers=fetched.header_pairs,
            body=fetched.body,
            requested_at=started,
            received_at=now,
            volatility=policy.volatility,
            vary=_vary_values(policy, request.lowered),
            now=now,
        )

    def _serve_stored(
        self,
        kind: Outcome,
        entry: StoredResponse,
        age_s: float,
        policy: ResolvedPolicy,
        ledger: RunLedger,
        run: RunRef,
        surface: Surface,
        *,
        served_stale: ServeStale | None = None,
        report: CallReport | None = None,
        revalidated: bool = False,
    ) -> Served:
        body = self.cache.read_body(entry)
        known = self.known_failure(policy.endpoint)
        if served_stale is not None and served_stale.reason is StaleReason.REVALIDATING and known:
            # Promising a refresh that keeps failing would be a lie by omission: once
            # leeward knows the origin is down, the copy is served because of that.
            served_stale = replace(served_stale, reason=StaleReason.ERROR)
        outcome = build(
            kind,
            policy,
            report=report,
            served=entry,
            served_stale=served_stale,
            ledger=ledger,
            known_failure=known,
            now=self.clock(),
        )
        stale_outcome_guard(outcome)
        self.record(
            outcome,
            report,
            surface,
            run,
            ledger,
            cache=CacheInfo(
                hit=True,
                age_s=int(age_s),
                bytes_served=len(body),
                pinned=entry.pinned,
                revalidated=revalidated or None,
            ),
        )
        return Served(
            outcome=outcome,
            status=entry.status,
            headers=(*_passable(entry.headers), *_leeward_headers(outcome, age_s)),
            body=body,
            from_cache=True,
        )

    def known_failure(self, endpoint: str) -> FailureClass | None:
        """The class this endpoint last failed with, when the last thing it did was fail."""
        health = self.health.get(endpoint)
        if health is None or health.last_outcome is not Outcome.DOWN:
            return None
        return health.last_class

    def _revalidate_later(self, request: HttpRequest, policy: ResolvedPolicy, key: str) -> None:
        """Refresh a served copy in the background, with nobody waiting on it."""
        if self.flights.in_flight(key):
            return

        async def refresh() -> None:
            run = RunRef.internal("revalidate")
            ledger = self.runs.ledger(run, self.clock())
            started = self.clock()
            entry = self.cache.get(key)
            report, _joined = await self._to_origin(request, policy, ledger, entry, key)
            fetched = report.fetched
            if report.ok and fetched is not None:
                if fetched.status == 304:
                    self.cache.refresh(
                        key, dict(fetched.headers), requested_at=started, received_at=self.clock()
                    )
                else:
                    self._store(request, policy, fetched, key, started, self.clock())
            # A refresh is a call leeward made, so it is a call leeward records. It is
            # also how the next stale serve learns that the origin is unreachable.
            refreshed = build(
                Outcome.FRESH if report.ok else Outcome.DOWN,
                policy,
                report=report,
                ledger=ledger,
                now=self.clock(),
            )
            self.record(refreshed, report, Surface.FETCH, run, ledger, cache=CacheInfo(hit=False))

        task = asyncio.create_task(refresh())
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    def record(
        self,
        outcome: CallOutcome,
        report: CallReport | None,
        surface: Surface,
        run: RunRef,
        ledger: RunLedger,
        *,
        cache: CacheInfo | None = None,
    ) -> None:
        """One event per call, and one for every attempt and breaker change behind it."""
        for record in report.attempts if report is not None else ():
            classification = record.classification
            self.events.emit(
                "attempt",
                run,
                {
                    "surface": str(surface),
                    "endpoint": outcome.endpoint,
                    "attempts": record.index,
                    "total_latency_ms": record.latency_ms,
                    "failure_class": str(classification.failure_class),
                    "disposition": (
                        str(classification.disposition) if classification.disposition else None
                    ),
                    "disposition_reason": classification.reason,
                    "injected": classification.injected,
                    "hedge": record.hedge,
                },
            )
        for transition in report.transitions if report is not None else ():
            opened_by = transition.after.opened_by
            self.events.emit(
                "breaker",
                run,
                {
                    "endpoint": transition.after.key,
                    "breaker": {
                        "scope": transition.after.scope,
                        "from_state": str(transition.before.state),
                        "to_state": str(transition.after.state),
                        "opened_by_class": str(opened_by.failure_class) if opened_by else None,
                    },
                },
            )
        remaining = ledger.remaining(outcome.endpoint)
        fields: EventFields = {
            "surface": str(surface),
            "endpoint": outcome.endpoint,
            "volatility": str(outcome.volatility),
            "rule_index": outcome.rule_index,
            "outcome": str(outcome.outcome),
            "advice": str(outcome.advice),
            "attempts": report.attempt_count if report is not None else 0,
            "attempt_latencies_ms": report.latencies_ms if report is not None else [],
            "total_latency_ms": int((report.elapsed_s if report is not None else 0.0) * 1000),
            "cache": cache,
            "budget_after": {
                "retry_attempts_remaining": remaining.retry_attempts,
                "retry_seconds_remaining": remaining.retry_seconds,
                "endpoint_attempts_remaining": remaining.endpoint_attempts,
            },
        }
        failure = outcome.failure
        if failure is not None:
            fields["failure_class"] = str(failure.failure_class)
            fields["disposition"] = str(failure.disposition)
            fields["disposition_reason"] = failure.reason
            fields["injected"] = failure.injected
            fields["failure_scope"] = failure.scope
            fields["underlying_class"] = (
                str(failure.underlying_class) if failure.underlying_class else None
            )
        if report is not None:
            fields["deadline"] = {
                "soft_s": report.deadlines.soft.at - report.deadlines.started_at,
                "hard_s": report.deadlines.hard.at - report.deadlines.started_at,
                "hit": report.deadline_hit,
            }
        self.events.emit("call", run, fields)
        self._note_health(outcome, report)

    def _note_health(self, outcome: CallOutcome, report: CallReport | None) -> None:
        """Keep the last word on each endpoint, bounded, for status to read."""
        previous = self.health.get(outcome.endpoint)
        failure = outcome.failure
        self.health[outcome.endpoint] = EndpointHealth(
            endpoint=outcome.endpoint,
            volatility=outcome.volatility,
            last_outcome=outcome.outcome,
            last_class=failure.failure_class if failure is not None else None,
            last_latency_ms=int((report.elapsed_s if report is not None else 0.0) * 1000),
            last_seen=self.clock(),
            calls=(previous.calls if previous else 0) + 1,
            stale_served=(previous.stale_served if previous else 0)
            + int(outcome.outcome is Outcome.STALE),
            down=(previous.down if previous else 0) + int(outcome.outcome is Outcome.DOWN),
        )
        self.health.move_to_end(outcome.endpoint)
        while len(self.health) > MAX_TRACKED_ENDPOINTS:
            self.health.popitem(last=False)


def _vary_values(policy: ResolvedPolicy, headers: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple((name, headers.get(name, "")) for name in policy.vary_on)


def _conditional(entry: StoredResponse | None) -> tuple[tuple[str, str], ...]:
    """Validators, so an unchanged document comes back as a 304 rather than a body."""
    if entry is None:
        return ()
    etag, last_modified = entry.validators
    conditional: list[tuple[str, str]] = []
    if etag:
        conditional.append(("If-None-Match", etag))
    if last_modified:
        conditional.append(("If-Modified-Since", last_modified))
    return tuple(conditional)


def _passable(headers: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """The origin's headers, minus the ones that belong to one connection."""
    return tuple((name, value) for name, value in headers if name.lower() not in HOP_BY_HOP)


def _accept_stale_via(policy: ResolvedPolicy, withheld: Withhold | None) -> str | None:
    if withheld is None or policy.volatility in (Volatility.LIVE, Volatility.NEVER):
        return None
    return "header" if policy.target.kind == "http" else "argument"


def _leeward_headers(outcome: CallOutcome, age: float | None) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = [
        ("X-Leeward-Outcome", str(outcome.outcome)),
        ("X-Leeward-Volatility", str(outcome.volatility)),
        ("X-Leeward-Advice", str(outcome.advice)),
    ]
    if outcome.failure is not None:
        headers.append(("X-Leeward-Class", str(outcome.failure.failure_class)))
    if age is not None:
        headers.append(("X-Leeward-Age", str(int(age))))
        headers.append(("Age", str(int(age))))
    if outcome.outcome is Outcome.STALE:
        headers.append(("Warning", STALE_WARNING))
    if outcome.note:
        headers.append(("X-Leeward-Advice-Note", outcome.note))
    return tuple(headers)


def _down_status(outcome: CallOutcome) -> int:
    failure = outcome.failure
    classes = (
        {failure.failure_class, failure.underlying_class} if failure is not None else set[object]()
    )
    return 504 if classes & GATEWAY_TIMEOUT_CLASSES else 503


def _down_headers(outcome: CallOutcome) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = [
        ("Content-Type", "application/json"),
        *_leeward_headers(outcome, None),
    ]
    if outcome.failure is not None and outcome.failure.retry_after_s:
        headers.append(("Retry-After", str(int(outcome.failure.retry_after_s))))
    return tuple(headers)


def down_body(outcome: CallOutcome) -> bytes:
    """The body of a synthesized failure: leeward's own words, marked as leeward's."""
    return json.dumps(outcome.as_dict(), ensure_ascii=False, indent=2).encode("utf-8")
