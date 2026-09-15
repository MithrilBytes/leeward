# SPDX-License-Identifier: Apache-2.0
"""Circuit breakers, one per endpoint and one per host.

The closed, open and half-open states follow the circuit breaker in Michael Nygard,
Release It! (Pragmatic Bookshelf, 2007), chapter 5. Two choices depart from the
textbook, because the caller is an agent rather than a service:

A failure that can never succeed opens the breaker at once, and the breaker keeps
the classification that opened it. A short-circuited call reports that class, since
an agent told only "circuit open" does the one thing it knows and tries again.

A breaker counts only failures that are about its own scope. A refused connection
says nothing about one endpoint, and a 404 says nothing about the host, so neither
moves the other's breaker. See FailureScope.

Every function here is pure over an immutable record; the registry holds the
records and reports each state change so it can be logged.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Literal

from leeward.classify import Classification
from leeward.config import BreakerSettings
from leeward.vocab import BreakerState, Disposition, FailureClass, FailureScope

Scope = Literal["host", "endpoint"]

HOST_OPEN_AFTER_CONNECTIONS = 2
"""Connection-level failures on two separate connections, with no success between
them, open a host breaker. One refused or timed-out connect can be a lost SYN; two
fresh connections failing the same way is the path to the host."""

CLEARED_ONLY_BY_EVENT = frozenset({FailureClass.TOOL_GONE})
"""Classes whose breaker is never probed on a timer. A vanished tool comes back when
tools/list shows it again, and only that event closes its breaker."""

_FAILURE_SCOPE: dict[Scope, FailureScope] = {
    "host": FailureScope.HOST,
    "endpoint": FailureScope.ENDPOINT,
}


@dataclass(frozen=True, slots=True)
class BreakerPolicy:
    open_after_failures: int = 3
    backoff_initial_s: float = 5.0
    backoff_max_s: float = 120.0
    close_after_successes: int = 2

    @classmethod
    def from_settings(cls, settings: BreakerSettings) -> BreakerPolicy:
        return cls(
            open_after_failures=settings.open_after_transient_failures,
            backoff_initial_s=settings.half_open_backoff_initial,
            backoff_max_s=settings.half_open_backoff_max,
            close_after_successes=settings.close_after_successes,
        )

    def for_scope(self, scope: Scope) -> BreakerPolicy:
        if scope == "host":
            return replace(self, open_after_failures=HOST_OPEN_AFTER_CONNECTIONS)
        return self


@dataclass(frozen=True, slots=True)
class Breaker:
    """One breaker's state. Every observation produces a new record."""

    key: str
    scope: Scope
    state: BreakerState = BreakerState.CLOSED
    failures: int = 0
    successes: int = 0
    opened_by: Classification | None = None
    backoff_s: float = 0.0
    next_probe_at: float | None = None
    probing: bool = False

    def next_probe_in_s(self, now: float) -> float | None:
        if self.state is BreakerState.CLOSED or self.next_probe_at is None:
            return None
        return max(self.next_probe_at - now, 0.0)


class Admission(StrEnum):
    ALLOW = "ALLOW"
    PROBE = "PROBE"
    REFUSE = "REFUSE"


def admit(breaker: Breaker, now: float) -> tuple[Admission, Breaker]:
    """Whether a call may go through, and the record after deciding.

    An open breaker lets exactly one probe through once its backoff has passed.
    While that probe is out, every other call is refused.
    """
    if breaker.state is BreakerState.CLOSED:
        return Admission.ALLOW, breaker
    if breaker.probing or breaker.next_probe_at is None or now < breaker.next_probe_at:
        return Admission.REFUSE, breaker
    return Admission.PROBE, replace(breaker, state=BreakerState.HALF_OPEN, probing=True)


def _closed(breaker: Breaker) -> Breaker:
    return Breaker(breaker.key, breaker.scope)


def _success(breaker: Breaker, policy: BreakerPolicy, now: float) -> Breaker:
    if breaker.state is BreakerState.CLOSED:
        return replace(breaker, failures=0) if breaker.failures else breaker
    opener = breaker.opened_by
    if opener is not None and opener.failure_class in CLEARED_ONLY_BY_EVENT:
        return breaker
    successes = breaker.successes + 1
    if successes >= policy.close_after_successes:
        return _closed(breaker)
    return replace(
        breaker, state=BreakerState.HALF_OPEN, successes=successes, probing=False, next_probe_at=now
    )


def _failure(
    breaker: Breaker, classification: Classification, policy: BreakerPolicy, now: float
) -> Breaker:
    failures = breaker.failures + 1
    never = classification.disposition is Disposition.NEVER
    if breaker.state is BreakerState.OPEN and not breaker.probing and not never:
        return replace(breaker, failures=failures)
    trips = (
        never or failures >= policy.open_after_failures or breaker.state is not BreakerState.CLOSED
    )
    if not trips:
        return replace(breaker, failures=failures, successes=0)
    if classification.failure_class in CLEARED_ONLY_BY_EVENT:
        return replace(
            breaker,
            state=BreakerState.OPEN,
            failures=failures,
            successes=0,
            opened_by=classification,
            backoff_s=0.0,
            next_probe_at=None,
            probing=False,
        )
    if never:
        backoff = policy.backoff_max_s
    elif breaker.backoff_s == 0:
        backoff = policy.backoff_initial_s
    else:
        backoff = min(breaker.backoff_s * 2, policy.backoff_max_s)
    wait = max(backoff, classification.retry_after_s or 0.0)
    return replace(
        breaker,
        state=BreakerState.OPEN,
        failures=failures,
        successes=0,
        opened_by=classification,
        backoff_s=backoff,
        next_probe_at=now + wait,
        probing=False,
    )


def observe(
    breaker: Breaker, classification: Classification, now: float, policy: BreakerPolicy
) -> Breaker:
    """The record after one attempt's classification.

    A failure about this breaker's scope counts against it. For an endpoint breaker,
    a failure about the host is neutral: the attempt never reached the endpoint, so
    an outstanding probe is withdrawn and retried once the host answers. Anything
    else proves the scope is reachable and counts as a success.
    """
    own = _FAILURE_SCOPE[breaker.scope]
    if classification.ok:
        return _success(breaker, policy, now)
    if classification.scope is own:
        return _failure(breaker, classification, policy, now)
    if breaker.scope == "endpoint" and classification.scope is FailureScope.HOST:
        if not breaker.probing:
            return breaker
        return replace(breaker, state=BreakerState.OPEN, probing=False, next_probe_at=now)
    return _success(breaker, policy, now)


@dataclass(frozen=True, slots=True)
class Transition:
    before: Breaker
    after: Breaker


@dataclass(frozen=True, slots=True)
class Verdict:
    admission: Admission
    refused_by: Breaker | None = None


class Breakers:
    """Every host and endpoint breaker. Host state is consulted before endpoint state."""

    def __init__(self, policy: BreakerPolicy) -> None:
        self._policy = policy
        self._records: dict[tuple[Scope, str], Breaker] = {}

    def get(self, scope: Scope, key: str) -> Breaker:
        return self._records.get((scope, key)) or Breaker(key, scope)

    def all(self) -> list[Breaker]:
        return list(self._records.values())

    def load(self, breakers: Iterable[Breaker]) -> None:
        for breaker in breakers:
            self._records[(breaker.scope, breaker.key)] = breaker

    def _keys(self, origin: str | None, endpoint: str) -> list[tuple[Scope, str]]:
        keys: list[tuple[Scope, str]] = [("host", origin)] if origin else []
        return [*keys, ("endpoint", endpoint)]

    def _store(self, before: Breaker, after: Breaker, transitions: list[Transition]) -> None:
        if after != before:
            self._records[(after.scope, after.key)] = after
        if after.state is not before.state:
            transitions.append(Transition(before, after))

    def admit(
        self, origin: str | None, endpoint: str, now: float
    ) -> tuple[Verdict, list[Transition]]:
        """Decide before any change is applied, so a refusal leaves no probe half-claimed."""
        decisions = [
            admit(self.get(scope, key), now) for scope, key in self._keys(origin, endpoint)
        ]
        for admission, breaker in decisions:
            if admission is Admission.REFUSE:
                return Verdict(Admission.REFUSE, breaker), []
        transitions: list[Transition] = []
        for (scope, key), (_admission, after) in zip(
            self._keys(origin, endpoint), decisions, strict=True
        ):
            self._store(self.get(scope, key), after, transitions)
        probing = any(admission is Admission.PROBE for admission, _ in decisions)
        return Verdict(Admission.PROBE if probing else Admission.ALLOW), transitions

    def record(
        self, origin: str | None, endpoint: str, classification: Classification, now: float
    ) -> list[Transition]:
        transitions: list[Transition] = []
        for scope, key in self._keys(origin, endpoint):
            before = self.get(scope, key)
            after = observe(before, classification, now, self._policy.for_scope(scope))
            self._store(before, after, transitions)
        return transitions

    def clear(self, scope: Scope, key: str) -> Transition | None:
        """Close a breaker because of an event, such as a vanished tool reappearing."""
        before = self.get(scope, key)
        if before.state is BreakerState.CLOSED:
            return None
        after = _closed(before)
        self._records[(scope, key)] = after
        return Transition(before, after)
