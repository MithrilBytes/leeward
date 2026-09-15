# SPDX-License-Identifier: Apache-2.0
"""Runs: which run a call belongs to, what it may still spend on retries, and what it learned.

A retry budget stops a failing dependency from multiplying the work aimed at it, the
argument for per-request and per-client retry limits in Beyer, Jones, Petoff and
Murphy, Site Reliability Engineering (O'Reilly, 2016), chapter 21, "Handling
Overload". Here the client is a run. Budgets count retries and hedges only, never
first attempts, so a run that makes many different calls is not punished for it.

A run also remembers failures whose scope is the run or one request: a rejected
token, a quota that will not reset in time, a 404. Those must stop this run from
asking again without stopping a different run that holds a different token.
"""

from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from leeward.canonical import canonical_json
from leeward.classify import Classification
from leeward.config import RunBudget
from leeward.events import RunRef
from leeward.vocab import RunResolution

_PLAIN_RUN_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_RUNS = 10_000
RUN_IDLE_EXPIRY_S = 3600.0


def _identifier(raw: str, prefix: str) -> str:
    """A caller-supplied id kept as is when plain, otherwise replaced by a hash of it.

    Header and metadata values end up in every event, so anything that is not a
    short plain token is hashed rather than written to the log verbatim.
    """
    if _PLAIN_RUN_ID.match(raw):
        return raw
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8', 'surrogatepass')).hexdigest()[:16]}"


def conversation_hash(messages: Sequence[Mapping[str, object]]) -> str:
    """A stable id for one conversation: its leading system messages and first user turn.

    Every completion in a conversation resends the history, so that prefix stays
    the same from the first turn to the last while everything after it grows.
    """
    prefix: list[dict[str, object]] = []
    for message in messages:
        role = message.get("role")
        prefix.append({"role": role, "content": message.get("content")})
        if role == "user":
            break
    return hashlib.sha256(canonical_json(prefix).encode("utf-8")).hexdigest()[:16]


def resolve_run(
    *,
    header: str | None = None,
    mcp_meta: str | None = None,
    mcp_session: str | None = None,
    llm_messages: Sequence[Mapping[str, object]] | None = None,
    connection: str | None = None,
) -> RunRef:
    """Run identity from the strongest signal present, in the documented order."""
    if header:
        return RunRef(_identifier(header, "h"), RunResolution.HEADER)
    if mcp_meta:
        return RunRef(_identifier(mcp_meta, "m"), RunResolution.MCP_META)
    if mcp_session:
        return RunRef(f"mcp-{_identifier(mcp_session, 's')}", RunResolution.MCP_SESSION)
    if llm_messages:
        return RunRef(f"llm-{conversation_hash(llm_messages)}", RunResolution.LLM_CONVERSATION_HASH)
    return RunRef(f"conn-{connection or 'unknown'}", RunResolution.CONNECTION)


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    retry_attempts: int = 20
    retry_seconds: float = 120.0
    endpoint_attempts: int = 4

    @classmethod
    def from_settings(cls, settings: RunBudget) -> BudgetLimits:
        return cls(
            retry_attempts=settings.max_retry_attempts_total,
            retry_seconds=settings.max_retry_seconds_total,
            endpoint_attempts=settings.max_endpoint_attempts,
        )


@dataclass(frozen=True, slots=True)
class Remaining:
    retry_attempts: int
    retry_seconds: float
    endpoint_attempts: int

    @property
    def exhausted(self) -> bool:
        return self.retry_attempts <= 0 or self.retry_seconds <= 0 or self.endpoint_attempts <= 0


@dataclass(frozen=True, slots=True)
class Remembered:
    classification: Classification
    until: float | None


@dataclass
class RunLedger:
    """What one run has spent and what it has learned. Owned by Runs."""

    run: RunRef
    limits: BudgetLimits
    started_at: float
    last_seen_at: float
    retry_attempts: int = 0
    retry_seconds: float = 0.0
    endpoint_retries: dict[str, int] = field(default_factory=dict[str, int])
    wedges: dict[str, int] = field(default_factory=dict[str, int])
    remembered: dict[str, Remembered] = field(default_factory=dict[str, Remembered])
    tunnel_warned: set[str] = field(default_factory=set[str])
    tokens_prompt: int = 0
    tokens_completion: int = 0
    tokens_on_retries: int = 0

    def remaining(self, endpoint: str) -> Remaining:
        return Remaining(
            retry_attempts=max(self.limits.retry_attempts - self.retry_attempts, 0),
            retry_seconds=max(self.limits.retry_seconds - self.retry_seconds, 0.0),
            endpoint_attempts=max(
                self.limits.endpoint_attempts - self.endpoint_retries.get(endpoint, 0), 0
            ),
        )

    def may_retry(self, endpoint: str) -> bool:
        return not self.remaining(endpoint).exhausted

    def spend_retry(self, endpoint: str) -> None:
        """Count one retry or hedge against the run and the endpoint."""
        self.retry_attempts += 1
        self.endpoint_retries[endpoint] = self.endpoint_retries.get(endpoint, 0) + 1

    def spend_seconds(self, seconds: float) -> None:
        """Count time spent retrying: backoff sleeps and the duration of retry attempts."""
        self.retry_seconds += max(seconds, 0.0)

    def note_wedge(self, endpoint: str) -> int:
        """Record a hang on this endpoint and return how many came before it."""
        before = self.wedges.get(endpoint, 0)
        self.wedges[endpoint] = before + 1
        return before

    def remember(self, key: str, classification: Classification, until: float | None) -> None:
        """Keep a run or request scoped failure, until a time or for the rest of the run."""
        self.remembered[key] = Remembered(classification, until)

    def recall(self, key: str, now: float) -> Remembered | None:
        found = self.remembered.get(key)
        if found is None:
            return None
        if found.until is not None and now >= found.until:
            del self.remembered[key]
            return None
        return found

    def first_tunnel_warning(self, endpoint: str) -> bool:
        """True once per endpoint per run, for warnings that should not repeat."""
        if endpoint in self.tunnel_warned:
            return False
        self.tunnel_warned.add(endpoint)
        return True


class Runs:
    """Every active run's ledger, bounded by count and by idle time so memory stays flat."""

    def __init__(
        self,
        limits: BudgetLimits,
        *,
        max_runs: int = MAX_RUNS,
        idle_expiry_s: float = RUN_IDLE_EXPIRY_S,
    ) -> None:
        self.limits = limits
        self._max_runs = max_runs
        self._idle_expiry_s = idle_expiry_s
        self._ledgers: OrderedDict[str, RunLedger] = OrderedDict()

    def ledger(self, run: RunRef, now: float) -> RunLedger:
        self._expire(now)
        found = self._ledgers.get(run.id)
        if found is None:
            found = RunLedger(run=run, limits=self.limits, started_at=now, last_seen_at=now)
            self._ledgers[run.id] = found
            while len(self._ledgers) > self._max_runs:
                self._ledgers.popitem(last=False)
        else:
            found.last_seen_at = now
            self._ledgers.move_to_end(run.id)
        return found

    def get(self, run_id: str) -> RunLedger | None:
        return self._ledgers.get(run_id)

    def active(self) -> list[RunLedger]:
        return list(self._ledgers.values())

    def _expire(self, now: float) -> None:
        while self._ledgers:
            oldest = next(iter(self._ledgers.values()))
            if now - oldest.last_seen_at < self._idle_expiry_s:
                return
            self._ledgers.popitem(last=False)
