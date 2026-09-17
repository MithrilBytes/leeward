# SPDX-License-Identifier: Apache-2.0
"""What the event log adds up to.

Everything here is arithmetic over events leeward already wrote, so a report costs
no network and is exactly as true as the log. Nothing is inferred: a call that was
answered without reaching anyone is one leeward recorded that way, not one estimated
from timing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from leeward.jsonish import mapping, text
from leeward.vocab import Outcome

CALL = "call"


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _float(value: object) -> float:
    return float(value) if isinstance(value, int | float) else 0.0


def percentile(values: Sequence[float], fraction: float) -> float:
    """Nearest rank, which needs no interpolation and no assumption about the shape."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-fraction * len(ordered) // 1))))
    return ordered[rank - 1]


@dataclass
class Endpoint:
    """One endpoint's share of the log."""

    endpoint: str
    calls: int = 0
    outcomes: dict[str, int] = field(default_factory=dict[str, int])
    classes: dict[str, int] = field(default_factory=dict[str, int])
    attempts: int = 0
    without_network: int = 0
    bytes_served: int = 0
    latencies_ms: list[float] = field(default_factory=list[float])

    def observe(self, event: Mapping[str, object]) -> None:
        self.calls += 1
        outcome = text(event.get("outcome")) or "UNKNOWN"
        self.outcomes[outcome] = self.outcomes.get(outcome, 0) + 1
        failure = text(event.get("failure_class"))
        if failure is not None and failure != "OK":
            self.classes[failure] = self.classes.get(failure, 0) + 1
        self.attempts += _int(event.get("attempts"))
        self.bytes_served += _int(mapping(event.get("cache")).get("bytes_served"))
        if _int(event.get("attempts")) == 0:
            self.without_network += 1
        self.latencies_ms.append(_float(event.get("total_latency_ms")))

    def as_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "calls": self.calls,
            "outcomes": dict(sorted(self.outcomes.items())),
            "failure_classes": dict(sorted(self.classes.items())),
            "attempts": self.attempts,
            "answered_without_network": self.without_network,
            "bytes_served_from_cache": self.bytes_served,
            "p50_ms": round(percentile(self.latencies_ms, 0.5), 1),
            "p95_ms": round(percentile(self.latencies_ms, 0.95), 1),
        }


def summarize(events: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """The report: per endpoint, and in total, over whatever events were handed in."""
    endpoints: dict[str, Endpoint] = {}
    runs: set[str] = set()
    first: str | None = None
    last: str | None = None
    refusals = 0
    injected = 0
    for event in events:
        if text(event.get("event")) != CALL:
            continue
        name = text(event.get("endpoint")) or "(unknown)"
        endpoints.setdefault(name, Endpoint(name)).observe(event)
        identity = text(mapping(event.get("run")).get("id"))
        if identity is not None:
            runs.add(identity)
        stamp = text(event.get("ts"))
        if stamp is not None:
            first = stamp if first is None or stamp < first else first
            last = stamp if last is None or stamp > last else last
        if text(event.get("failure_class")) in ("BREAKER_OPEN", "BUDGET_EXHAUSTED"):
            refusals += 1
        if event.get("injected") is True:
            injected += 1

    ranked = sorted(endpoints.values(), key=lambda item: (-item.calls, item.endpoint))
    totals = {
        "calls": sum(item.calls for item in ranked),
        "attempts": sum(item.attempts for item in ranked),
        "answered_without_network": sum(item.without_network for item in ranked),
        "bytes_served_from_cache": sum(item.bytes_served for item in ranked),
        "refused_before_calling": refusals,
        "injected": injected,
        "runs": len(runs),
        "endpoints": len(ranked),
        "outcomes": _tally(ranked),
        "from": first,
        "to": last,
    }
    return {"totals": totals, "endpoints": [item.as_dict() for item in ranked]}


def _tally(endpoints: Sequence[Endpoint]) -> dict[str, int]:
    counted: dict[str, int] = {}
    for item in endpoints:
        for outcome, count in item.outcomes.items():
            counted[outcome] = counted.get(outcome, 0) + count
    return dict(sorted(counted.items()))


def headline(summary: Mapping[str, object]) -> str:
    """One sentence a person can read without the table."""
    totals = cast("dict[str, Any]", summary["totals"])
    calls = _int(totals.get("calls"))
    if calls == 0:
        return "no calls recorded yet"
    outcomes = cast("dict[str, int]", totals.get("outcomes") or {})
    served = outcomes.get(str(Outcome.FRESH), 0) + outcomes.get(str(Outcome.STALE), 0)
    free = _int(totals.get("answered_without_network"))
    return (
        f"{calls} calls, {served} answered, {outcomes.get(str(Outcome.DOWN), 0)} down, "
        f"{free} without reaching anyone"
    )
