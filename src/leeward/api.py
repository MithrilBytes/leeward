# SPDX-License-Identifier: Apache-2.0
"""Status and forecast: what leeward knows without asking anyone.

Both answer from local state only. That is the point: they have to work during the
outage they are describing, so neither opens a connection, and a test asserts it.

A forecast says what a call would return if it were made now. It reads the same
policy, the same cache, the same breakers and the same armed faults the real call
would, and stops short of the one thing it cannot do without the network: reaching
the origin. Where the origin's health is genuinely unknown, it says so rather than
promising success.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from leeward.cache.freshness import ServeFresh, ServeStale, Situation, Withhold, decide
from leeward.cache.store import cache_key
from leeward.policy import CallTarget, ResolvedPolicy, resolve
from leeward.proxy import Proxy
from leeward.vocab import Advice, BreakerState, Outcome, Volatility, WithheldReason


@dataclass(frozen=True, slots=True)
class Forecast:
    """What a call would return if it were made now, and why leeward thinks so."""

    endpoint: str
    volatility: Volatility
    predicted: Outcome
    advice: Advice
    reason: str
    rule_index: int | None = None
    age_s: int | None = None
    breaker: BreakerState = BreakerState.CLOSED
    injected: bool = False
    withheld: WithheldReason | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "volatility": str(self.volatility),
            "predicted": str(self.predicted),
            "advice": str(self.advice),
            "reason": self.reason,
            "rule_index": self.rule_index,
            "age_s": self.age_s,
            "breaker": str(self.breaker),
            "injected": self.injected,
            "withheld": str(self.withheld) if self.withheld else None,
        }


def forecast(proxy: Proxy, target: CallTarget, now: float | None = None) -> Forecast:
    """Predict one call's outcome from local state, without opening a connection."""
    moment = now if now is not None else proxy.clock()
    entry = None
    policy = resolve(proxy.config, target)
    if policy.cacheable and target.kind == "http":
        key = cache_key(target.method or "GET", target.name)
        entry = proxy.cache.get(key)
        if entry is not None and policy.rule_index is None:
            policy = resolve(proxy.config, target, dict(entry.headers))
    allowance = policy.stale_allowance()
    breaker = proxy.breakers.get("endpoint", policy.endpoint)
    host = proxy.breakers.get("host", target.origin or "") if target.origin else None
    fault = proxy.injector.armed(policy.endpoint, target.origin, moment)

    fresh = decide(entry, allowance, Situation.START, moment)
    if isinstance(fresh, ServeFresh):
        return _forecast(
            policy,
            Outcome.FRESH,
            Advice.PROCEED,
            "a stored copy is still within its freshness lifetime",
            age_s=int(fresh.age_s),
            breaker=breaker.state,
        )

    blocked = fault is not None and fault.failure_class is not None
    open_breaker = breaker.state is BreakerState.OPEN or (
        host is not None and host.state is BreakerState.OPEN
    )
    if blocked or open_breaker:
        failed = decide(entry, allowance, Situation.ORIGIN_FAILED, moment)
        reason = (
            f"a fault is armed here ({fault.failure_class})"
            if blocked and fault is not None
            else "the breaker is open"
        )
        if isinstance(failed, ServeStale):
            return _forecast(
                policy,
                Outcome.STALE,
                Advice.PROCEED_WITH_CAUTION,
                f"{reason}, and a copy this class still allows would be served",
                age_s=int(failed.age_s),
                breaker=breaker.state,
                injected=blocked,
            )
        withheld = failed if isinstance(failed, Withhold) else None
        advice = (
            Advice.TREAT_AS_UNKNOWN if policy.volatility is Volatility.LIVE else Advice.DO_NOT_RETRY
        )
        return _forecast(
            policy,
            Outcome.DOWN,
            advice,
            f"{reason}, and nothing may be served in its place",
            age_s=int(withheld.age_s) if withheld else None,
            breaker=breaker.state,
            injected=blocked,
            withheld=withheld.reason if withheld else None,
        )

    revalidating = decide(entry, allowance, Situation.START, moment)
    if isinstance(revalidating, ServeStale):
        return _forecast(
            policy,
            Outcome.STALE,
            Advice.PROCEED_WITH_CAUTION,
            "a copy would be served while a fresh one is fetched behind it",
            age_s=int(revalidating.age_s),
            breaker=breaker.state,
        )
    return _forecast(
        policy,
        Outcome.FRESH,
        Advice.PROCEED,
        "nothing known says this would fail, so the origin would be asked",
        breaker=breaker.state,
    )


def _forecast(
    policy: ResolvedPolicy,
    predicted: Outcome,
    advice: Advice,
    reason: str,
    *,
    age_s: int | None = None,
    breaker: BreakerState = BreakerState.CLOSED,
    injected: bool = False,
    withheld: WithheldReason | None = None,
) -> Forecast:
    return Forecast(
        endpoint=policy.endpoint,
        volatility=policy.volatility,
        predicted=predicted,
        advice=advice,
        reason=reason,
        rule_index=policy.rule_index,
        age_s=age_s,
        breaker=breaker,
        injected=injected,
        withheld=withheld,
    )


def status(proxy: Proxy, now: float | None = None) -> dict[str, object]:
    """Everything leeward can say about itself without asking anyone else."""
    moment = now if now is not None else proxy.clock()
    stats = proxy.cache.stats()
    return {
        "profile": proxy.config.profile,
        "data_dir": str(proxy.loaded.data_dir),
        "endpoints": [
            health.as_dict(proxy.breakers.get("endpoint", endpoint).state)
            for endpoint, health in proxy.health.items()
        ],
        "breakers": [
            {
                "scope": breaker.scope,
                "key": breaker.key,
                "state": str(breaker.state),
                "opened_by_class": (
                    str(breaker.opened_by.failure_class) if breaker.opened_by else None
                ),
                "next_probe_in_s": breaker.next_probe_in_s(moment),
            }
            for breaker in proxy.breakers.all()
            if breaker.state is not BreakerState.CLOSED
        ],
        "cache": {
            "entries": stats.entries,
            "bytes": stats.bytes,
            "pinned": stats.pinned,
            "oldest_stored_at": stats.oldest_stored_at,
        },
        "runs": [
            {
                "id": ledger.run.id,
                "resolved_by": str(ledger.run.resolved_by),
                "retry_attempts_remaining": max(
                    ledger.limits.retry_attempts - ledger.retry_attempts, 0
                ),
                "retry_seconds_remaining": max(
                    ledger.limits.retry_seconds - ledger.retry_seconds, 0.0
                ),
                "tokens_on_retries": ledger.tokens_on_retries,
            }
            for ledger in proxy.runs.active()
        ],
        "chaos": {
            "enabled": proxy.injector.enabled,
            "armed": [fault.as_dict() for fault in proxy.injector.all(moment)],
        },
    }


@dataclass
class Degraded:
    """What the status line would say, if it were switched on."""

    down: list[str] = field(default_factory=list[str])
    stale: list[str] = field(default_factory=list[str])

    @property
    def anything(self) -> bool:
        return bool(self.down or self.stale)


def degraded(proxy: Proxy) -> Degraded:
    """Endpoints that are failing, and endpoints being answered from cache."""
    report = Degraded()
    for endpoint, health in proxy.health.items():
        if health.last_outcome is Outcome.DOWN:
            report.down.append(endpoint)
        elif health.last_outcome is Outcome.STALE:
            report.stale.append(endpoint)
    return report
