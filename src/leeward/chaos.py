# SPDX-License-Identifier: Apache-2.0
"""Fault injection, armed by hand and always recorded as injected.

A demonstration that a proxy survives an outage is worth nothing if nobody can tell
whether the outage was real, so a fault armed here marks every event it produces.

The injector sits at the transport boundary rather than in front of the classifier,
so an injected fault takes the same path as a real one: the attempt engine sees
evidence, the classifier names it, the breaker counts it, and the note is written
from the same template. Nothing downstream has a special case for chaos, which is
what makes a recording evidence rather than theatre.

Faults live in a small file under the data directory, because `leeward chaos` runs
in one process and `leeward serve` in another, and `leeward forecast` in a third has
to predict what the armed fault will do.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal, cast

from leeward.vocab import FailureClass

Scope = Literal["endpoint", "host"]

TIMED_OUT_CLASSES = frozenset(
    {FailureClass.CONNECT_TIMEOUT, FailureClass.READ_TIMEOUT, FailureClass.WEDGED}
)
"""Classes that mean nothing answered. An injection of one of these waits for the
deadline it belongs to before reporting, because a blackhole that answered instantly
would make every timing in a recording a lie."""

INJECTABLE = frozenset(FailureClass) - {
    FailureClass.OK,
    FailureClass.BREAKER_OPEN,
    FailureClass.BUDGET_EXHAUSTED,
}
"""Everything an origin can do to leeward. The two classes leeward produces itself
cannot be injected, and neither can success."""


class ChaosDisabledError(RuntimeError):
    """Fault injection was asked for while it is switched off, or under a production profile."""


@dataclass(frozen=True, slots=True)
class Fault:
    """One armed fault. `until` is None for one that stays until it is lifted."""

    target: str
    scope: Scope = "endpoint"
    failure_class: FailureClass | None = None
    latency_s: float = 0.0
    retry_after_s: float | None = None
    until: float | None = None

    def expired(self, now: float) -> bool:
        return self.until is not None and now >= self.until

    def matches(self, endpoint: str, origin: str | None) -> bool:
        subject = endpoint if self.scope == "endpoint" else origin
        return subject is not None and fnmatchcase(subject, self.target)

    def as_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "scope": self.scope,
            "failure_class": str(self.failure_class) if self.failure_class else None,
            "latency_s": self.latency_s,
            "retry_after_s": self.retry_after_s,
            "until": self.until,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> Fault:
        failure = raw.get("failure_class")
        scope = raw.get("scope")
        return cls(
            target=str(raw.get("target", "*")),
            scope="host" if scope == "host" else "endpoint",
            failure_class=FailureClass(failure) if isinstance(failure, str) else None,
            latency_s=float(cast("float", raw.get("latency_s") or 0.0)),
            retry_after_s=(
                float(cast("float", raw["retry_after_s"]))
                if isinstance(raw.get("retry_after_s"), int | float)
                else None
            ),
            until=(
                float(cast("float", raw["until"]))
                if isinstance(raw.get("until"), int | float)
                else None
            ),
        )


class FaultInjector:
    """The armed faults, shared between processes through one small file.

    Reloaded when the file changes, so a fault armed by the CLI reaches a running
    proxy without either one holding a lock on the other.
    """

    def __init__(self, path: Path, *, enabled: bool, profile: str) -> None:
        if enabled and profile == "production":
            raise ChaosDisabledError(
                "chaos: fault injection cannot be enabled while profile is production"
            )
        self.path = path
        self.enabled = enabled
        self._faults: list[Fault] = []
        self._stamp: tuple[int, int] | None = None

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise ChaosDisabledError("fault injection is off; set chaos.enabled: true to use it")

    def _reload(self) -> None:
        """Read the file when its size or modification time has changed."""
        try:
            status = self.path.stat()
        except FileNotFoundError:
            self._faults, self._stamp = [], None
            return
        stamp = (status.st_size, status.st_mtime_ns)
        if stamp == self._stamp:
            return
        raw: object = json.loads(self.path.read_text(encoding="utf-8") or "[]")
        items = cast("list[dict[str, object]]", raw) if isinstance(raw, list) else []
        self._faults = [Fault.from_dict(item) for item in items]
        self._stamp = stamp

    def _write(self) -> None:
        """Replace the file atomically, so a reader never sees half a list."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps([fault.as_dict() for fault in self._faults], indent=2) + "\n"
        handle, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".chaos-")
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(payload)
        os.replace(temporary, self.path)
        self._stamp = None

    def arm(
        self,
        target: str,
        *,
        now: float,
        scope: Scope = "endpoint",
        failure_class: FailureClass | None = None,
        latency_s: float = 0.0,
        retry_after_s: float | None = None,
        for_seconds: float | None = None,
    ) -> Fault:
        self._require_enabled()
        if failure_class is not None and failure_class not in INJECTABLE:
            raise ChaosDisabledError(f"{failure_class} is leeward's own; it cannot be injected")
        if failure_class is None and latency_s <= 0:
            raise ChaosDisabledError("arm a failure class or a latency, or there is nothing to do")
        self._reload()
        fault = Fault(
            target=target,
            scope=scope,
            failure_class=failure_class,
            latency_s=latency_s,
            retry_after_s=retry_after_s,
            until=None if for_seconds is None else now + for_seconds,
        )
        self._faults = [existing for existing in self._faults if existing.target != target]
        self._faults.append(fault)
        self._write()
        return fault

    def restore(self, target: str) -> list[Fault]:
        """Lift the faults whose target matches, returning what was lifted."""
        self._require_enabled()
        self._reload()
        lifted = [fault for fault in self._faults if fnmatchcase(fault.target, target)]
        if lifted:
            self._faults = [fault for fault in self._faults if fault not in lifted]
            self._write()
        return lifted

    def restore_all(self) -> list[Fault]:
        self._require_enabled()
        self._reload()
        lifted = list(self._faults)
        if lifted:
            self._faults = []
            self._write()
        return lifted

    def armed(self, endpoint: str, origin: str | None, now: float) -> Fault | None:
        """The first armed fault this call matches, host scope before endpoint scope."""
        if not self.enabled:
            return None
        self._reload()
        live = [fault for fault in self._faults if not fault.expired(now)]
        for scope in ("host", "endpoint"):
            for fault in live:
                if fault.scope == scope and fault.matches(endpoint, origin):
                    return fault
        return None

    def all(self, now: float) -> list[Fault]:
        if not self.enabled:
            return []
        self._reload()
        return [fault for fault in self._faults if not fault.expired(now)]

    def with_deadline(
        self, fault: Fault, connect_timeout_s: float, hard_deadline_s: float
    ) -> float:
        """How long an injected fault should take before it reports, in seconds."""
        if fault.failure_class is None:
            return fault.latency_s
        if fault.failure_class is FailureClass.WEDGED:
            return hard_deadline_s
        if fault.failure_class in TIMED_OUT_CLASSES:
            return max(connect_timeout_s, fault.latency_s)
        return fault.latency_s

    def hang(self, target: str, *, now: float, scope: Scope = "endpoint") -> Fault:
        """Accept connections and never answer: the wedge that costs a run its deadline."""
        return self.arm(target, now=now, scope=scope, failure_class=FailureClass.WEDGED)

    def load(self, faults: list[Fault]) -> None:
        """Replace the armed set, used by tests and by the demo controller."""
        self._require_enabled()
        self._faults = list(faults)
        self._write()

    def snapshot(self) -> list[Fault]:
        return list(self._faults)

    def expire(self, now: float) -> list[Fault]:
        """Drop faults whose time has run out, returning them."""
        self._reload()
        gone = [fault for fault in self._faults if fault.expired(now)]
        if gone:
            self._faults = [fault for fault in self._faults if not fault.expired(now)]
            self._write()
        return gone

    def retimed(self, fault: Fault, now: float) -> Fault:
        """The same fault with its remaining time measured from now, for status output."""
        return replace(fault, until=None if fault.until is None else max(fault.until - now, 0.0))
