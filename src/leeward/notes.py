# SPDX-License-Identifier: Apache-2.0
"""Notes: what leeward says to the model, rendered from versioned templates.

A note is leeward speaking, never the origin, so it is built only from things
leeward knows: a host or tool name, a class, a count, a duration. No part of a
response reaches it. The `[leeward]` prefix is there so that a note can never be
mistaken for retrieved data, and so retrieved data can never impersonate a note.

Every note says the same four things in the same order: what happened, whether
waiting can help, what is available instead, and what to do about it. It is written
for a reader with very little patience, because that is what a model reading a tool
result has.

The wording lives in files, and the hash of that set travels on every event, so a
change in what leeward said is visible in the log rather than being folklore.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache

from leeward.cache.freshness import StaleReason
from leeward.templates import template_texts
from leeward.units import human_duration
from leeward.vocab import Advice, Disposition, FailureClass, Outcome, Volatility, WithheldReason

NOTE_LIMIT = 400
"""Every note fits in this many characters. The detail lives in the structured field."""

PREFIX = "[leeward]"
NAME_LIMIT = 48

_VARIABLE = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")
_COMMENT = re.compile(r"\{#.*?#\}\s*", re.DOTALL)


class MissingNoteValueError(KeyError):
    """A template asked for something the caller did not provide."""


@cache
def clauses() -> dict[str, str]:
    """The sentence parts, read from the clause template as `key: text` lines."""
    found: dict[str, str] = {}
    for line in template_texts()["clauses"].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("{#"):
            continue
        key, separator, text = stripped.partition(":")
        if separator:
            found[key.strip()] = text.strip()
    return found


def render(template: str, values: Mapping[str, str]) -> str:
    """Fill a template, refusing to leave a hole where a value should be."""
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            missing.append(name)
            return ""
        return values[name]

    text = _VARIABLE.sub(replace, _COMMENT.sub("", template).strip())
    if missing:
        raise MissingNoteValueError(f"the template wanted {', '.join(sorted(set(missing)))}")
    return " ".join(text.split())


def clause(name: str, values: Mapping[str, str] | None = None) -> str:
    text = clauses().get(name, "")
    return render(text, values or {}) if text else ""


def shorten(name: str, limit: int = NAME_LIMIT) -> str:
    return name if len(name) <= limit else name[: limit - 3] + "..."


@dataclass(frozen=True, slots=True)
class NoteFacts:
    """Everything a note may mention. All of it is leeward's own knowledge."""

    outcome: Outcome
    host_or_tool: str
    volatility: Volatility
    failure_class: FailureClass | None = None
    disposition: Disposition | None = None
    attempts: int = 0
    elapsed_s: float = 0.0
    age_s: float | None = None
    stale_reason: StaleReason | None = None
    withheld_age_s: float | None = None
    withheld_reason: WithheldReason | None = None
    retry_after_s: float | None = None
    retry_attempts_remaining: int | None = None
    accept_stale_via: str | None = None
    tool_name: str | None = None
    server_name: str | None = None
    soft_deadline_s: float | None = None
    clock_is_wrong: bool = False
    advice: Advice | None = None
    """The advice beside the note, which the note must not contradict."""


CONNECTIVITY_CLASSES = frozenset(
    {
        FailureClass.DNS_FAILURE,
        FailureClass.DNS_NXDOMAIN,
        FailureClass.CONNECT_TIMEOUT,
        FailureClass.CONNECT_REFUSED,
        FailureClass.WEDGED,
    }
)
"""Failures where nothing is getting through right now, whether or not it might later."""

_ACCURACY = {
    Volatility.STATIC: "accuracy.static",
    Volatility.SLOW: "accuracy.slow",
    Volatility.VOLATILE: "accuracy.volatile",
}

_BECAUSE = {
    StaleReason.ERROR: "because.unreachable",
    StaleReason.SLOW: "because.slow",
    StaleReason.REVALIDATING: "because.revalidating",
    StaleReason.ACCEPTED: "because.unreachable",
}


def _retry_clause(facts: NoteFacts) -> str:
    if facts.clock_is_wrong:
        return clause("retry.clock")
    if facts.disposition is Disposition.WAIT and facts.retry_after_s:
        return clause("retry.after", {"retry_after_human": human_duration(facts.retry_after_s)})
    if facts.failure_class in (FailureClass.TOOL_GONE, FailureClass.BUDGET_EXHAUSTED):
        return clause("retry.never_run")
    if facts.advice is Advice.RETRY_AFTER:
        # The advice says another try is worth making, so the note says when rather
        # than contradict it. A first hang of a call that is not hedged lands here.
        if facts.retry_after_s:
            return clause("retry.after", {"retry_after_human": human_duration(facts.retry_after_s)})
        return clause("retry.shortly")
    if facts.failure_class in CONNECTIVITY_CLASSES and facts.tool_name is None:
        # Whatever the disposition says about later, nothing gets through now. A tool
        # has no connectivity of its own to wait for, so it gets the plain clauses.
        return clause("retry.connectivity")
    if facts.disposition is Disposition.NEVER:
        return clause("retry.never")
    if facts.attempts > 1:
        return clause("retry.exhausted")
    return clause("retry.shortly")


def _alternatives_clause(facts: NoteFacts) -> str:
    if facts.withheld_reason is not WithheldReason.BEYOND_STALE_ALLOWANCE:
        return ""
    age = human_duration(facts.withheld_age_s or 0.0)
    text = clause("alternative.too_old", {"withheld_age_human": age})
    if facts.accept_stale_via == "header":
        text = f"{text} {clause('alternative.header')}"
    elif facts.accept_stale_via == "argument":
        text = f"{text} {clause('alternative.argument')}"
    return f" {text}"


def _stale(facts: NoteFacts, templates: Mapping[str, str]) -> str:
    reason = facts.stale_reason or StaleReason.ERROR
    because = clause(
        _BECAUSE[reason],
        {
            "host_or_tool": shorten(facts.host_or_tool),
            "failure_class": str(facts.failure_class or FailureClass.OK),
            "soft_human": human_duration(facts.soft_deadline_s or 0.0),
        },
    )
    return render(
        templates["stale"],
        {
            "age_human": human_duration(facts.age_s or 0.0),
            "because_clause": because,
            "volatility": str(facts.volatility),
            "accuracy_clause": clause(_ACCURACY.get(facts.volatility, "accuracy.volatile")),
            "retry_clause": _retry_clause(facts),
        },
    )


def _down(facts: NoteFacts, templates: Mapping[str, str]) -> str:
    name = shorten(facts.host_or_tool)
    failure = str(facts.failure_class or FailureClass.OK)
    plural = "" if facts.attempts == 1 else "s"
    if facts.failure_class is FailureClass.TOOL_GONE:
        return render(
            templates["gone"],
            {
                "tool_name": shorten(facts.tool_name or facts.host_or_tool),
                "server_name": shorten(facts.server_name or "its server"),
            },
        )
    if facts.failure_class is FailureClass.BUDGET_EXHAUSTED:
        return render(
            templates["budget"],
            {
                "host_or_tool": name,
                "spent_attempts": str(max(facts.attempts, 1)),
                "scope_clause": f" {clause('scope.run')}",
            },
        )
    if facts.withheld_reason is WithheldReason.VOLATILITY_LIVE:
        return render(
            templates["live_not_stale"],
            {
                "host_or_tool": name,
                "failure_class": failure,
                "elapsed_human": human_duration(facts.elapsed_s),
                "attempts": str(facts.attempts),
                "attempts_plural": plural,
                "withheld_age_human": human_duration(facts.withheld_age_s or 0.0),
            },
        )
    if facts.disposition is Disposition.WAIT and facts.retry_after_s:
        remaining = facts.retry_attempts_remaining
        budget = (
            f"{clause('budget.remaining', {'retry_attempts_remaining': str(remaining)})}"
            if remaining is not None
            else ""
        )
        return render(
            templates["wait"],
            {
                "host_or_tool": name,
                "failure_class": failure,
                "retry_after_human": human_duration(facts.retry_after_s),
                "budget_clause": budget,
            },
        )
    return render(
        templates["down"],
        {
            "host_or_tool": name,
            "failure_class": failure,
            "elapsed_human": human_duration(facts.elapsed_s),
            "attempts": str(facts.attempts),
            "attempts_plural": plural,
            "retry_clause": _retry_clause(facts),
            "alternatives_clause": _alternatives_clause(facts),
        },
    )


def compose(facts: NoteFacts) -> str:
    """The note for one outcome, or nothing at all when the call simply worked."""
    if facts.outcome is Outcome.FRESH:
        return ""
    templates = template_texts()
    text = _stale(facts, templates) if facts.outcome is Outcome.STALE else _down(facts, templates)
    return _fit(text)


def _fit(text: str) -> str:
    """Keep a note inside its limit by dropping its last sentences, never its first."""
    if len(text) <= NOTE_LIMIT:
        return text
    sentences = re.split(r"(?<=\.) ", text)
    while len(sentences) > 1 and len(" ".join(sentences)) > NOTE_LIMIT:
        sentences.pop()
    trimmed = " ".join(sentences)
    return trimmed if len(trimmed) <= NOTE_LIMIT else trimmed[: NOTE_LIMIT - 3].rstrip() + "..."


def status_line(down: list[str], stale: list[str]) -> str:
    """The one line LLM mode may prepend, and only while something is degraded."""
    if not down and not stale:
        return ""
    parts: list[str] = []
    if down:
        parts.append(f"{', '.join(shorten(name, 24) for name in down[:3])} unreachable")
    if stale:
        parts.append(f"{', '.join(shorten(name, 24) for name in stale[:3])} served from cache")
    return render(template_texts()["status_line"], {"summary": "; ".join(parts)})
