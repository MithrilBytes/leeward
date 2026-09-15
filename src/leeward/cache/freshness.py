# SPDX-License-Identifier: Apache-2.0
"""HTTP caching semantics: the subset of RFC 9111 and RFC 5861 that leeward applies."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

DELTA_SECONDS_CEILING = 2**31
"""RFC 9111 §1.2.2: a delta-seconds value too large to represent is taken as 2^31."""

_DIGITS = re.compile(r"^[0-9]+$")
_QUOTED_PAIR = re.compile(r"\\(.)")


def _split_list(field: str) -> list[str]:
    """Split a comma-separated field value, leaving commas inside quoted strings alone.

    RFC 9110 §5.6.1 defines the list syntax and §5.6.4 the quoted-string, whose
    backslash escapes a quote.
    """
    items: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in field:
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            items.append("".join(current))
            current = []
            continue
        current.append(char)
    items.append("".join(current))
    return [item.strip() for item in items if item.strip()]


def parse_cache_control(field_values: Iterable[str]) -> dict[str, str | None]:
    """Directives from one or more Cache-Control field lines (RFC 9111 §5.2).

    Names are case-insensitive. A directive without an argument maps to None. When
    a directive repeats, the first occurrence is used, which RFC 9111 §4.2.1 allows.
    """
    directives: dict[str, str | None] = {}
    for field in field_values:
        for item in _split_list(field):
            name, separator, value = item.partition("=")
            name = name.strip().lower()
            if not name:
                continue
            value = value.strip()
            if separator and len(value) >= 2 and value[0] == value[-1] == '"':
                value = _QUOTED_PAIR.sub(r"\1", value[1:-1])
            directives.setdefault(name, value if separator else None)
    return directives


def delta_seconds(value: str | None) -> int | None:
    """A delta-seconds argument (RFC 9111 §1.2.2), or None when absent or malformed."""
    if value is None or not _DIGITS.match(value):
        return None
    return min(int(value), DELTA_SECONDS_CEILING)


def header_values(headers: Mapping[str, str], name: str) -> list[str]:
    """Every value of a field, matched case-insensitively (RFC 9110 §5.1)."""
    wanted = name.lower()
    return [value for key, value in headers.items() if key.lower() == wanted]
