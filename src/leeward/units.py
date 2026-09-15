# SPDX-License-Identifier: Apache-2.0
"""Durations and byte sizes, parsed from configuration and written for people."""

from __future__ import annotations

import re

_DURATION = re.compile(r"^([0-9]+)(ms|s|m|h|d)$")
_SECONDS_PER_UNIT = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}

_SIZE = re.compile(r"^([0-9]+)\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)?$")
# IEC 80000-13:2008 keeps the SI prefixes decimal and gives binary multiples their own
# names, so 200MB is 200 * 1000**2 bytes and 200MiB is 200 * 1024**2.
_BYTES_PER_UNIT = {
    "B": 1,
    "KB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
}


def parse_duration(text: str) -> float:
    """Seconds in a duration such as '850ms', '30s', '6h' or '30d'. Zero is '0s'."""
    match = _DURATION.match(text.strip())
    if match is None:
        raise ValueError(f"{text!r} is not a duration; write a whole number and a unit, e.g. '30s'")
    return int(match.group(1)) * _SECONDS_PER_UNIT[match.group(2)]


def parse_size(value: int | str) -> int:
    """Bytes in a size given as an integer or a string such as '200MB' or '64KiB'."""
    if isinstance(value, bool):
        raise ValueError("expected a byte count, not a boolean")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("a byte count cannot be negative")
        return value
    match = _SIZE.match(value.strip())
    if match is None:
        raise ValueError(f"{value!r} is not a size; write e.g. 10485760, '200MB' or '64KiB'")
    return int(match.group(1)) * _BYTES_PER_UNIT[match.group(2) or "B"]


def human_duration(seconds: float) -> str:
    """A short duration for a note: '850ms', '30s', '41m', '2h 5m', '3d 4h'.

    Truncated rather than rounded, so an age is never reported as older or younger
    than a whole unit it has not reached.
    """
    seconds = max(seconds, 0.0)
    if seconds == 0:
        return "0s"
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    whole = int(seconds)
    for unit, size, smaller, smaller_size in (("d", 86400, "h", 3600), ("h", 3600, "m", 60)):
        if whole >= size:
            major, rest = divmod(whole, size)
            minor = rest // smaller_size
            return f"{major}{unit} {minor}{smaller}" if minor else f"{major}{unit}"
    if whole >= 60:
        return f"{whole // 60}m"
    return f"{whole}s"


def human_bytes(count: int) -> str:
    """Decimal units, to match how sizes are written in configuration."""
    for unit, size in (("GB", 1000**3), ("MB", 1000**2), ("KB", 1000)):
        if count >= size:
            return f"{count / size:.1f} {unit}"
    return f"{count} B"
