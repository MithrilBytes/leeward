# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON, so equal values hash equally wherever they came from.

Tool arguments become cache keys and conversations become run identities, and both
must not depend on the order a client happened to write its keys or how it
formatted a number. This is the JSON Canonicalization Scheme of RFC 8785: keys
sorted by UTF-16 code units, no insignificant whitespace, and numbers written the
way ECMAScript writes them.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import cast

MAX_SAFE_INTEGER = 2**53
"""Integers up to 2^53 survive the IEEE 754 double that I-JSON numbers are (RFC 7493 §2.2)."""


def _number(value: float) -> str:
    """ECMAScript Number::toString (ECMA-262 §6.1.6.1.20), which RFC 8785 §3.2.2.3 requires.

    repr() already gives the shortest digits that round-trip, which is the digit
    string the ECMAScript algorithm calls for; only the layout differs.
    """
    if math.isnan(value) or math.isinf(value):
        raise ValueError("JSON has no representation for NaN or infinity")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    parts = Decimal(repr(abs(value))).as_tuple()
    all_digits = "".join(str(digit) for digit in parts.digits)
    digits = all_digits.rstrip("0")
    exponent = int(parts.exponent) + len(all_digits) - len(digits)
    k = len(digits)
    n = exponent + k
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = f"{digits[:n]}.{digits[n:]}"
    elif -6 < n <= 0:
        body = "0." + "0" * -n + digits
    else:
        mantissa = digits[0] + (f".{digits[1:]}" if k > 1 else "")
        body = f"{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    return sign + body


def _encode(value: object) -> str:
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        return str(value) if abs(value) <= MAX_SAFE_INTEGER else _number(float(value))
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        text = json.dumps(value, ensure_ascii=False)
        text.encode("utf-8")
        return text
    if isinstance(value, Mapping):
        entries = cast("Mapping[object, object]", value)
        items: list[tuple[str, object]] = []
        for key, item in entries.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings, not {type(key).__name__}")
            items.append((key, item))
        items.sort(key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_encode(key)}:{_encode(item)}" for key, item in items) + "}"
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        members = cast("Sequence[object]", value)
        return "[" + ",".join(_encode(item) for item in members) + "]"
    raise TypeError(f"{type(value).__name__} is not a JSON value")


def canonical_json(value: object) -> str:
    """The RFC 8785 serialization of a JSON value. Lone surrogates raise, as I-JSON forbids them."""
    return _encode(value)


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
