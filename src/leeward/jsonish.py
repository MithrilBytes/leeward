# SPDX-License-Identifier: Apache-2.0
"""Reading objects that came from somewhere else.

An event log line, a client's `_meta`, an MCP client configuration written by another
program: all of them arrive as `object` and have to be narrowed before anything can be
read out of them. Doing that inline costs a cast and an isinstance at every use, so the
shape is stated once here instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

EMPTY: Mapping[str, object] = {}


def mapping(value: object) -> Mapping[str, object]:
    """The value as a mapping of string keys, or an empty one."""
    return cast("Mapping[str, object]", value) if isinstance(value, dict) else EMPTY


def text(value: object) -> str | None:
    """The value as a non-empty string, or nothing."""
    return value if isinstance(value, str) and value else None
