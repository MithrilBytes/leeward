# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

import pytest

from leeward.surfaces.mcp import room_for_outcome

OPEN = {"type": "object", "properties": {"result": {"type": "string"}}, "required": ["result"]}


@pytest.mark.parametrize(
    ("schema", "structured", "room"),
    [
        (None, None, True),
        (None, {"result": "x"}, True),
        (None, ["a", "list"], False),
        (OPEN, {"result": "x"}, True),
        ({**OPEN, "additionalProperties": True}, {"result": "x"}, True),
        ({**OPEN, "additionalProperties": False}, {"result": "x"}, False),
        ({**OPEN, "additionalProperties": {"type": "string"}}, {"result": "x"}, False),
        ({**OPEN, "unevaluatedProperties": False}, {"result": "x"}, False),
        ({**OPEN, "allOf": [{"required": ["result"]}]}, {"result": "x"}, False),
        ({**OPEN, "$ref": "#/$defs/result"}, {"result": "x"}, False),
        ({"type": "object", "properties": {"leeward": {"type": "string"}}}, {}, False),
        ({"type": "array"}, {"result": "x"}, False),
        (OPEN, None, False),
    ],
)
def test_an_outcome_joins_structured_content_only_where_the_schema_has_room(
    schema: dict[str, Any] | None, structured: object, room: bool
) -> None:
    assert room_for_outcome(schema, structured) is room
