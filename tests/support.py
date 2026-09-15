# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the tests: the published schemas as validators."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from functools import cache
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

REPO_ROOT = Path(__file__).resolve().parents[1]


@cache
def validator(name: str) -> Draft202012Validator:
    path = REPO_ROOT / "schemas" / f"{name}.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def assert_valid(name: str, instance: object) -> None:
    check = cast(
        "Callable[[Any], Iterable[ValidationError]]",
        validator(name).iter_errors,  # pyright: ignore[reportUnknownMemberType]
    )
    errors: list[ValidationError] = list(check(cast("Any", instance)))
    assert not errors, "\n".join(f"{list(error.path)}: {error.message}" for error in errors)
