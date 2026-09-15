# SPDX-License-Identifier: Apache-2.0
"""Note templates, and the hash that ties every event to the wording that produced it."""

from __future__ import annotations

import hashlib
from functools import cache
from importlib.resources import files

TEMPLATE_NAMES = (
    "budget",
    "clauses",
    "down",
    "gone",
    "live_not_stale",
    "stale",
    "status_line",
    "wait",
)


@cache
def template_texts() -> dict[str, str]:
    """Every template's text, read on first use rather than at import."""
    root = files(__name__)
    return {
        name: root.joinpath(f"{name}.txt").read_text(encoding="utf-8") for name in TEMPLATE_NAMES
    }


@cache
def template_set_sha256() -> str:
    """SHA-256 over each template's name, length and bytes, in name order.

    Framing each file by name and length means moving a sentence from one template
    to another changes the hash, as it should: the notes would read differently.
    """
    digest = hashlib.sha256()
    for name, text in sorted(template_texts().items()):
        data = text.encode("utf-8")
        digest.update(f"{name}\n{len(data)}\n".encode())
        digest.update(data)
    return digest.hexdigest()
