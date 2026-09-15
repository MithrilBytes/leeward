# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from leeward.config import Config, parse_config
from leeward.policy import CallTarget, policy_warnings, resolve
from leeward.vocab import Volatility

RULES = """
rules:
  - name: wiki
    match: {url: "*/wiki/*"}
    class: static
    stale_on_error: 30d
  - name: status
    match: {url: "*/status*"}
    class: live
    hard_deadline: 10s
  - name: deadline-only
    match: {host: "slow.example.com"}
    hard_deadline: 3s
  - name: notes
    match: {tool: "notes/*"}
    pure: true
    stale_on_error: 6h
  - name: writes
    match: {method: POST}
    class: never
    idempotent: false
  - name: models
    match: {tier: "*"}
    soft_deadline: 20s
    hard_deadline: 120s
"""


@pytest.fixture(scope="module")
def config() -> Config:
    return parse_config(RULES).config


ITEMS = "https://api.example.com/items"


@pytest.mark.parametrize(
    ("target", "origin", "volatility", "source", "rule_index"),
    [
        (
            CallTarget.http("https://en.wikipedia.org/wiki/Foo"),
            None,
            "static",
            "rules[0] (wiki)",
            0,
        ),
        (
            CallTarget.http("https://en.wikipedia.org/wiki/Foo"),
            {"Cache-Control": "no-store"},
            "static",
            "rules[0] (wiki)",
            0,
        ),
        (CallTarget.http(ITEMS), {"Cache-Control": "no-store"}, "never", "no-store", None),
        (CallTarget.http(ITEMS), {"cache-control": "no-cache"}, "live", "every use", None),
        (CallTarget.http(ITEMS), {"Cache-Control": "max-age=0, must-revalidate"}, "live", "", None),
        (
            CallTarget.http(ITEMS),
            {"Cache-Control": "public, max-age=31536000, immutable"},
            "static",
            "immutable",
            None,
        ),
        (
            CallTarget.http(ITEMS),
            {"Cache-Control": "max-age=172800"},
            "slow",
            "max-age=172800",
            None,
        ),
        (CallTarget.http(ITEMS), {"Cache-Control": "max-age=60"}, "volatile", "max-age=60", None),
        (CallTarget.http(ITEMS, "POST"), None, "never", "rules[4] (writes)", 4),
        (CallTarget.http(ITEMS, "PUT"), None, "never", "method PUT may have side effects", None),
        (
            CallTarget.http(ITEMS, "PUT"),
            {"Cache-Control": "max-age=60"},
            "volatile",
            "origin",
            None,
        ),
        (CallTarget.tool("notes", "search_notes"), None, "volatile", "defaults.class", 3),
        (CallTarget.tool("notes", "create_note"), None, "never", "write_tool_pattern", 3),
        (CallTarget.tool("mail", "sendMessage"), None, "never", "write_tool_pattern", None),
        (CallTarget.tool("mail", "settings_lookup"), None, "volatile", "defaults.class", None),
        (CallTarget.tier("primary"), None, "never", "model completions", 5),
        (CallTarget.http("https://slow.example.com/x"), None, "volatile", "defaults.class", 2),
    ],
)
def test_class_precedence_is_rule_then_origin_then_side_effects_then_default(
    config: Config,
    target: CallTarget,
    origin: dict[str, str] | None,
    volatility: str,
    source: str,
    rule_index: int | None,
) -> None:
    policy = resolve(config, target, origin)
    assert policy.volatility == volatility
    assert source in policy.volatility_source
    assert policy.rule_index == rule_index


def test_the_first_matching_rule_wins() -> None:
    config = parse_config(
        "rules:\n  - match: {url: '*'}\n    class: slow\n"
        "  - match: {url: '*/wiki/*'}\n    class: static\n"
    ).config
    policy = resolve(config, CallTarget.http("https://en.wikipedia.org/wiki/Foo"))
    assert (policy.volatility, policy.rule_index) == (Volatility.SLOW, 0)


@pytest.mark.parametrize(
    ("target", "soft", "hard", "source"),
    [
        (CallTarget.http("https://en.wikipedia.org/wiki/Foo"), 5.0, 30.0, "defaults"),
        (CallTarget.http("https://ops.example.com/status"), 5.0, 10.0, "rules[1] (status)"),
        (CallTarget.http("https://slow.example.com/x"), 3.0, 3.0, "rules[2] (deadline-only)"),
        (CallTarget.tier("primary"), 20.0, 120.0, "rules[5] (models)"),
    ],
)
def test_deadlines_come_from_the_rule_or_the_defaults(
    config: Config, target: CallTarget, soft: float, hard: float, source: str
) -> None:
    policy = resolve(config, target)
    assert (policy.soft_deadline_s, policy.hard_deadline_s, policy.deadline_source) == (
        soft,
        hard,
        source,
    )


def test_model_calls_default_to_longer_deadlines_without_a_rule() -> None:
    policy = resolve(Config(), CallTarget.tier("local"))
    assert (policy.soft_deadline_s, policy.hard_deadline_s) == (20.0, 120.0)


def test_stale_allowances_come_from_rule_origin_or_class(config: Config) -> None:
    wiki = resolve(config, CallTarget.http("https://en.wikipedia.org/wiki/Foo"))
    assert (wiki.stale_on_error_s, wiki.stale_while_revalidate_s) == (30 * 86400.0, 30 * 86400.0)

    live = resolve(config, CallTarget.http("https://ops.example.com/status"))
    assert (live.stale_on_error_s, live.stale_while_revalidate_s) == (0.0, 0.0)

    headers = {"Cache-Control": 'max-age=60, stale-if-error=600, stale-while-revalidate="30"'}
    origin = resolve(config, CallTarget.http(ITEMS), headers)
    assert (origin.stale_on_error_s, origin.stale_while_revalidate_s) == (600.0, 30.0)
    assert origin.stale_source == "origin stale-if-error"

    volatile = resolve(config, CallTarget.http(ITEMS))
    assert (volatile.stale_on_error_s, volatile.stale_while_revalidate_s) == (3600.0, 0.0)


def test_a_live_endpoint_has_no_stale_allowance_even_if_the_origin_offers_one() -> None:
    config = parse_config("rules:\n  - match: {url: '*/status*'}\n    class: live\n").config
    headers = {"Cache-Control": "max-age=5, stale-if-error=86400, stale-while-revalidate=60"}
    policy = resolve(config, CallTarget.http("https://ops.example.com/status"), headers)
    assert (policy.stale_on_error_s, policy.stale_while_revalidate_s) == (0.0, 0.0)


@pytest.mark.parametrize(
    ("target", "cacheable", "idempotent"),
    [
        (CallTarget.http(ITEMS), True, True),
        (CallTarget.http(ITEMS, "HEAD"), True, True),
        (CallTarget.http(ITEMS, "POST"), False, False),
        (CallTarget.http(ITEMS, "PUT"), False, False),
        (CallTarget.tool("notes", "search_notes"), True, True),
        (CallTarget.tool("notes", "create_note"), False, True),
        (CallTarget.tool("other", "lookup"), False, False),
        (CallTarget.tier("primary"), False, False),
    ],
)
def test_only_safe_methods_and_pure_calls_are_cacheable(
    config: Config, target: CallTarget, cacheable: bool, idempotent: bool
) -> None:
    policy = resolve(config, target)
    assert (policy.cacheable, policy.idempotent) == (cacheable, idempotent)


@pytest.mark.parametrize(
    ("url", "endpoint", "origin"),
    [
        (
            "https://api.example.com/tickets/123?page=2",
            "https://api.example.com/tickets/{id}",
            "https://api.example.com:443",
        ),
        ("http://127.0.0.1:8900/status", "http://127.0.0.1:8900/status", "http://127.0.0.1:8900"),
        (
            "https://EXAMPLE.com:443/a/0f8fad5b-d9cb-469f-a165-70867728950e/b",
            "https://example.com/a/{id}/b",
            "https://example.com:443",
        ),
        ("http://[::1]:8080/x/deadbeefdeadbeef", "http://[::1]:8080/x/{id}", "http://[::1]:8080"),
        (
            "https://en.wikipedia.org/wiki/2003_blackout",
            "https://en.wikipedia.org/wiki/2003_blackout",
            None,
        ),
    ],
)
def test_endpoints_template_identifier_segments(
    url: str, endpoint: str, origin: str | None
) -> None:
    target = CallTarget.http(url)
    assert target.endpoint == endpoint
    if origin is not None:
        assert target.origin == origin


def test_targets_parse_the_way_the_cli_accepts_them() -> None:
    assert CallTarget.parse("notes/search") == CallTarget.tool("notes", "search")
    assert CallTarget.parse("tier:local") == CallTarget.tier("local")
    assert CallTarget.parse("https://x.example/y").kind == "http"
    assert CallTarget.tool("notes", "search").endpoint == "notes/search"
    assert CallTarget.tier("local").endpoint == "tier:local"
    with pytest.raises(ValueError, match="not a URL"):
        CallTarget.parse("justaword")


def test_caching_non_get_responses_without_varying_on_credentials_warns() -> None:
    risky = parse_config("rules:\n  - match: {method: POST}\n    pure: true\n").config
    assert "vary_on: [authorization]" in policy_warnings(risky)[0]
    safe = parse_config(
        "rules:\n  - match: {method: POST}\n    pure: true\n    vary_on: [Authorization]\n"
    ).config
    assert policy_warnings(safe) == []
