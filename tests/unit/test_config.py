# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import pytest

from leeward.config import DEFAULT_REDACT_HEADERS, ConfigError, load_config, parse_config
from leeward.units import human_bytes, human_duration, parse_duration, parse_size
from leeward.vocab import Volatility
from tests.support import REPO_ROOT


def test_the_example_configuration_is_valid() -> None:
    config = load_config(REPO_ROOT / "leeward.example.yaml").config
    assert [rule.name for rule in config.rules[:2]] == ["wikipedia-articles", "operator-status"]
    assert config.rules[1].volatility is Volatility.LIVE


def test_the_starter_configuration_is_valid() -> None:
    config = parse_config(files("leeward").joinpath("starter.yaml").read_text()).config
    assert config.surfaces.fetch.enabled


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        (
            "defaults:\n  soft_deadlin: 5s\n",
            "defaults.soft_deadlin: Extra inputs are not permitted",
        ),
        ("rules:\n  - match: {url: '*'}\n    clas: static\n", "rules.0.clas: Extra inputs"),
        ("profile: dev\nprofile: production\n", "line 2: duplicate key 'profile'"),
        (
            "rules:\n  - match: {url: '*'}\n    class: static\n    class: live\n",
            "line 4: duplicate key 'class'",
        ),
        (
            "rules:\n  - match: {url: '*'}\n    class: live\n    stale_on_error: 1h\n",
            "stale_on_error must be 0s for class live",
        ),
        ("rules:\n  - match: {url: '*'}\n    class: never\n    pure: true\n", "cannot be pure"),
        ("rules:\n  - match: {}\n", "a match needs at least one of"),
        ("rules:\n  - match: {url: '*'}\n    stale_on_error: 0\n", "expected a duration string"),
        ("profile: production\nchaos: {enabled: true}\n", "while profile is production"),
        (
            "surfaces:\n  fetch: {enabled: true, listen: '127.0.0.1:8787'}\n"
            "  llm: {enabled: true, listen: '127.0.0.1:9999'}\n",
            "share one listener",
        ),
        ("surfaces:\n  fetch:\n    mounts: {v1: 'https://example.com'}\n", "reserved or invalid"),
        (
            "classes:\n  - {when_status: 500, as_class: BREAKER_OPEN}\n",
            "produced by leeward itself",
        ),
        ("- a list\n- not sections\n", "top level must be a mapping"),
    ],
)
def test_invalid_configuration_names_the_file_key_and_reason(text: str, fragment: str) -> None:
    with pytest.raises(ConfigError) as caught:
        parse_config(text, Path("/srv/leeward.yaml"))
    assert str(caught.value).startswith("/srv/leeward.yaml: ")
    assert fragment in str(caught.value)


@pytest.mark.parametrize(
    "text",
    [
        "surfaces:\n  llm:\n    tiers:\n"
        "      - {name: x, base_url: 'http://h', model: m, api_key: sk-not-a-real-key}\n",
        "surfaces:\n  mcp:\n    servers:\n"
        "      gh: {transport: stdio, command: [gh-mcp], env: {GITHUB_TOKEN: placeholder}}\n",
    ],
)
def test_a_secret_written_into_configuration_is_refused(text: str) -> None:
    with pytest.raises(ConfigError, match="looks like a secret"):
        parse_config(text)


def test_a_secret_named_by_environment_variable_is_accepted() -> None:
    text = (
        "surfaces:\n  mcp:\n    servers:\n      gh:\n        transport: http\n"
        "        url: https://mcp.example.com/mcp\n        headers_env: {Authorization: GH_AUTH}\n"
    )
    server = parse_config(text).config.surfaces.mcp.servers["gh"]
    assert server.transport == "http"


def test_configuration_can_add_redacted_headers_but_not_remove_the_defaults() -> None:
    config = parse_config("redaction:\n  headers: [x-internal-token]\n").config
    assert config.redact_headers() == frozenset(DEFAULT_REDACT_HEADERS) | {"x-internal-token"}


def test_a_relative_data_dir_resolves_against_the_config_file(tmp_path: Path) -> None:
    path = tmp_path / "leeward.yaml"
    path.write_text("data_dir: ./state\n")
    assert load_config(path).data_dir == (tmp_path / "state").resolve()


def test_without_a_config_file_the_defaults_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    loaded = load_config(None)
    assert loaded.source is None
    assert loaded.config.defaults.volatility is Volatility.VOLATILE


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("850ms", 0.85), ("0s", 0.0), ("30s", 30.0), ("6h", 21600.0), ("30d", 2592000.0)],
)
def test_durations_parse(text: str, seconds: float) -> None:
    assert parse_duration(text) == pytest.approx(seconds)


@pytest.mark.parametrize("text", ["30", "1.5s", "-1s", "5 minutes", "1w"])
def test_malformed_durations_are_rejected(text: str) -> None:
    with pytest.raises(ValueError, match="not a duration"):
        parse_duration(text)


@pytest.mark.parametrize(
    ("value", "count"),
    [
        (10485760, 10485760),
        ("200MB", 200_000_000),
        ("64KiB", 65536),
        ("1GiB", 1024**3),
        ("12 B", 12),
    ],
)
def test_sizes_use_decimal_and_binary_prefixes_as_named(value: int | str, count: int) -> None:
    assert parse_size(value) == count


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (0.0, "0s"),
        (0.25, "250ms"),
        (42.9, "42s"),
        (41 * 60 + 59, "41m"),
        (3600 + 5 * 60 + 59, "1h 5m"),
        (7200, "2h"),
        (3 * 86400 + 4 * 3600 + 59, "3d 4h"),
    ],
)
def test_human_durations_truncate_rather_than_round(seconds: float, text: str) -> None:
    assert human_duration(seconds) == text


def test_human_bytes_use_decimal_units() -> None:
    assert human_bytes(3_100_000) == "3.1 MB"
    assert human_bytes(999) == "999 B"
