# SPDX-License-Identifier: Apache-2.0
"""Configuration: read leeward.yaml, validate it, and say exactly what is wrong.

Unknown keys are errors, and so are duplicate keys. A proxy that quietly ignores a
misspelled deadline behaves differently from what its operator believes, and the
difference shows up during an outage, which is the worst time to find it.

Secrets never appear here. A field names the environment variable that holds one,
and leeward reads the variable when it needs the value, never at import.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self, cast
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError, model_validator

from leeward.units import parse_duration, parse_size
from leeward.vocab import LEEWARD_CLASSES, Disposition, FailureClass, Volatility

DEFAULT_REDACT_HEADERS = ("authorization", "x-api-key", "cookie", "proxy-authorization")
DEFAULT_WRITE_TOOL_PATTERN = (
    r"^(create|update|delete|remove|send|post|put|patch|write|set|insert|upsert|drop|"
    r"execute|run|deploy|publish|approve|reject|cancel|transfer|pay|book|order|submit)"
    r"([_\-.]|[A-Z]|$)"
)
RESERVED_MOUNTS = frozenset({"fetch", "leeward", "mcp", "v1"})
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SECRET_NAME = re.compile(
    r"(api[_-]?key|apikey|token|secret|passw(or)?d|authorization|credential|private[_-]?key)",
    re.IGNORECASE,
)


class ConfigError(ValueError):
    """The configuration is invalid. The message names the file, the key and the reason."""


def _duration(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError("expected a duration string such as '30s', '6h' or '0s'")
    return parse_duration(value)


def _size(value: object) -> int:
    if not isinstance(value, int | str):
        raise ValueError("expected a byte count or a size such as '200MB'")
    return parse_size(value)


def _regex(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("expected a regular expression")
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError(f"not a valid regular expression: {exc}") from exc
    return value


def _listen(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("expected host:port")
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"{value!r} is not host:port")
    return value


def _cron(value: object) -> str:
    field = r"(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?"
    if (
        not isinstance(value, str)
        or not all(re.fullmatch(f"{field}(,{field})*", part) for part in value.split())
        or len(value.split()) != 5
    ):
        raise ValueError(f"{value!r} is not a five-field cron expression")
    return value


Duration = Annotated[float, BeforeValidator(_duration)]
Size = Annotated[int, BeforeValidator(_size)]
Regex = Annotated[str, BeforeValidator(_regex)]
Listen = Annotated[str, BeforeValidator(_listen)]
Cron = Annotated[str, BeforeValidator(_cron)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class StdioServer(Strict):
    transport: Literal["stdio"]
    command: list[str] = Field(min_length=1)
    env: dict[str, str] = {}
    env_from: list[str] = []
    cwd: str | None = None
    accept_stale_argument: bool = False


class HttpServer(Strict):
    transport: Literal["http"]
    url: str
    headers_env: dict[str, str] = {}
    accept_stale_argument: bool = False


class McpSurface(Strict):
    enabled: bool = False
    listen: Listen = "127.0.0.1:8787"
    servers: dict[str, Annotated[StdioServer | HttpServer, Field(discriminator="transport")]] = {}


class GenericFetch(Strict):
    enabled: bool = False
    allow_hosts: list[str] = []


class FetchSurface(Strict):
    enabled: bool = False
    listen: Listen = "127.0.0.1:8787"
    mounts: dict[str, str] = {}
    generic_fetch: GenericFetch = GenericFetch()


class ForwardSurface(Strict):
    enabled: bool = False
    listen: Listen = "127.0.0.1:8788"


class Tier(Strict):
    name: str
    base_url: str
    model: str
    api_key_env: str | None = None


class StatusLine(Strict):
    enabled: bool = False


class LlmSurface(Strict):
    enabled: bool = False
    listen: Listen = "127.0.0.1:8787"
    tiers: list[Tier] = []
    status_line: StatusLine = StatusLine()


class Surfaces(Strict):
    mcp: McpSurface = McpSurface()
    fetch: FetchSurface = FetchSurface()
    forward: ForwardSurface = ForwardSurface()
    llm: LlmSurface = LlmSurface()


class RunBudget(Strict):
    max_retry_attempts_total: int = Field(default=20, ge=0)
    max_retry_seconds_total: float = Field(default=120.0, ge=0)
    max_endpoint_attempts: int = Field(default=4, ge=0)


class BreakerSettings(Strict):
    open_after_transient_failures: int = Field(default=3, ge=1)
    half_open_backoff_initial: Duration = 5.0
    half_open_backoff_max: Duration = 120.0
    close_after_successes: int = Field(default=2, ge=1)


class Defaults(Strict):
    volatility: Volatility = Field(default=Volatility.VOLATILE, alias="class")
    soft_deadline: Duration = 5.0
    hard_deadline: Duration = 30.0
    max_attempts: int = Field(default=2, ge=1, le=10)
    max_body_bytes: Size = 10 * 1024 * 1024
    run_budget: RunBudget = RunBudget()
    breaker: BreakerSettings = BreakerSettings()
    write_tool_pattern: Regex = DEFAULT_WRITE_TOOL_PATTERN

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.soft_deadline > self.hard_deadline:
            raise ValueError("soft_deadline must not be later than hard_deadline")
        return self


class Match(Strict):
    url: str | None = None
    host: str | None = None
    tool: str | None = None
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "*"] | None = None
    tier: str | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not any((self.url, self.host, self.tool, self.method, self.tier)):
            raise ValueError("a match needs at least one of url, host, tool, method, tier")
        return self


class ClassMapping(Strict):
    """Teaches leeward how an upstream reports a failure it would otherwise misread."""

    when_status: int | None = None
    when_body_matches: Regex | None = None
    when_error_code: str | None = None
    as_class: FailureClass
    as_disposition: Disposition | None = None
    retry_after: Duration | None = None

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        if self.when_status is None and self.when_body_matches is None and not self.when_error_code:
            raise ValueError(
                "needs at least one of when_status, when_body_matches, when_error_code"
            )
        if self.as_class in LEEWARD_CLASSES or self.as_class is FailureClass.OK:
            raise ValueError(f"{self.as_class} is produced by leeward itself and cannot be mapped")
        if self.retry_after is not None and self.as_disposition is not Disposition.WAIT:
            raise ValueError("retry_after only makes sense with as_disposition: WAIT")
        return self


class Rule(Strict):
    name: str | None = None
    match: Match
    volatility: Volatility | None = Field(default=None, alias="class")
    stale_on_error: Duration | None = None
    stale_while_revalidate: Duration | None = None
    soft_deadline: Duration | None = None
    hard_deadline: Duration | None = None
    max_attempts: int | None = Field(default=None, ge=1, le=10)
    pure: bool = False
    idempotent: bool | None = None
    vary_on: list[str] = []
    max_body_bytes: Size | None = None
    classes: list[ClassMapping] = []

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        if self.volatility in (Volatility.LIVE, Volatility.NEVER):
            for key in ("stale_on_error", "stale_while_revalidate"):
                if getattr(self, key) not in (None, 0.0):
                    raise ValueError(f"{key} must be 0s for class {self.volatility}")
        if self.volatility is Volatility.NEVER and self.pure:
            raise ValueError("a never-class endpoint cannot be pure: it is not cached at all")
        if (
            self.soft_deadline is not None
            and self.hard_deadline is not None
            and self.soft_deadline > self.hard_deadline
        ):
            raise ValueError("soft_deadline must not be later than hard_deadline")
        return self


class CorpusBase(Strict):
    name: str
    warm_on_degradation: bool = False
    max_bytes: Size | None = None
    concurrency: int = Field(default=2, ge=1, le=16)
    rps: float = Field(default=5.0, gt=0, le=100)
    schedule: Cron | None = None
    follow_links: bool = False


class UrlListCorpus(CorpusBase):
    type: Literal["url_list"]
    urls: list[str] = []
    urls_file: str | None = None

    @model_validator(mode="after")
    def _has_urls(self) -> Self:
        if not self.urls and not self.urls_file:
            raise ValueError("a url_list corpus needs urls or urls_file")
        return self


class SitemapCorpus(CorpusBase):
    type: Literal["sitemap"]
    url: str
    respect_robots: bool = True
    hosts: list[str] = []


class DirectoryCorpus(CorpusBase):
    type: Literal["directory"]
    path: str
    maps_to: str


class ZimCorpus(CorpusBase):
    type: Literal["zim"]
    kiwix_url: str
    maps_host: str


class McpResourcesCorpus(CorpusBase):
    type: Literal["mcp_resources"]
    server: str


Corpus = Annotated[
    UrlListCorpus | SitemapCorpus | DirectoryCorpus | ZimCorpus | McpResourcesCorpus,
    Field(discriminator="type"),
]


class ChaosSettings(Strict):
    enabled: bool = False


class Redaction(Strict):
    headers: list[str] = list(DEFAULT_REDACT_HEADERS)


class WarmSettings(Strict):
    user_agent: str | None = None


class ClockSettings(Strict):
    skew_threshold: Duration = 300.0


class Config(Strict):
    profile: Literal["dev", "production"] = "dev"
    data_dir: str = "./.leeward"
    surfaces: Surfaces = Surfaces()
    defaults: Defaults = Defaults()
    rules: list[Rule] = []
    classes: list[ClassMapping] = []
    corpora: list[Corpus] = []
    chaos: ChaosSettings = ChaosSettings()
    redaction: Redaction = Redaction()
    warm: WarmSettings = WarmSettings()
    clock: ClockSettings = ClockSettings()

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        if self.chaos.enabled and self.profile == "production":
            raise ValueError("chaos: fault injection cannot be enabled while profile is production")
        shared = {
            s.listen
            for s in (self.surfaces.mcp, self.surfaces.fetch, self.surfaces.llm)
            if s.enabled
        }
        if len(shared) > 1:
            raise ValueError(
                f"surfaces: mcp, fetch and llm share one listener, but name {sorted(shared)}"
            )
        if self.surfaces.forward.enabled and self.surfaces.forward.listen in shared:
            raise ValueError("surfaces.forward.listen must differ from the shared listener")
        for name, url in self.surfaces.fetch.mounts.items():
            if name in RESERVED_MOUNTS or not _NAME.match(name):
                raise ValueError(f"surfaces.fetch.mounts.{name}: reserved or invalid mount name")
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"surfaces.fetch.mounts.{name}: {url!r} is not an http(s) URL")
        for name in self.surfaces.mcp.servers:
            if not _NAME.match(name):
                raise ValueError(f"surfaces.mcp.servers.{name}: invalid server name")
        for label, names in (
            ("corpora", [c.name for c in self.corpora]),
            ("surfaces.llm.tiers", [t.name for t in self.surfaces.llm.tiers]),
        ):
            duplicate = next((n for n in names if names.count(n) > 1), None)
            if duplicate is not None:
                raise ValueError(f"{label}: duplicate name {duplicate!r}")
        return self

    def redact_headers(self) -> frozenset[str]:
        """The defaults always apply; configuration can only add to them."""
        return frozenset(DEFAULT_REDACT_HEADERS) | {h.lower() for h in self.redaction.headers}


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    config: Config
    source: Path | None

    @property
    def base_dir(self) -> Path:
        return self.source.parent if self.source is not None else Path.cwd()

    @property
    def data_dir(self) -> Path:
        path = Path(self.config.data_dir).expanduser()
        return path if path.is_absolute() else (self.base_dir / path).resolve()


def _duplicate_key(node: yaml.Node | None) -> tuple[int, str] | None:
    """The line and name of the first key repeated within one mapping, if any.

    PyYAML keeps the last of two identical keys without a word, so a second
    hard_deadline further down a rule would silently replace the first.
    """
    if isinstance(node, yaml.MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode):
                name = str(key_node.value)
                if name in seen:
                    return key_node.start_mark.line + 1, name
                seen.add(name)
            found = _duplicate_key(value_node)
            if found is not None:
                return found
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            found = _duplicate_key(item)
            if found is not None:
                return found
    return None


def _refuse_inline_secrets(raw: object, path: str = "") -> None:
    if isinstance(raw, dict):
        for key, value in cast("dict[object, object]", raw).items():
            here = f"{path}.{key}" if path else str(key)
            names_a_variable = isinstance(key, str) and key.endswith("_env")
            if (
                isinstance(key, str)
                and SECRET_NAME.search(key)
                and not names_a_variable
                and isinstance(value, str | int)
            ):
                raise ConfigError(
                    f"{here}: this looks like a secret written into configuration. Name the"
                    " environment variable that holds it instead (a key ending in _env, or"
                    " env_from for an MCP server's environment)."
                )
            if not names_a_variable:
                _refuse_inline_secrets(value, here)
    elif isinstance(raw, list):
        for index, value in enumerate(cast("list[object]", raw)):
            _refuse_inline_secrets(value, f"{path}[{index}]")


def _explain(error: ValidationError) -> str:
    lines: list[str] = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "<root>"
        lines.append(f"  {location}: {item['msg']}")
    return "\n".join(lines)


def parse_config(text: str, source: Path | None = None) -> LoadedConfig:
    label = str(source) if source is not None else "<config>"
    try:
        duplicate = _duplicate_key(yaml.compose(text, Loader=yaml.SafeLoader))  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
        raw: object = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{label}: not valid YAML: {exc}") from exc
    if duplicate is not None:
        line, key = duplicate
        raise ConfigError(f"{label}: line {line}: duplicate key {key!r}")
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{label}: the top level must be a mapping of sections")
    mapping = cast("dict[str, object]", raw)
    try:
        _refuse_inline_secrets(mapping)
    except ConfigError as exc:
        raise ConfigError(f"{label}: {exc}") from exc
    try:
        return LoadedConfig(Config.model_validate(mapping), source)
    except ValidationError as exc:
        raise ConfigError(f"{label}: configuration is invalid\n{_explain(exc)}") from exc


def load_config(path: Path | None = None) -> LoadedConfig:
    """Read the named file, or ./leeward.yaml, or fall back to built-in defaults."""
    if path is None:
        candidate = Path.cwd() / "leeward.yaml"
        if not candidate.exists():
            return LoadedConfig(Config(), None)
        path = candidate
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"{path}: no such configuration file") from exc
    return parse_config(text, path.resolve())
