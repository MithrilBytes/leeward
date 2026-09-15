# SPDX-License-Identifier: Apache-2.0
"""The words leeward uses to describe a call, shared by every module.

Each enum here appears verbatim in events, outcomes and notes, so a value is part
of the public contract: renaming one breaks every consumer of the event log.
"""

from __future__ import annotations

from enum import StrEnum


class FailureClass(StrEnum):
    """Why an attempt did not succeed. Every attempt ends in exactly one of these."""

    OK = "OK"
    DNS_NXDOMAIN = "DNS_NXDOMAIN"
    DNS_FAILURE = "DNS_FAILURE"
    CONNECT_REFUSED = "CONNECT_REFUSED"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    TLS_CLOCK_SKEW = "TLS_CLOCK_SKEW"
    TLS_OTHER = "TLS_OTHER"
    READ_TIMEOUT = "READ_TIMEOUT"
    WEDGED = "WEDGED"
    AUTH_FAILURE = "AUTH_FAILURE"
    NOT_FOUND = "NOT_FOUND"
    INVALID_REQUEST = "INVALID_REQUEST"
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    SERVER_ERROR = "SERVER_ERROR"
    TOOL_GONE = "TOOL_GONE"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    CONTENT_TOO_LARGE = "CONTENT_TOO_LARGE"
    BREAKER_OPEN = "BREAKER_OPEN"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


CONNECTION_CLASSES = frozenset(
    {
        FailureClass.DNS_NXDOMAIN,
        FailureClass.DNS_FAILURE,
        FailureClass.CONNECT_REFUSED,
        FailureClass.CONNECT_TIMEOUT,
    }
)
"""Failures that happen before a connection exists, so they say something about the
host and the path to it rather than about any one endpoint on that host."""

LEEWARD_CLASSES = frozenset({FailureClass.BREAKER_OPEN, FailureClass.BUDGET_EXHAUSTED})
"""Classes leeward produces itself. No origin response can be mapped onto them."""


class Disposition(StrEnum):
    """Whether retrying can ever succeed."""

    TRANSIENT = "TRANSIENT"
    WAIT = "WAIT"
    NEVER = "NEVER"
    UNKNOWN = "UNKNOWN"


class FailureScope(StrEnum):
    """Who a failure is about, which decides where leeward remembers it.

    A refused connection is about the host. A tool that vanished is about the
    endpoint. A rejected token is about the caller, so it must not stop a different
    run that holds a different token. A 404 is about one request, so it must not
    stop requests for other resources behind the same endpoint.
    """

    HOST = "host"
    ENDPOINT = "endpoint"
    RUN = "run"
    REQUEST = "request"


class Volatility(StrEnum):
    """How fast an endpoint's content changes, and so how old a copy may be served."""

    STATIC = "static"
    SLOW = "slow"
    VOLATILE = "volatile"
    LIVE = "live"
    NEVER = "never"


STALE_SERVABLE = frozenset({Volatility.STATIC, Volatility.SLOW, Volatility.VOLATILE})
"""The only classes that may ever be served past their freshness lifetime."""


class Outcome(StrEnum):
    FRESH = "FRESH"
    STALE = "STALE"
    DOWN = "DOWN"


class Advice(StrEnum):
    PROCEED = "PROCEED"
    PROCEED_WITH_CAUTION = "PROCEED_WITH_CAUTION"
    RETRY_AFTER = "RETRY_AFTER"
    DO_NOT_RETRY = "DO_NOT_RETRY"
    TREAT_AS_UNKNOWN = "TREAT_AS_UNKNOWN"


class BreakerState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class WithheldReason(StrEnum):
    """Why a stored copy existed but was not served."""

    VOLATILITY_LIVE = "VOLATILITY_LIVE"
    VOLATILITY_NEVER = "VOLATILITY_NEVER"
    BEYOND_STALE_ALLOWANCE = "BEYOND_STALE_ALLOWANCE"
    VARY_MISMATCH = "VARY_MISMATCH"


class RunResolution(StrEnum):
    """How a run's identity was determined, strongest first."""

    HEADER = "header"
    MCP_META = "mcp_meta"
    MCP_SESSION = "mcp_session"
    LLM_CONVERSATION_HASH = "llm_conversation_hash"
    CONNECTION = "connection"
    CLI = "cli"
    INTERNAL = "internal"


class Surface(StrEnum):
    MCP = "mcp"
    FETCH = "fetch"
    FORWARD = "forward"
    LLM = "llm"
    CLI = "cli"


class ClockTrust(StrEnum):
    """Whether this machine's clock can be believed when a certificate looks out of date."""

    TRUSTED = "TRUSTED"
    UNCHECKED = "UNCHECKED"
    SKEWED = "SKEWED"
