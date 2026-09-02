"""Filter for the sole outbound flow from the scope: IOC search in threat intelligence.

Two independent checks:

- destination: the queried domain must be on the allowlist;
- content: the sent string must contain only the campaign name, never an element of the
  internal context (hostname, private address, hunt id, internal path).

The content filter works by detecting internal patterns, not by an allowlist of words: it
complements the shape constraint imposed on `campaign_name`, it does not replace it.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from middleware.errors import ErrorCode, ToolError

_CAMPAIGN_NAME_RE = re.compile(r"^[\w \-.'/+&()]{2,120}$", re.UNICODE)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_HUNT_ID_RE = re.compile(r"\bhunt[_-][A-Za-z0-9]{4,}\b", re.I)
_UNC_PATH_RE = re.compile(r"\\\\[A-Za-z0-9_.$-]+\\")
_WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\")
_UPN_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def check_campaign_name(value: str, *, internal_suffixes: tuple[str, ...]) -> str:
    """Validate the only string allowed to leave the scope."""

    candidate = value.strip()
    if not _CAMPAIGN_NAME_RE.match(candidate):
        raise ToolError(
            ErrorCode.EGRESS_BLOCKED,
            "The search term must be a campaign, actor or TTP name, from 2 to 120 "
            "characters, without technical punctuation.",
            hint="Example: Volt Typhoon.",
        )

    reason = _detect_internal_context(candidate, internal_suffixes)
    if reason:
        raise ToolError(
            ErrorCode.EGRESS_BLOCKED,
            f"External search blocked: the query contains {reason}.",
            hint="Only the campaign name can leave the internal scope.",
        )
    return candidate


def _detect_internal_context(value: str, internal_suffixes: tuple[str, ...]) -> str | None:
    lowered = value.lower()

    for suffix in internal_suffixes:
        if suffix and suffix in lowered:
            return "an internal hostname"

    for match in _IPV4_RE.findall(value):
        try:
            address = ipaddress.ip_address(match)
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            return "an internal IP address"

    if _UUID_RE.search(value):
        return "a technical id"
    if _HUNT_ID_RE.search(value):
        return "a hunt id"
    if _UNC_PATH_RE.search(value) or _WINDOWS_PATH_RE.search(value):
        return "an internal file path"
    if _UPN_RE.search(value):
        return "an email address"
    return None


def check_destination(url: str, *, allowed_domains: tuple[str, ...]) -> str:
    """Check that an outbound URL targets an authorized threat intelligence source."""

    if not allowed_domains:
        raise ToolError(
            ErrorCode.EGRESS_BLOCKED,
            "No threat intelligence source is authorized on this installation.",
            hint="The allowlist is empty: the hunt must run on provided IOCs.",
        )

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ToolError(
            ErrorCode.EGRESS_BLOCKED,
            "Only the HTTPS protocol is allowed outbound.",
        )

    host = (parts.hostname or "").lower()
    if not host:
        raise ToolError(ErrorCode.EGRESS_BLOCKED, "Invalid outbound URL.")

    for domain in allowed_domains:
        if host == domain or host.endswith(f".{domain}"):
            return host

    raise ToolError(
        ErrorCode.EGRESS_BLOCKED,
        "Destination outside the threat intelligence allowlist.",
        hint="Authorized sources: " + ", ".join(allowed_domains),
    )
