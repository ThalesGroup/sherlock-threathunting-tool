"""Anti-hallucination guardrail: no IOC from the model's memory.

Two complementary locks:

1. At the scope entry, an IOC without a usable source is discarded by the code, not
   reported to the model. It never reaches the validation screen.
2. At the exit, before any SIEM call, the indicators present in the query's literals are
   compared to the set validated by the analyst. An unknown indicator fails the call.

The second lock only covers attributable indicators (hashes, public addresses, domains,
URLs). Binary names, paths and registry keys are excluded: behavioral hunting relies on
them, and they do not designate an attacker.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

from middleware.errors import ErrorCode, ToolError


class IocType(StrEnum):
    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    OTHER = "other"


class IocStatus(StrEnum):
    PENDING_VALIDATION = "pending_validation"
    VALIDATED = "validated"
    REJECTED = "rejected"


ATTRIBUTABLE_TYPES = frozenset({IocType.HASH, IocType.IP, IocType.DOMAIN, IocType.URL})

_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]{3,}", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)

_FILE_EXTENSIONS = frozenset(
    """exe dll ps1 psm1 bat cmd scr vbs vbe js jse wsf wsh msi msc cpl ocx drv sys pif hta jar
    lnk py sh so bin conf ini cfg csv db dat log tmp txt xml json yaml yml zip rar 7z tar gz
    docx docm xlsx xlsm pptx pdf png jpg jpeg gif iso img cab reg pem key crt""".split()
)


def _looks_like_filename(candidate: str) -> str | None:
    """Distinguish `wmic.exe` from a domain. A binary name is not an attributable indicator."""

    labels = candidate.lower().split(".")
    if len(labels) == 2 and labels[-1] in _FILE_EXTENSIONS:
        return candidate
    return None


def _repair_defanged(text: str) -> str:
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("hxxp", "http")
        .replace("HXXP", "http")
    )


class Ioc(BaseModel):
    """Indicator carried by its source. An IOC without a source does not exist in the platform."""

    value: str
    type: IocType
    source_name: str
    source_url: str
    first_seen: str | None = None
    confidence: str | None = None
    corroborating_sources: list[str] = Field(default_factory=list)
    """Other sources that reported the same indicator. Multi-source corroboration is a
    confidence signal: the same IOC seen in two independent feeds weighs more."""
    status: IocStatus = IocStatus.PENDING_VALIDATION
    validated_by: str | None = None
    validated_at: str | None = None

    @field_validator("value")
    @classmethod
    def _strip(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("empty IOC value")
        return cleaned

    def normalized(self) -> str:
        return normalize_indicator(self.value, self.type)


class ManualIoc(BaseModel):
    """IOC provided directly by the analyst. Its source is the analyst themselves."""

    value: str
    type: IocType
    provided_by: str
    note: str | None = None
    status: IocStatus = IocStatus.VALIDATED
    validated_at: str | None = Field(default=None)

    def to_ioc(self) -> Ioc:
        return Ioc(
            value=self.value,
            type=self.type,
            source_name=f"analyst:{self.provided_by}",
            source_url=f"internal://analyst/{self.provided_by}",
            confidence="analyst",
            status=self.status,
            validated_by=self.provided_by,
            validated_at=self.validated_at,
        )


_HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def hash_algorithm(value: str) -> str | None:
    """Algorithm of a hexadecimal hash, inferred from its length. None if the value is
    not a recognizable hash."""

    cleaned = value.strip().lower()
    if not cleaned or any(char not in "0123456789abcdef" for char in cleaned):
        return None
    return _HASH_ALGORITHMS.get(len(cleaned))


def normalize_indicator(value: str, ioc_type: IocType | None = None) -> str:
    cleaned = value.strip().strip("\"'")
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
    if ioc_type in (IocType.FILE_PATH, IocType.REGISTRY_KEY):
        return cleaned.lower()
    return cleaned.lower().rstrip(".")


def has_usable_source(
    ioc: Ioc, *, allowed_domains: tuple[str, ...], allow_any_https: bool = False
) -> bool:
    """A usable source is an HTTPS URL on an approved source, or the analyst.

    In open search (`SHL_TI_OPEN_SEARCH`), any HTTPS page counts as a source: the domain
    constraint is relaxed, never the requirement of a source. An IOC without a URL of
    provenance stays nonexistent.
    """

    if ioc.source_url.startswith("internal://analyst/"):
        return True
    parts = urlsplit(ioc.source_url)
    if parts.scheme != "https" or not parts.hostname:
        return False
    if allow_any_https:
        return True
    host = parts.hostname.lower()
    return any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains)


def filter_sourced(
    iocs: list[Ioc],
    *,
    allowed_domains: tuple[str, ...],
    allow_any_https: bool = False,
) -> tuple[list[Ioc], list[dict[str, str]]]:
    """Separate sourced IOCs from the rest. The latter do not reach the analyst."""

    kept: list[Ioc] = []
    dropped: list[dict[str, str]] = []
    for ioc in iocs:
        if has_usable_source(ioc, allowed_domains=allowed_domains, allow_any_https=allow_any_https):
            kept.append(ioc)
        else:
            dropped.append({"value": ioc.value, "reason": "source missing or not approved"})
    return kept, dropped


def string_literals(query: str) -> list[str]:
    """Extract the string literals from a query."""

    literals: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(query):
        char = query[i]
        if quote is None:
            if char in "\"'":
                quote = char
                current = []
            i += 1
            continue
        if char == "\\" and i + 1 < len(query):
            current.append(query[i + 1])
            i += 2
            continue
        if char == quote:
            literals.append("".join(current))
            quote = None
            i += 1
            continue
        current.append(char)
        i += 1
    return literals


def extract_attributable_indicators(query: str) -> set[str]:
    """Attributable indicators present in a query's literals.

    Only the literals are inspected: the bare identifiers of a query (table names, UDM
    field paths such as `principal.hostname`) are not indicators.
    """

    found: set[str] = set()
    for raw_literal in string_literals(query):
        literal = _repair_defanged(raw_literal)
        for url in _URL_RE.findall(literal):
            found.add(normalize_indicator(url, IocType.URL))
        for digest in _HASH_RE.findall(literal):
            found.add(normalize_indicator(digest, IocType.HASH))
        for raw_ip in _IPV4_RE.findall(literal):
            try:
                address = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue
            if not (address.is_private or address.is_loopback or address.is_link_local):
                found.add(str(address))
        remainder = _URL_RE.sub(" ", literal)
        for domain in _DOMAIN_RE.findall(remainder):
            if _IPV4_RE.fullmatch(domain) or _looks_like_filename(domain):
                continue
            found.add(normalize_indicator(domain, IocType.DOMAIN))
    return found


def validated_indicator_set(iocs: list[Ioc]) -> set[str]:
    values: set[str] = set()
    for ioc in iocs:
        if ioc.status is not IocStatus.VALIDATED:
            continue
        normalized = ioc.normalized()
        values.add(normalized)
        if ioc.type is IocType.URL:
            host = urlsplit(normalized).hostname
            if host:
                values.add(host)
    return values


def assert_query_indicators_validated(query: str, validated: list[Ioc]) -> None:
    """Reject a query that carries an indicator not validated by the analyst."""

    allowed = validated_indicator_set(validated)
    present = extract_attributable_indicators(query)
    unknown = sorted(indicator for indicator in present if indicator not in allowed)
    if not unknown:
        return

    shown = ", ".join(unknown[:5])
    raise ToolError(
        ErrorCode.IOC_UNSOURCED,
        f"The query contains {len(unknown)} unvalidated indicator(s): {shown}.",
        hint=(
            "An indicator must come from a cited source and have been validated by the "
            "analyst before reaching a SIEM. Reformulate the query on the validated "
            "indicators or on behaviors."
        ),
    )


def assert_checkpoint_passed(iocs: list[Ioc], *, hunt_id: str) -> None:
    pending = [ioc for ioc in iocs if ioc.status is IocStatus.PENDING_VALIDATION]
    if pending:
        raise ToolError(
            ErrorCode.IOC_NOT_VALIDATED,
            f"{len(pending)} indicator(s) pending analyst validation.",
            hint="No SIEM query is possible before passing the human checkpoint.",
        )
    _ = hunt_id


def summarize_for_model(iocs: list[Ioc]) -> list[dict[str, Any]]:
    """View sent to the model: the source is always present."""

    return [
        {
            "value": ioc.value,
            "type": ioc.type.value,
            "source": ioc.source_name,
            "source_url": ioc.source_url,
            "corroborating_sources": ioc.corroborating_sources,
            "first_seen": ioc.first_seen,
            "confidence": ioc.confidence,
            "status": ioc.status.value,
        }
        for ioc in iocs
    ]
