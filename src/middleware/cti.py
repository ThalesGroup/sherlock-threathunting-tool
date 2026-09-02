"""Analysis of CTI reports provided by the analyst (PDF), upstream of a hunt.

The report is an external document: its text is treated as untrusted content, encapsulated
before reaching the model, which has no tool at its disposal. The model's output is never
taken at face value: attacks are capped and truncated, and each candidate IOC is
re-validated by pattern (hexadecimal hash, public IP, plausible domain) - an indicator
invented without a valid form does not exist.

No outbound flow: the PDF comes from the analyst, the analysis goes through the AI gateway
(the sanctioned path to the model), nothing leaves the internal perimeter.
"""

from __future__ import annotations

import ipaddress
import json
import re
from io import BytesIO
from typing import Any, Protocol

from middleware.errors import ErrorCode, ToolError
from middleware.untrusted import INSTRUCTION_NOTICE, wrap

MAX_PDF_BYTES = 15 * 1024 * 1024
_MAX_PAGES = 80
_MAX_TEXT_CHARS = 60_000
_MAX_ATTACKS = 10
_MAX_IOCS_PER_ATTACK = 100

_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")

_KINDS = ("campaign", "vulnerability", "malware", "actor", "other")
_APPROACHES = ("hypothesis", "campaign")

_ANALYSIS_PROMPT = f"""You are analyzing a cyber threat intelligence report provided by an analyst.

{INSTRUCTION_NOTICE}

Identify each distinct threat described in the report, and propose for each the best
hunting approach. A distinct threat = a different attack, campaign, vulnerability or actor.
The phases, modules, persistence mechanisms, ancillary tools and variants of a single
attack are NOT separate entries: they fold into the entry of that attack (their indicators
in its `iocs`, their behaviors summarized in its `summary`). A report that describes only
one campaign yields ONE single entry.

- `campaign` if the report publishes usable indicators of compromise (hashes, IPs, domains,
  URLs): the hunt will start from these indicators.
- `hypothesis` otherwise (vulnerability, technique, campaign without IOC): then write a
  concrete behavioral hypothesis that is queryable in a SIEM, in English.

Reply only with a JSON array of objects:
{{"name": "short name of the attack", "kind": "campaign|vulnerability|malware|actor|other",
"summary": "factual summary in 2-3 sentences, in English",
"approach": "hypothesis|campaign",
"suggested_hypothesis": "behavioral hypothesis (if approach=hypothesis, otherwise empty)",
"iocs": [{{"value": "...", "type": "hash|ip|domain|url|email|file_path|registry_key|other"}}]}}

Extract only indicators presented by the report as malicious: never the infrastructure of
the report's publisher, never an indicator from your own knowledge. If the document is not
a threat report, reply `[]`."""


class CompletionModel(Protocol):
    async def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> Any: ...


def extract_pdf_text(data: bytes) -> tuple[str, int, bool]:
    """Extracts the text of a PDF, capped in pages and characters.

    Returns (text, number of pages read, truncated).
    """

    if len(data) > MAX_PDF_BYTES:
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            f"PDF too large (cap {MAX_PDF_BYTES // (1024 * 1024)} MB).",
        )
    try:
        from pypdf import PdfReader

        reader = PdfReader(BytesIO(data))
        pages = reader.pages[:_MAX_PAGES]
        chunks = []
        for page in pages:
            chunks.append(page.extract_text() or "")
        text = "\n".join(chunks)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            "Unreadable PDF: the file could not be parsed.",
            hint="Check that it is a text PDF, not protected.",
        ) from exc

    truncated = len(text) > _MAX_TEXT_CHARS or len(reader.pages) > _MAX_PAGES
    return text[:_MAX_TEXT_CHARS], len(pages), truncated


async def analyze_report_text(
    text: str,
    *,
    gateway: CompletionModel,
    model: str,
    source_name: str,
) -> list[dict[str, Any]]:
    """Has the model analyze the report text and re-validates its output."""

    if not text.strip():
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            "The PDF contains no extractable text.",
            hint="A scanned (image) PDF is not usable without OCR.",
        )

    completion = await gateway.complete(
        model=model,
        messages=[
            {"role": "system", "content": _ANALYSIS_PROMPT},
            {"role": "user", "content": wrap(text, source="CTI report", reference=source_name)},
        ],
        max_tokens=8192,
    )
    return _validated_attacks(getattr(completion, "content", "") or "")


def _validated_attacks(content: str) -> list[dict[str, Any]]:
    start = content.find("[")
    end = content.rfind("]")
    if start == -1 or end <= start:
        return []
    try:
        parsed = json.loads(content[start : end + 1])
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []

    attacks: list[dict[str, Any]] = []
    for item in parsed[:_MAX_ATTACKS]:
        if not isinstance(item, dict):
            continue
        name = _clean_str(item.get("name"), 120)
        summary = _clean_str(item.get("summary"), 1200)
        if not name or not summary:
            continue
        kind = item.get("kind") if item.get("kind") in _KINDS else "other"
        iocs = _validated_iocs(item.get("iocs"))
        approach = item.get("approach") if item.get("approach") in _APPROACHES else None
        if approach is None or (approach == "campaign" and not iocs):
            approach = "campaign" if iocs else "hypothesis"
        attacks.append(
            {
                "name": name,
                "kind": kind,
                "summary": summary,
                "approach": approach,
                "suggested_hypothesis": _clean_str(item.get("suggested_hypothesis"), 2000),
                "iocs": iocs,
            }
        )
    return attacks


def _clean_str(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def _validated_iocs(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    kept: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw[:_MAX_IOCS_PER_ATTACK]:
        if not isinstance(item, dict):
            continue
        value = _refang(str(item.get("value", "")).strip())
        ioc_type = str(item.get("type", ""))
        if not value or len(value) > 2048:
            continue
        if not _matches_type(value, ioc_type):
            continue
        key = f"{ioc_type}:{value.lower()}"
        if key in seen:
            continue
        seen.add(key)
        kept.append({"value": value, "type": ioc_type})
    return kept


def _refang(value: str) -> str:
    return (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("hxxp", "http")
        .replace("HXXP", "http")
    )


def _matches_type(value: str, ioc_type: str) -> bool:
    from urllib.parse import urlsplit

    match ioc_type:
        case "hash":
            return bool(_HASH_RE.match(value))
        case "ip":
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return False
            return not (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
                or address.is_multicast
            )
        case "domain":
            return bool(_DOMAIN_RE.match(value))
        case "url":
            parts = urlsplit(value)
            return parts.scheme in ("http", "https") and bool(parts.hostname)
        case "email":
            return bool(_EMAIL_RE.match(value))
        case "file_path":
            return len(value) > 3 and ("/" in value or "\\" in value)
        case "registry_key":
            return value.upper().startswith("HK")
        case "other":
            return 3 < len(value) <= 200
    return False
