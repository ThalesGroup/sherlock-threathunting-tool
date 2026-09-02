"""Threat intelligence connector: the only flow that leaves the internal scope.

What goes out: a campaign, actor or TTP name, and nothing else. What comes in: indicators
that all carry a citable source, the others being discarded by the code.

The connector knows no hunt data: it does not receive the context, so it cannot disclose
it, even on request from the model.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from itertools import zip_longest
from typing import Any

from middleware.clients.base import UpstreamClient
from middleware.errors import ErrorCode, ToolError
from middleware.guardrails.egress import check_campaign_name, check_destination
from middleware.guardrails.ioc import Ioc, IocType, filter_sourced

TIME_RANGE_DAYS = {"month": 30, "3months": 91, "9months": 274, "year": 365}
"""Freshness windows offered to the analyst, in days."""


class ThreatIntelSource(ABC):
    """An approved source. The called domain is verified on every call."""

    name: str
    domain: str

    def covered_domains(self) -> tuple[str, ...]:
        """Domains this source may cite as the origin of an IOC."""

        return (self.domain,)

    @abstractmethod
    async def search(
        self, campaign: str, *, limit: int, time_range: str | None = None
    ) -> list[Ioc]: ...


class VirusTotalSource(ThreatIntelSource):
    """Search by VirusTotal collection. Requires an approved key in the vault."""

    name = "VirusTotal"
    domain = "virustotal.com"

    def __init__(self, api_key: str, client: UpstreamClient | None = None) -> None:
        self._api_key = api_key
        self._client = client or UpstreamClient(label="Threat intel")

    async def search(
        self, campaign: str, *, limit: int, time_range: str | None = None
    ) -> list[Ioc]:
        url = "https://www.virustotal.com/api/v3/search"
        check_destination(url, allowed_domains=(self.domain,))
        payload = await self._client.request_json(
            "GET",
            url,
            headers={"x-apikey": self._api_key, "accept": "application/json"},
            params={"query": campaign, "limit": limit},
        )
        return [ioc for item in payload.get("data", []) if (ioc := _parse_vt_item(item))]


class OtxSource(ThreatIntelSource):
    """AlienVault OTX: pulses link a campaign name to its indicators.

    Two calls: search for pulses by name, then read the indicators of the most relevant
    pulses. Each IOC cites the pulse it comes from.
    """

    name = "AlienVault OTX"
    domain = "otx.alienvault.com"

    _MAX_PULSES = 5

    def __init__(self, api_key: str, client: UpstreamClient | None = None) -> None:
        self._api_key = api_key
        self._client = client or UpstreamClient(label="Threat intel")

    async def search(
        self, campaign: str, *, limit: int, time_range: str | None = None
    ) -> list[Ioc]:
        base = f"https://{self.domain}/api/v1"
        check_destination(base, allowed_domains=(self.domain,))
        headers = {"X-OTX-API-KEY": self._api_key, "accept": "application/json"}

        pulses = await self._client.request_json(
            "GET",
            f"{base}/search/pulses",
            headers=headers,
            params={"q": campaign, "limit": self._MAX_PULSES},
        )

        collected: list[Ioc] = []
        for pulse in pulses.get("results", []):
            pulse_id = pulse.get("id")
            if not pulse_id or len(collected) >= limit:
                break
            indicators = await self._client.request_json(
                "GET",
                f"{base}/pulses/{pulse_id}/indicators",
                headers=headers,
            )
            for item in indicators.get("results", []):
                ioc = _parse_otx_indicator(item, pulse_id=str(pulse_id))
                if ioc:
                    collected.append(ioc)
        return collected[:limit]


class ThreatFoxSource(ThreatIntelSource):
    """abuse.ch ThreatFox: recent operational IOCs, indexed by malware and by tag."""

    name = "ThreatFox"
    domain = "threatfox.abuse.ch"

    def __init__(self, auth_key: str, client: UpstreamClient | None = None) -> None:
        self._auth_key = auth_key
        self._client = client or UpstreamClient(label="Threat intel")

    async def search(
        self, campaign: str, *, limit: int, time_range: str | None = None
    ) -> list[Ioc]:
        url = f"https://{self.domain}/api/v1/"
        check_destination(url, allowed_domains=(self.domain,))
        headers = {"Auth-Key": self._auth_key, "accept": "application/json"}

        collected: list[Ioc] = []
        seen: set[str] = set()
        for query in _threatfox_queries(campaign):
            payload = await self._client.request_json("POST", url, headers=headers, json_body=query)
            if payload.get("query_status") != "ok":
                continue
            data = payload.get("data")
            if not isinstance(data, list):
                continue
            for item in data:
                ioc = _parse_threatfox_item(item)
                if ioc and ioc.value not in seen:
                    seen.add(ioc.value)
                    collected.append(ioc)
            if len(collected) >= limit:
                break
        return collected[:limit]


class MispFeedSource(ThreatIntelSource):
    """CIRCL public MISP OSINT feed: threat intelligence events as static JSON.

    The only key-less source: the feed is freely accessible for reading. The search runs
    on the titles of the manifest's events; the attributes of the retained events become
    IOCs citing the document they come from.
    """

    name = "CIRCL OSINT (MISP)"
    domain = "www.circl.lu"

    _FEED_BASE = "https://www.circl.lu/doc/misp/feed-osint"
    _MAX_EVENTS = 4
    _MANIFEST_TTL_SECONDS = 3600.0

    def __init__(self, client: UpstreamClient | None = None) -> None:
        self._client = client or UpstreamClient(label="Threat intel")
        self._manifest: dict[str, Any] | None = None
        self._manifest_at = 0.0

    def covered_domains(self) -> tuple[str, ...]:
        return (self.domain, "circl.lu")

    async def search(
        self, campaign: str, *, limit: int, time_range: str | None = None
    ) -> list[Ioc]:
        manifest = await self._get_manifest()
        collected: list[Ioc] = []
        for uuid, entry in _match_misp_events(manifest, campaign)[: self._MAX_EVENTS]:
            url = f"{self._FEED_BASE}/{uuid}.json"
            check_destination(url, allowed_domains=(self.domain,))
            payload = await self._client.request_json("GET", url)
            event = payload.get("Event")
            if isinstance(event, dict):
                collected.extend(
                    _parse_misp_event(event, source_url=url, event_date=entry.get("date"))
                )
            if len(collected) >= limit:
                break
        return collected[:limit]

    async def _get_manifest(self) -> dict[str, Any]:
        now = time.monotonic()
        expired = now - self._manifest_at > self._MANIFEST_TTL_SECONDS
        if self._manifest is None or expired:
            url = f"{self._FEED_BASE}/manifest.json"
            check_destination(url, allowed_domains=(self.domain,))
            self._manifest = await self._client.request_json("GET", url)
            self._manifest_at = now
        return self._manifest


def _interleave(per_source: list[list[Ioc]]) -> list[Ioc]:
    """Interleaves results source by source (one from each in turn) so that no source is
    starved by the cap. A single indicator seen in several sources is kept only once, but
    retains the trace of the sources that corroborate it."""

    collected: list[Ioc] = []
    seen: dict[str, Ioc] = {}
    for tier in zip_longest(*per_source):
        for ioc in tier:
            if ioc is None:
                continue
            key = ioc.normalized()
            primary = seen.get(key)
            if primary is not None:
                if (
                    ioc.source_name != primary.source_name
                    and ioc.source_name not in primary.corroborating_sources
                ):
                    primary.corroborating_sources.append(ioc.source_name)
                continue
            seen[key] = ioc
            collected.append(ioc)
    return collected


class ThreatIntelConnector:
    """Facade used by the TI tool. Applies the anti-leak filter before any call."""

    def __init__(
        self,
        sources: list[ThreatIntelSource],
        *,
        allowed_domains: tuple[str, ...],
        internal_suffixes: tuple[str, ...],
        open_sources: bool = False,
    ) -> None:
        self._sources = [
            source
            for source in sources
            if any(domain in allowed_domains for domain in source.covered_domains())
        ]
        self._allowed_domains = allowed_domains
        self._internal_suffixes = internal_suffixes
        self._open_sources = open_sources
        """Open search (`SHL_TI_OPEN_SEARCH`): any HTTPS page counts as a source. The
        requirement of a source per IOC remains; only the scope of domains opens up."""

    @property
    def enabled(self) -> bool:
        return bool(self._sources)

    async def search(
        self,
        campaign_name: str,
        *,
        ioc_types: tuple[IocType, ...] | None = None,
        max_results: int,
        time_range: str | None = None,
    ) -> tuple[list[Ioc], list[dict[str, str]]]:
        campaign = check_campaign_name(campaign_name, internal_suffixes=self._internal_suffixes)
        if time_range is not None and time_range not in TIME_RANGE_DAYS:
            raise ToolError(
                ErrorCode.SCHEMA_INVALID,
                "Unknown freshness: " + ", ".join(TIME_RANGE_DAYS) + ".",
            )

        if not self.enabled:
            raise ToolError(
                ErrorCode.EGRESS_BLOCKED,
                "No threat intelligence source is enabled on this installation.",
                hint="Proceed with the indicators provided by the analyst.",
            )

        per_source: list[list[Ioc]] = []
        dropped: list[dict[str, str]] = []
        for source in self._sources:
            try:
                per_source.append(
                    await source.search(campaign, limit=max_results, time_range=time_range)
                )
            except ToolError as error:
                dropped.append(
                    {"value": source.name, "reason": f"source unavailable ({error.code.value})"}
                )

        collected = _interleave(per_source)
        kept, unsourced = filter_sourced(
            collected,
            allowed_domains=self._allowed_domains,
            allow_any_https=self._open_sources,
        )
        dropped.extend(unsourced)
        if time_range:
            kept, stale = _split_stale(kept, time_range)
            dropped.extend(stale)
        if ioc_types:
            wanted = set(ioc_types)
            kept = [ioc for ioc in kept if ioc.type in wanted]
        return kept[:max_results], dropped


def _split_stale(iocs: list[Ioc], time_range: str) -> tuple[list[Ioc], list[dict[str, str]]]:
    """Discards IOCs whose first observation predates the requested window.

    An IOC with no known date is kept: indicators extracted from web reports have no
    `first_seen` of their own, but the window is already applied to the pages' publication
    date by the search engine.
    """

    from datetime import UTC, datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(days=TIME_RANGE_DAYS[time_range])
    kept: list[Ioc] = []
    stale: list[dict[str, str]] = []
    for ioc in iocs:
        seen_at = _parse_first_seen(ioc.first_seen)
        if seen_at is not None and seen_at < cutoff:
            stale.append({"value": ioc.value, "reason": "outside freshness window"})
        else:
            kept.append(ioc)
    return kept, stale


def _parse_first_seen(value: str | None) -> Any:
    if not value:
        return None
    from datetime import UTC, datetime

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


_VT_TYPE_MAP: dict[str, IocType] = {
    "file": IocType.HASH,
    "domain": IocType.DOMAIN,
    "ip_address": IocType.IP,
    "url": IocType.URL,
}


def _parse_vt_item(item: dict[str, Any]) -> Ioc | None:
    raw_type = item.get("type")
    ioc_type = _VT_TYPE_MAP.get(str(raw_type))
    if ioc_type is None:
        return None

    identifier = item.get("id")
    attributes = item.get("attributes") or {}
    value = attributes.get("url") if ioc_type is IocType.URL else identifier
    if not value:
        return None

    return Ioc(
        value=str(value),
        type=ioc_type,
        source_name="VirusTotal",
        source_url=f"https://www.virustotal.com/gui/{raw_type}/{identifier}",
        first_seen=_iso_or_none(attributes.get("first_submission_date")),
        confidence=_vt_confidence(attributes),
    )


def _iso_or_none(value: Any) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    from datetime import UTC, datetime

    return datetime.fromtimestamp(value, UTC).isoformat()


def _vt_confidence(attributes: dict[str, Any]) -> str | None:
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    malicious = int(stats.get("malicious", 0))
    if malicious >= 10:
        return "high"
    if malicious >= 3:
        return "medium"
    return "low"


_OTX_TYPE_MAP: dict[str, IocType] = {
    "IPv4": IocType.IP,
    "IPv6": IocType.IP,
    "domain": IocType.DOMAIN,
    "hostname": IocType.DOMAIN,
    "URL": IocType.URL,
    "URI": IocType.URL,
    "FileHash-MD5": IocType.HASH,
    "FileHash-SHA1": IocType.HASH,
    "FileHash-SHA256": IocType.HASH,
    "email": IocType.EMAIL,
    "FilePath": IocType.FILE_PATH,
}


def _parse_otx_indicator(item: dict[str, Any], *, pulse_id: str) -> Ioc | None:
    ioc_type = _OTX_TYPE_MAP.get(str(item.get("type")))
    value = item.get("indicator")
    if ioc_type is None or not value:
        return None
    return Ioc(
        value=str(value),
        type=ioc_type,
        source_name="AlienVault OTX",
        source_url=f"https://otx.alienvault.com/pulse/{pulse_id}",
        first_seen=item.get("created") or None,
        confidence=None,
    )


def _threatfox_queries(campaign: str) -> list[dict[str, Any]]:
    """ThreatFox indexes by tag and by malware name; tags have no spaces."""

    compact = campaign.replace(" ", "")
    queries: list[dict[str, Any]] = [{"query": "taginfo", "tag": campaign, "limit": 200}]
    if compact != campaign:
        queries.append({"query": "taginfo", "tag": compact, "limit": 200})
    queries.append({"query": "malwareinfo", "malware": campaign, "limit": 200})
    return queries


_THREATFOX_TYPE_MAP: dict[str, IocType] = {
    "ip:port": IocType.IP,
    "domain": IocType.DOMAIN,
    "url": IocType.URL,
    "md5_hash": IocType.HASH,
    "sha1_hash": IocType.HASH,
    "sha256_hash": IocType.HASH,
    "envelope_from": IocType.EMAIL,
}


def _parse_threatfox_item(item: dict[str, Any]) -> Ioc | None:
    ioc_type = _THREATFOX_TYPE_MAP.get(str(item.get("ioc_type")))
    value = item.get("ioc")
    identifier = item.get("id")
    if ioc_type is None or not value or not identifier:
        return None

    text = str(value)
    if ioc_type is IocType.IP and ":" in text:
        text = text.rsplit(":", 1)[0]

    return Ioc(
        value=text,
        type=ioc_type,
        source_name="ThreatFox",
        source_url=f"https://threatfox.abuse.ch/ioc/{identifier}/",
        first_seen=item.get("first_seen") or None,
        confidence=_threatfox_confidence(item),
    )


def _threatfox_confidence(item: dict[str, Any]) -> str | None:
    level = item.get("confidence_level")
    if not isinstance(level, (int, float)):
        return None
    if level >= 75:
        return "high"
    if level >= 50:
        return "medium"
    return "low"


_MISP_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")

_MISP_TYPE_MAP: dict[str, IocType] = {
    "md5": IocType.HASH,
    "sha1": IocType.HASH,
    "sha256": IocType.HASH,
    "ip-src": IocType.IP,
    "ip-dst": IocType.IP,
    "domain": IocType.DOMAIN,
    "hostname": IocType.DOMAIN,
    "url": IocType.URL,
    "email": IocType.EMAIL,
    "email-src": IocType.EMAIL,
    "email-dst": IocType.EMAIL,
    "filename": IocType.FILE_PATH,
    "regkey": IocType.REGISTRY_KEY,
}


def _match_misp_events(manifest: dict[str, Any], campaign: str) -> list[tuple[str, dict[str, Any]]]:
    """Events whose title contains all the words of the campaign, from most recent to
    oldest. An identifier that is not a UUID is ignored: nothing extracted from the manifest
    builds a URL path without validation."""

    tokens = [token for token in campaign.lower().split() if token]
    if not tokens:
        return []
    matches: list[tuple[str, dict[str, Any]]] = []
    for uuid, entry in manifest.items():
        if not isinstance(entry, dict) or not _MISP_UUID_RE.match(str(uuid)):
            continue
        info = str(entry.get("info") or "").lower()
        if all(token in info for token in tokens):
            matches.append((str(uuid), entry))
    matches.sort(key=lambda item: str(item[1].get("date") or ""), reverse=True)
    return matches


def _parse_misp_event(event: dict[str, Any], *, source_url: str, event_date: Any) -> list[Ioc]:
    attributes = list(event.get("Attribute") or [])
    for misp_object in event.get("Object") or []:
        if isinstance(misp_object, dict):
            attributes.extend(misp_object.get("Attribute") or [])

    iocs: list[Ioc] = []
    seen: set[str] = set()
    for attribute in attributes:
        ioc = _parse_misp_attribute(attribute, source_url=source_url, event_date=event_date)
        if ioc and ioc.value not in seen:
            seen.add(ioc.value)
            iocs.append(ioc)
    return iocs


def _parse_misp_attribute(attribute: Any, *, source_url: str, event_date: Any) -> Ioc | None:
    if not isinstance(attribute, dict):
        return None
    raw_type = str(attribute.get("type") or "")
    raw_value = attribute.get("value")
    if not raw_value:
        return None

    resolved = _resolve_misp_type(raw_type, str(raw_value))
    if resolved is None:
        return None
    ioc_type, value = resolved

    return Ioc(
        value=value,
        type=ioc_type,
        source_name="CIRCL OSINT (MISP)",
        source_url=source_url,
        first_seen=_misp_first_seen(attribute, event_date),
        confidence="medium" if attribute.get("to_ids") else "low",
    )


def _resolve_misp_type(raw_type: str, value: str) -> tuple[IocType, str] | None:
    """Resolves a MISP type, composites included (`filename|sha256`, `ip-dst|port`,
    `domain|ip`). On a composite, the hash part is preferred, otherwise the first known
    part."""

    if "|" not in raw_type:
        ioc_type = _MISP_TYPE_MAP.get(raw_type)
        return (ioc_type, value) if ioc_type else None

    pairs = list(zip(raw_type.split("|"), value.split("|"), strict=False))
    known = [
        (mapped, part.strip())
        for part_type, part in pairs
        if (mapped := _MISP_TYPE_MAP.get(part_type)) and part.strip()
    ]
    if not known:
        return None
    for mapped, part in known:
        if mapped is IocType.HASH:
            return mapped, part
    return known[0]


def _misp_first_seen(attribute: dict[str, Any], event_date: Any) -> str | None:
    timestamp = attribute.get("timestamp")
    try:
        return _iso_or_none(int(timestamp))
    except (TypeError, ValueError):
        pass
    return str(event_date) if event_date else None
