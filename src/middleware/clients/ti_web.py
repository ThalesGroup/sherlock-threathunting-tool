"""The "Publisher reports" threat intelligence source: web search over an allowlist.

Reproduces the pattern "I name a campaign, published IOCs are reported to me" without
opening the entire web: the search is restricted to approved publishers (CISA, CERT-FR,
security vendors), each page is fetched over an allowlist, and the IOCs are extracted from
it by the model then re-validated by the code.

Three locks specific to this source:

- the page read is untrusted content: it is encapsulated in the `untrusted_data`
  delimiters before reaching the model, which has no tool at its disposal;
- the model's output is never taken at face value: each candidate is re-validated by
  pattern according to its type (hex hash, public IP, plausible domain), the rest is
  discarded;
- each retained IOC carries the URL of the report it comes from. An IOC that the model
  would "know" without a source page cannot exist here.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from typing import Any, Protocol
from urllib.parse import urlsplit

from middleware.clients.base import UpstreamClient
from middleware.clients.ti import TIME_RANGE_DAYS, ThreatIntelSource
from middleware.errors import ToolError
from middleware.guardrails.egress import check_destination
from middleware.guardrails.ioc import Ioc, IocType
from middleware.untrusted import INSTRUCTION_NOTICE, wrap

logger = logging.getLogger("shl.ti_web")

_SEARCH_DOMAIN = "googleapis.com"
_SEARCH_URL = "https://www.googleapis.com/customsearch/v1"

_BRAVE_DOMAIN = "api.search.brave.com"
_BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"

_TAVILY_DOMAIN = "api.tavily.com"
_TAVILY_URL = "https://api.tavily.com/search"

_PROVIDER_DOMAINS = {
    "google": _SEARCH_DOMAIN,
    "brave": _BRAVE_DOMAIN,
    "tavily": _TAVILY_DOMAIN,
}

_SOCIAL_DOMAINS = (
    "facebook.com",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "reddit.com",
    "t.me",
    "youtube.com",
    "instagram.com",
)
"""Social networks and aggregators: never usable IOCs, always a wasted reading slot.
Excluded from page selection, in open mode as in closed mode."""

_MAX_PAGES = 6
"""Number of report pages read per search. The engine's ranking fluctuates from one call
to the next: reading too few pages misses the right report depending on the draw, reading
too many multiplies the model's extractions. Six is the compromise chosen."""

_MAX_PAGE_CHARS = 30_000

_PAGE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
}
"""Public reports sit behind anti-bot protections that respond 403 to bare HTTP clients.
A page that refuses anyway (403, redirect) is simply ignored: it does not make the source
fail."""

_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")

_EXTRACTION_PROMPT = f"""You extract indicators of compromise from a public report.

{INSTRUCTION_NOTICE}

Respond only with a JSON array of {{"value", "type"}} objects, where `type` is `hash`,
`ip`, `domain`, `url`, `email`, `file_path` or `registry_key`. Extract only indicators
presented by the report as malicious or linked to the campaign: never the publisher's
infrastructure, never an indicator from your own knowledge. If the report contains none,
respond `[]`."""


class CompletionModel(Protocol):
    """The sanctioned path to the model (AI gateway client), without depending on it."""

    async def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> Any: ...


class WebReportSource(ThreatIntelSource):
    """Searches for reports published by approved publishers and extracts the IOCs from them."""

    name = "Publisher reports"
    domain = _SEARCH_DOMAIN

    def __init__(
        self,
        *,
        search_api_key: str,
        search_engine_id: str,
        publisher_domains: tuple[str, ...],
        gateway: CompletionModel,
        model: str,
        client: UpstreamClient | None = None,
        max_pages: int = _MAX_PAGES,
        open_search: bool = False,
        search_provider: str = "google",
    ) -> None:
        if search_provider not in _PROVIDER_DOMAINS:
            raise ValueError(f"Unknown search provider: {search_provider}")
        self._search_provider = search_provider
        """`google` = Custom Search JSON API (key + cx, engine restricted to sites since
        2026). `brave` = Brave Search API (key only, full index, paid). `tavily` = Tavily
        Search API (key only, full index, free tier)."""
        self.domain = _PROVIDER_DOMAINS[search_provider]
        self._search_api_key = search_api_key
        self._search_engine_id = search_engine_id
        self._publisher_domains = tuple(domain.lower() for domain in publisher_domains)
        self._gateway = gateway
        self._model = model
        self._client = client or UpstreamClient(label="Threat intel")
        self._max_pages = max_pages
        self._open_search = open_search
        """Open search mode (`SHL_TI_OPEN_SEARCH`): any HTTPS page found by the engine is
        readable, not only the approved publishers. A deliberate relaxation of the egress
        allowlist, confined to the upstream phase: only the campaign name goes out, and each
        extracted IOC keeps its source page then passes analyst validation."""

    def covered_domains(self) -> tuple[str, ...]:
        if self._open_search and not self._publisher_domains:
            return (self.domain,)
        return self._publisher_domains

    async def search(
        self, campaign: str, *, limit: int, time_range: str | None = None
    ) -> list[Ioc]:
        pages = await self._find_report_pages(campaign, time_range=time_range)
        logger.info("Web search '%s': %d page(s) retained", campaign, len(pages))

        collected: list[Ioc] = []
        seen: dict[str, Ioc] = {}
        for url, prefetched in pages:
            try:
                extracted = await self._extract_from_page(
                    url, prefetched=prefetched, campaign=campaign
                )
            except ToolError as exc:
                logger.warning("Page skipped (%s): %s - %s", url, exc.code.value, exc.message)
                continue
            for ioc in extracted:
                key = f"{ioc.type.value}:{ioc.value.lower()}"
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
            if len(collected) >= limit:
                break
        return collected[:limit]

    async def _find_report_pages(
        self, campaign: str, *, time_range: str | None = None
    ) -> list[tuple[str, str | None]]:
        """Searches for reports, then keeps only the allowed pages.

        The filter is applied code-side on each result: the search engine's configuration
        is not a guardrail, the allowlist is. Each entry carries the content already
        extracted by the engine when it provides it (Tavily): pages behind an anti-bot
        protection thus remain readable without direct access.
        """

        query = f"{campaign} indicators of compromise"
        if self._search_provider == "tavily":
            check_destination(_TAVILY_URL, allowed_domains=(_TAVILY_DOMAIN,))
            body: dict[str, Any] = {
                "query": query,
                "max_results": 10,
                "include_raw_content": True,
            }
            if time_range:
                body["start_date"] = _window_start(time_range).strftime("%Y-%m-%d")

            entries: list[tuple[Any, Any]] = []
            if self._open_search and self._publisher_domains:
                # The engine's ranking varies from one call to the next: a first search
                # restricted to approved publishers guarantees their reports are found and
                # read first, whatever the draw of the open search that follows. The query
                # is condensed (article titles pasted as-is degrade relevance): only words
                # from the campaign name, nothing new leaves the scope.
                condensed = " ".join(campaign.split()[:6])
                trusted = await self._client.request_json(
                    "POST",
                    _TAVILY_URL,
                    headers={"Authorization": f"Bearer {self._search_api_key}"},
                    json_body=body
                    | {
                        "query": condensed,
                        "max_results": 15,
                        "include_domains": list(self._publisher_domains),
                    },
                )
                entries.extend(
                    (item.get("url"), item.get("raw_content"), item.get("title"))
                    for item in trusted.get("results", []) or []
                )
            payload = await self._client.request_json(
                "POST",
                _TAVILY_URL,
                headers={"Authorization": f"Bearer {self._search_api_key}"},
                json_body=body,
            )
            entries.extend(
                (item.get("url"), item.get("raw_content"), item.get("title"))
                for item in payload.get("results", []) or []
            )
            return self._filter_pages(entries, campaign=campaign)
        if self._search_provider == "brave":
            check_destination(_BRAVE_URL, allowed_domains=(_BRAVE_DOMAIN,))
            payload = await self._client.request_json(
                "GET",
                _BRAVE_URL,
                headers={
                    "X-Subscription-Token": self._search_api_key,
                    "Accept": "application/json",
                },
                params={"q": query, "count": 10}
                | ({"freshness": _brave_freshness(time_range)} if time_range else {}),
            )
            web = payload.get("web") or {}
            links = [item.get("url") for item in web.get("results", []) or []]
        else:
            check_destination(_SEARCH_URL, allowed_domains=(_SEARCH_DOMAIN,))
            payload = await self._client.request_json(
                "GET",
                _SEARCH_URL,
                params={
                    "key": self._search_api_key,
                    "cx": self._search_engine_id,
                    "q": query,
                    "num": 10,
                }
                | ({"dateRestrict": _GOOGLE_DATE_RESTRICT[time_range]} if time_range else {}),
            )
            links = [item.get("link") for item in payload.get("items", []) or []]

        return self._filter_pages([(link, None, None) for link in links], campaign=campaign)

    def _filter_pages(
        self, entries: list[tuple[Any, Any, Any]], *, campaign: str = ""
    ) -> list[tuple[str, str | None]]:
        """Selects the pages to read. Approved publishers go to the front: read first,
        their IOCs win attribution (deduplication keeps the first occurrence). Within each
        group, pages whose URL or title cites a distinctive word of the campaign precede
        generic pages: the engine's ranking, very sensitive to vague keywords, no longer
        decides alone."""

        keywords = {word.lower() for word in campaign.split() if len(word) >= 4}
        preferred: list[tuple[int, int, tuple[str, str | None]]] = []
        others: list[tuple[int, int, tuple[str, str | None]]] = []
        seen_links: set[tuple[str, str]] = set()
        for rank, (link, raw, title) in enumerate(entries):
            if not isinstance(link, str) or not self._page_allowed(link):
                continue
            parts = urlsplit(link)
            host = (parts.hostname or "").lower()
            key = (host.removeprefix("www."), parts.path.rstrip("/"))
            if key in seen_links:
                continue
            seen_links.add(key)
            if any(host == d or host.endswith(f".{d}") for d in _SOCIAL_DOMAINS):
                continue
            content = raw if isinstance(raw, str) and raw.strip() else None
            haystack = f"{parts.path} {title if isinstance(title, str) else ''}".lower()
            relevance = sum(1 for word in keywords if word in haystack)
            bucket = preferred if self._is_approved_publisher(link) else others
            bucket.append((-relevance, rank, (link, content)))
        preferred_pages = [page for _, _, page in sorted(preferred)]
        other_pages = [page for _, _, page in sorted(others)]
        # Approved publishers go to the front but do not take every slot: open search
        # keeps at least two pages for sources outside the list.
        head = preferred_pages[: self._max_pages - 2] if other_pages else preferred_pages
        rest = [page for page in preferred_pages if page not in head]
        return (head + other_pages + rest)[: self._max_pages]

    def _page_allowed(self, url: str) -> bool:
        """In closed mode: approved publishers only. In open mode: any HTTPS page."""

        if self._open_search:
            parts = urlsplit(url)
            return parts.scheme == "https" and bool(parts.hostname)
        return self._is_approved_publisher(url)

    def _is_approved_publisher(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            return False
        host = parts.hostname.lower()
        return any(
            host == domain or host.endswith(f".{domain}") for domain in self._publisher_domains
        )

    async def _extract_from_page(
        self, url: str, *, prefetched: str | None = None, campaign: str = ""
    ) -> list[Ioc]:
        if prefetched is not None:
            text = prefetched[:_MAX_PAGE_CHARS]
        else:
            if self._open_search:
                page_host = (urlsplit(url).hostname or "").lower()
                check_destination(url, allowed_domains=(page_host,) if page_host else ())
            else:
                check_destination(url, allowed_domains=self._publisher_domains)
            html = await self._client.request_text(
                url, headers=_PAGE_HEADERS, max_chars=_MAX_PAGE_CHARS * 4
            )
            text = _html_to_text(html)[:_MAX_PAGE_CHARS]
        if not text.strip():
            return []

        host = urlsplit(url).hostname or "publisher"
        system_prompt = _EXTRACTION_PROMPT
        if campaign:
            system_prompt += (
                f"\n\nThreat under investigation: {campaign}. If the document does not "
                "deal with this specific campaign or threat, respond `[]`: indicators of "
                "another threat would pollute the investigation."
            )
        completion = await self._gateway.complete(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": wrap(text, source=host, reference=url)},
            ],
        )

        iocs: list[Ioc] = []
        for candidate in _parse_extraction(getattr(completion, "content", "") or ""):
            ioc = self._validated(candidate, source_url=url, source_host=host)
            if ioc:
                iocs.append(ioc)
        return iocs

    def _validated(
        self, candidate: dict[str, Any], *, source_url: str, source_host: str
    ) -> Ioc | None:
        """Re-validate a model candidate. The pattern overrides the model's word."""

        raw = candidate.get("value")
        raw_type = candidate.get("type")
        if not isinstance(raw, str) or not isinstance(raw_type, str):
            return None
        try:
            ioc_type = IocType(raw_type)
        except ValueError:
            return None

        value = _refang(raw.strip())
        if not value or len(value) > 2048:
            return None
        if not self._matches_type(value, ioc_type):
            return None
        if ioc_type in (IocType.DOMAIN, IocType.URL):
            candidate_url = value if "://" in value else f"https://{value}"
            if self._is_approved_publisher(candidate_url):
                return None
            candidate_host = (urlsplit(candidate_url).hostname or "").lower()
            if candidate_host and (
                candidate_host == source_host or candidate_host.endswith(f".{source_host}")
            ):
                return None

        return Ioc(
            value=value,
            type=ioc_type,
            source_name=source_host,
            source_url=source_url,
            confidence="medium",
        )

    def _matches_type(self, value: str, ioc_type: IocType) -> bool:
        match ioc_type:
            case IocType.HASH:
                return bool(_HASH_RE.match(value))
            case IocType.IP:
                return _is_public_ip(value)
            case IocType.DOMAIN:
                return bool(_DOMAIN_RE.match(value))
            case IocType.URL:
                parts = urlsplit(value)
                return parts.scheme in ("http", "https") and bool(parts.hostname)
            case IocType.EMAIL:
                return bool(_EMAIL_RE.match(value))
            case IocType.FILE_PATH:
                return len(value) > 3 and ("/" in value or "\\" in value)
            case IocType.REGISTRY_KEY:
                return value.upper().startswith("HK")
        return False


_GOOGLE_DATE_RESTRICT = {"month": "m1", "3months": "m3", "9months": "m9", "year": "y1"}


def _window_start(time_range: str) -> datetime:
    return datetime.now(UTC) - timedelta(days=TIME_RANGE_DAYS[time_range])


def _brave_freshness(time_range: str) -> str:
    """Brave accepts `pm`/`py` for the standard windows, and date bounds
    `YYYY-MM-DDtoYYYY-MM-DD` for the intermediate ones (3 and 9 months)."""

    if time_range == "month":
        return "pm"
    if time_range == "year":
        return "py"
    now = datetime.now(UTC)
    return f"{_window_start(time_range).strftime('%Y-%m-%d')}to{now.strftime('%Y-%m-%d')}"


def _is_public_ip(value: str) -> bool:
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


def _refang(value: str) -> str:
    return (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("hxxp", "http")
        .replace("HXXP", "http")
    )


def _parse_extraction(content: str) -> list[dict[str, Any]]:
    """Read the JSON array from the response. An unreadable response means zero IOC, no error."""

    start = content.find("[")
    end = content.rfind("]")
    if start == -1 or end <= start:
        return []
    try:
        parsed = json.loads(content[start : end + 1])
    except json.JSONDecodeError:
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


class _TextExtractor(HTMLParser):
    _SKIPPED = frozenset({"script", "style", "noscript", "svg", "head"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIPPED:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIPPED and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth and data.strip():
            self._chunks.append(data.strip())

    def text(self) -> str:
        return " ".join(self._chunks)


def _html_to_text(html: str) -> str:
    extractor = _TextExtractor()
    try:
        extractor.feed(html)
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    return extractor.text()
