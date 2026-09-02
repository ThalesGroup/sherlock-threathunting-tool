"""Google SecOps (Chronicle) client, read-only UDM search.

Identity: dedicated GCP service account carrying the `Chronicle API Viewer` role (or
`Chronicle API Limited Viewer`, more restrictive, which excludes rules and retrohunts).
On GCP, authentication goes through Workload Identity rather than an exported key.

The instance path and API version are configurable: they vary by region
and tenant tier, and must be confirmed before going into service.
"""

from __future__ import annotations

import re
import time
from typing import Any, Protocol

from middleware.clients.base import UpstreamClient
from middleware.clients.results import QueryOutcome
from middleware.errors import ErrorCode, ToolError

SCOPE = "https://www.googleapis.com/auth/cloud-platform"

_DEFAULT_BASE_URL = "https://chronicle.googleapis.com/v1alpha"
_INSTANCE_PATH_RE = re.compile(r"^projects/[^/\s]+/locations/([^/\s]+)/instances/[^/\s]+$")


def resolve_instance(instance_path: str, base_url: str = "") -> tuple[str, str]:
    """Validates the instance path and derives the regional endpoint.

    The region is read from the path (`locations/<region>`): `us` stays on the global
    endpoint, any other region takes its prefix (`europe-chronicle.googleapis.com`).
    The host thus stays decided by the code, never by free input. An explicit
    `base_url` (SHL_SECOPS_BASE_URL) takes precedence for special cases.
    """

    path = instance_path.strip().strip("/")
    match = _INSTANCE_PATH_RE.match(path)
    if not match:
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            "Invalid SecOps instance path.",
            hint="Expected format: projects/<id>/locations/<region>/instances/<uuid>.",
        )
    if base_url:
        return path, base_url
    region = match.group(1).lower()
    if region in ("us", "global"):
        return path, _DEFAULT_BASE_URL
    return path, f"https://{region}-chronicle.googleapis.com/v1alpha"


class TokenProvider(Protocol):
    async def token_for(self, scope: str) -> str: ...


class SecOpsClient:
    def __init__(
        self,
        *,
        token_provider: TokenProvider,
        base_url: str,
        instance_path: str,
        client: UpstreamClient | None = None,
    ) -> None:
        self._tokens = token_provider
        self._base_url = base_url.rstrip("/")
        self._instance_path = instance_path.strip("/")
        self._client = client or UpstreamClient(label="SecOps")

    async def aclose(self) -> None:
        await self._client.aclose()

    async def run_query(
        self,
        *,
        query: str,
        start_time: str,
        end_time: str,
        row_cap: int,
    ) -> QueryOutcome:
        """UDM search via the `:udmSearch` API (verified 2026-08-25: the
        `legacy:legacyFetchUdmSearchView` path returns 404 on recent tenants)."""

        token = await self._tokens.token_for(SCOPE)

        started = time.monotonic()
        payload = await self._client.request_json(
            "GET",
            f"{self._base_url}/{self._instance_path}:udmSearch",
            headers={"Authorization": f"Bearer {token}"},
            params={
                "query": query,
                "timeRange.startTime": start_time,
                "timeRange.endTime": end_time,
                "limit": row_cap,
            },
        )
        duration_ms = int((time.monotonic() - started) * 1000)

        rows = _flatten_events(payload)
        truncated = len(rows) >= row_cap or bool(payload.get("moreDataAvailable"))
        return QueryOutcome(rows=rows[:row_cap], truncated=truncated, duration_ms=duration_ms)


def _flatten_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flattens UDM events: the nested structure is unusable as is."""

    container = payload.get("events")
    if isinstance(container, dict):
        events = container.get("events") or []
    elif isinstance(container, list):
        events = container
    else:
        events = []

    rows: list[dict[str, Any]] = []
    for event in events:
        inner = None
        if isinstance(event, dict):
            inner = event.get("udm") or event.get("event")
        rows.append(_flatten(inner if isinstance(inner, dict) else event))
    return rows


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            flat.update(_flatten(item, path))
    elif isinstance(value, list):
        if value and all(not isinstance(item, (dict, list)) for item in value):
            flat[prefix] = ", ".join(str(item) for item in value)
        else:
            for index, item in enumerate(value[:5]):
                flat.update(_flatten(item, f"{prefix}[{index}]"))
    else:
        flat[prefix or "value"] = value
    return flat
