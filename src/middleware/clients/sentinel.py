"""Microsoft Sentinel client (Log Analytics query API).

Identity: Entra ID app registration carrying the application permission
`Log Analytics Data.Read`, with the Azure RBAC role `Log Analytics Reader` assigned
workspace by workspace. No write permission is requested.

The real workspace name never appears on the model side: the tool receives a logical alias,
resolved by the middleware before reaching here.
"""

from __future__ import annotations

import re
import time
from typing import Any, Protocol

from middleware.clients.base import UpstreamClient
from middleware.clients.results import QueryOutcome, rows_from_columnar
from middleware.errors import ErrorCode, ToolError

SCOPE = "https://api.loganalytics.io/.default"
_BASE_URL = "https://api.loganalytics.io/v1"

ARM_SCOPE = "https://management.azure.com/.default"
_ARM_BASE_URL = "https://management.azure.com"
_ARM_API_VERSION = "2022-10-01"
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._()-]{0,89}$")


class TokenProvider(Protocol):
    async def token_for(self, scope: str) -> str: ...


class SentinelClient:
    def __init__(
        self,
        *,
        token_provider: TokenProvider,
        client: UpstreamClient | None = None,
        base_url: str = _BASE_URL,
    ) -> None:
        self._tokens = token_provider
        self._client = client or UpstreamClient(label="Sentinel")
        self._base_url = base_url.rstrip("/")

    async def aclose(self) -> None:
        await self._client.aclose()

    async def run_query(
        self,
        *,
        query: str,
        workspace_id: str,
        timespan_days: int,
        row_cap: int,
        timespan: str | None = None,
    ) -> QueryOutcome:
        """An absolute `timespan` (`start/end` ISO 8601) takes precedence over the relative
        depth: it carries the investigation period set by the analyst."""

        token = await self._tokens.token_for(SCOPE)

        started = time.monotonic()
        payload = await self._client.request_json(
            "POST",
            f"{self._base_url}/workspaces/{workspace_id}/query",
            headers={"Authorization": f"Bearer {token}"},
            json_body={"query": query, "timespan": timespan or f"P{timespan_days}D"},
        )
        duration_ms = int((time.monotonic() - started) * 1000)

        rows = _rows_from_tables(payload)
        truncated = len(rows) >= row_cap or _has_truncation_warning(payload)
        return QueryOutcome(rows=rows[:row_cap], truncated=truncated, duration_ms=duration_ms)


def _rows_from_tables(payload: dict[str, Any]) -> list[dict[str, Any]]:
    tables = payload.get("tables") or []
    if not tables:
        return []
    primary = tables[0]
    columns = [
        column.get("name", f"col{index}") for index, column in enumerate(primary.get("columns", []))
    ]
    return rows_from_columnar(columns, primary.get("rows", []))


def _has_truncation_warning(payload: dict[str, Any]) -> bool:
    error = payload.get("error") or {}
    details = error.get("details") if isinstance(error, dict) else None
    if not isinstance(details, list):
        return False
    return any("truncat" in str(detail).lower() for detail in details)


async def resolve_workspace_id(
    token_provider: TokenProvider,
    *,
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
    client: UpstreamClient | None = None,
    base_url: str = _ARM_BASE_URL,
) -> str:
    """Retrieves the Workspace ID (`customerId` GUID) of a Log Analytics workspace from
    its subscription, resource group and name, via Azure Resource
    Manager. Read-only; the Log Analytics Reader role on the workspace is enough."""

    subscription_id = subscription_id.strip()
    resource_group = resource_group.strip()
    workspace_name = workspace_name.strip()
    if not _GUID_RE.match(subscription_id):
        raise ToolError(ErrorCode.SCHEMA_INVALID, "Subscription ID expected as a GUID.")
    for label, value in (("resource group", resource_group), ("workspace", workspace_name)):
        if not _RESOURCE_NAME_RE.match(value):
            raise ToolError(ErrorCode.SCHEMA_INVALID, f"Invalid {label} name.")

    token = await token_provider.token_for(ARM_SCOPE)
    own_client = client is None
    upstream = client or UpstreamClient(label="Azure Resource Manager")
    try:
        payload = await upstream.request_json(
            "GET",
            f"{base_url.rstrip('/')}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
            f"?api-version={_ARM_API_VERSION}",
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        if own_client:
            await upstream.aclose()

    properties = payload.get("properties") or {}
    customer_id = properties.get("customerId") if isinstance(properties, dict) else None
    if not isinstance(customer_id, str) or not _GUID_RE.match(customer_id):
        raise ToolError(
            ErrorCode.UPSTREAM_UNAVAILABLE,
            "Azure Resource Manager did not return a workspace identifier.",
        )
    return customer_id
