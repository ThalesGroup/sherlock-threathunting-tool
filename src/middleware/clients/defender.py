"""Microsoft Defender client via the Graph security API.

Identity: Entra ID app registration with the application permission
`ThreatHunting.Read.All` (admin consent required). Endpoint `POST /security/runHuntingQuery`.
The legacy Defender XDR API is not used.

The API accepts no time window parameter: the bound must be carried by the
query, which the KQL guardrail checks before the call.
"""

from __future__ import annotations

import time
from typing import Any, Protocol

from middleware.clients.base import UpstreamClient
from middleware.clients.results import QueryOutcome

SCOPE = "https://graph.microsoft.com/.default"
_BASE_URL = "https://graph.microsoft.com/v1.0"

API_MAX_ROWS = 100_000
API_MAX_WINDOW_DAYS = 30


class TokenProvider(Protocol):
    async def token_for(self, scope: str) -> str: ...


class DefenderClient:
    def __init__(
        self,
        *,
        token_provider: TokenProvider,
        client: UpstreamClient | None = None,
        base_url: str = _BASE_URL,
    ) -> None:
        self._tokens = token_provider
        self._client = client or UpstreamClient(label="Defender")
        self._base_url = base_url.rstrip("/")

    async def aclose(self) -> None:
        await self._client.aclose()

    async def run_query(self, *, query: str, row_cap: int) -> QueryOutcome:
        token = await self._tokens.token_for(SCOPE)

        started = time.monotonic()
        payload = await self._client.request_json(
            "POST",
            f"{self._base_url}/security/runHuntingQuery",
            headers={"Authorization": f"Bearer {token}"},
            json_body={"Query": query},
        )
        duration_ms = int((time.monotonic() - started) * 1000)

        rows: list[dict[str, Any]] = payload.get("results") or []
        truncated = len(rows) >= row_cap
        return QueryOutcome(rows=rows[:row_cap], truncated=truncated, duration_ms=duration_ms)
