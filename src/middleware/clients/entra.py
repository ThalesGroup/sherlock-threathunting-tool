"""Entra ID token acquisition for the Sentinel and Defender service identities.

The client credentials flow is used because the agent runs with no signed-in user.
The token is kept in memory until it expires; it is never logged.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from middleware.clients.base import outbound_verify
from middleware.errors import ErrorCode, ToolError

_EXPIRY_MARGIN_SECONDS = 120


@dataclass(frozen=True)
class EntraCredentials:
    tenant_id: str
    client_id: str
    client_secret: str
    authority: str = "https://login.microsoftonline.com"


class EntraTokenProvider:
    """Provides an application token per scope, with caching."""

    def __init__(
        self,
        credentials: EntraCredentials,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[str, float]] = {}
        self._client = httpx.AsyncClient(
            timeout=15.0, transport=transport, verify=outbound_verify()
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def token_for(self, scope: str) -> str:
        cached = self._cache.get(scope)
        if cached and cached[1] > time.monotonic():
            return cached[0]

        url = f"{self._credentials.authority}/{self._credentials.tenant_id}/oauth2/v2.0/token"
        try:
            response = await self._client.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._credentials.client_id,
                    "client_secret": self._credentials.client_secret,
                    "scope": scope,
                },
            )
        except httpx.HTTPError as exc:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "Authentication service unreachable.",
            ) from exc

        if response.status_code != 200:
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                "Platform authentication refused.",
                hint="Check the service identity authorization.",
            )

        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                "Access token missing from the authentication response.",
            )
        expires_in = int(payload.get("expires_in", 3600))
        self._cache[scope] = (
            token,
            time.monotonic() + max(60, expires_in - _EXPIRY_MARGIN_SECONDS),
        )
        return token


class StaticTokenProvider:
    """Used in tests and for managed identities, where the token comes from the host."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def token_for(self, scope: str) -> str:
        _ = scope
        return self._token

    async def aclose(self) -> None:
        return None
