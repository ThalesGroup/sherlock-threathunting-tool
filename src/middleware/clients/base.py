"""Common HTTP base for all outbound calls.

Every network call from the platform goes through here. Errors are converted into
structured errors: the model learns that a call failed, never where or how.
"""

from __future__ import annotations

from typing import Any

import httpx

from middleware.errors import ErrorCode, ToolError

DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=5.0)

_OUTBOUND_VERIFY: str | bool = True
"""Certificate authority for outbound calls. `True` = public store (certifi).
Behind an enterprise TLS inspection proxy, the application configures here the bundle
containing the internal root, otherwise inspected domains are rejected."""


def configure_outbound_ca(bundle: str | None) -> None:
    """Sets the trust authority for outbound calls. Called once at startup from
    the configuration (`SHL_CA_BUNDLE`). An empty bundle restores the public store."""

    global _OUTBOUND_VERIFY
    _OUTBOUND_VERIFY = bundle or True


def outbound_verify() -> str | bool:
    return _OUTBOUND_VERIFY


class UpstreamClient:
    """Minimal HTTP client, with no followed redirect and no infrastructure leak."""

    def __init__(
        self,
        *,
        label: str,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.label = label
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
            verify=outbound_verify(),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> UpstreamClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = await self._request(
            method, url, headers=headers, json_body=json_body, params=params
        )
        return self._handle_response(response)

    async def request_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_chars: int = 200_000,
    ) -> str:
        """Fetches textual content (report page), capped in size."""

        response = await self._request("GET", url, headers=headers, json_body=None, params=None)
        self._check_status(response)
        return response.text[:max_chars]

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        json_body: dict[str, Any] | None,
        params: dict[str, Any] | None,
    ) -> httpx.Response:
        try:
            return await self._client.request(
                method,
                url,
                headers=headers,
                json=json_body,
                params=params,
            )
        except httpx.TimeoutException as exc:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"Timeout on {self.label}.",
                hint="Reduce the time window or the query complexity.",
            ) from exc
        except httpx.HTTPError as exc:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"Source {self.label} unreachable.",
            ) from exc

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        self._check_status(response)
        try:
            payload = response.json()
        except ValueError as exc:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"Unreadable response from {self.label}.",
            ) from exc
        if not isinstance(payload, dict):
            return {"value": payload}
        return payload

    def _check_status(self, response: httpx.Response) -> None:
        if response.is_redirect:
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                f"Redirect refused on {self.label}.",
            )
        if response.status_code == 429:
            raise ToolError(
                ErrorCode.RATE_LIMITED,
                f"Quota reached on {self.label}.",
                hint="Space out the queries or reduce their number.",
            )
        if response.status_code in (401, 403):
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                f"Access refused by {self.label}.",
                hint="The platform does not have the required read permissions on this source.",
            )
        if response.status_code >= 500:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"Internal error from {self.label}.",
            )
        if response.status_code >= 400:
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                f"Query refused by {self.label}.",
                hint=_safe_reason(response),
            )


_SAFE_REASON_MAX = 200


def _safe_reason(response: httpx.Response) -> str | None:
    """Extracts a usable error reason without exposing the queried infrastructure."""

    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    message: Any = None
    if isinstance(error, dict):
        message = error.get("message") or error.get("code")
    elif isinstance(error, str):
        message = error
    if not isinstance(message, str):
        return None
    if "://" in message or "\\" in message:
        return None
    return message[:_SAFE_REASON_MAX]
