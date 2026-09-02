"""Google Cloud token acquisition for the SecOps (Chronicle) service identity.

Service account flow: a JWT signed RS256 with the account's private key is exchanged
for an access token at the Google issuance endpoint. The token is kept in
memory until it expires; neither the key nor the token is logged.

On GCP, prefer Workload Identity (token provided by the host, via `StaticTokenProvider`);
the exported JSON key is the off-GCP path, to be stored in the configuration vault.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass

import httpx

from middleware.clients.base import outbound_verify
from middleware.errors import ErrorCode, ToolError

_EXPIRY_MARGIN_SECONDS = 120
_TOKEN_LIFETIME_SECONDS = 3600


@dataclass(frozen=True)
class GcpCredentials:
    client_email: str
    private_key: str
    token_uri: str = "https://oauth2.googleapis.com/token"  # noqa: S105 - public URL

    @classmethod
    def from_service_account_json(cls, raw: str) -> GcpCredentials:
        """Reads an exported service account key (the complete JSON file)."""

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ToolError(
                ErrorCode.SCHEMA_INVALID,
                "The SecOps key must be the complete service account JSON.",
            ) from exc
        email = data.get("client_email")
        key = data.get("private_key")
        if not email or not key:
            raise ToolError(
                ErrorCode.SCHEMA_INVALID,
                "Incomplete service account key: client_email or private_key missing.",
            )
        return cls(
            client_email=email,
            private_key=key,
            token_uri=data.get("token_uri") or cls.token_uri,
        )


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _signed_assertion(credentials: GcpCredentials, scope: str) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64url(
        json.dumps(
            {
                "iss": credentials.client_email,
                "scope": scope,
                "aud": credentials.token_uri,
                "iat": now,
                "exp": now + _TOKEN_LIFETIME_SECONDS,
            }
        ).encode()
    )
    message = header + b"." + claims

    try:
        key = serialization.load_pem_private_key(credentials.private_key.encode(), password=None)
    except ValueError as exc:
        raise ToolError(
            ErrorCode.SCHEMA_INVALID,
            "The service account private key is unreadable.",
        ) from exc
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b"." + _b64url(signature)).decode()


class GcpTokenProvider:
    """Provides an access token per scope, with caching."""

    def __init__(
        self,
        credentials: GcpCredentials,
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

        try:
            response = await self._client.post(
                self._credentials.token_uri,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": _signed_assertion(self._credentials, scope),
                },
            )
        except httpx.HTTPError as exc:
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "Google authentication service unreachable.",
            ) from exc

        if response.status_code != 200:
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                "SecOps service account authentication refused.",
                hint="Check the JSON key and the Chronicle API Viewer authorization.",
            )

        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                "Access token missing from the Google authentication response.",
            )
        expires_in = int(payload.get("expires_in", _TOKEN_LIFETIME_SECONDS))
        self._cache[scope] = (
            token,
            time.monotonic() + max(60, expires_in - _EXPIRY_MARGIN_SECONDS),
        )
        return token
