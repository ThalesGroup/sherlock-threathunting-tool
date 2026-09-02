"""Analyst authentication and roles.

Entra ID SSO over OIDC. Two roles: `analyst` (runs hunts, validates indicators and
reports) and `reader` (read-only access). Validation actions are reserved for the
analyst role and attributed by name in the audit log.

The development validator only agrees to serve if the environment is `dev`: it cannot
be enabled by mistake in production.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import Depends, HTTPException, Request, status

ROLE_ANALYST = "analyst"
ROLE_READER = "reader"
ROLE_ADMIN = "admin"


@dataclass(frozen=True)
class Principal:
    subject: str
    name: str
    roles: frozenset[str]

    @property
    def is_analyst(self) -> bool:
        return ROLE_ANALYST in self.roles

    @property
    def is_admin(self) -> bool:
        return ROLE_ADMIN in self.roles

    @property
    def can_read(self) -> bool:
        return bool(self.roles & {ROLE_ANALYST, ROLE_READER, ROLE_ADMIN})


class TokenValidator(ABC):
    @abstractmethod
    async def validate(self, request: Request) -> Principal: ...


class DevTokenValidator(TokenValidator):
    """Development only: identity comes from headers, with no proof."""

    def __init__(self, environment: str) -> None:
        if environment != "dev":
            raise RuntimeError(
                "The development validator is forbidden outside the dev environment."
            )

    async def validate(self, request: Request) -> Principal:
        subject = request.headers.get("X-Dev-User")
        if not subject:
            raise _unauthenticated()
        roles = request.headers.get("X-Dev-Roles", ROLE_ANALYST)
        return Principal(
            subject=subject,
            name=subject,
            roles=frozenset(role.strip() for role in roles.split(",") if role.strip()),
        )


class SessionTokenValidator(TokenValidator):
    """Session via httpOnly cookie, issued from a local account.

    The optional fallback (X-Dev-* headers, dev environment only) stays available
    for tests and tooling calls; the browser itself goes through the session.
    """

    def __init__(self, sessions: Any, *, fallback: TokenValidator | None = None) -> None:
        self._sessions = sessions
        self._fallback = fallback

    async def validate(self, request: Request) -> Principal:
        token = request.cookies.get("shl_session")
        if token:
            principal = self._sessions.read(token)
            if principal is not None:
                return principal
        if self._fallback is not None:
            return await self._fallback.validate(request)
        raise _unauthenticated()


class EntraTokenValidator(TokenValidator):
    """Validation of the Entra ID access token against the tenant's public keys."""

    def __init__(
        self,
        *,
        tenant_id: str,
        audience: str,
        role_claim: str = "roles",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._audience = audience
        self._role_claim = role_claim
        self._jwks: dict[str, Any] | None = None
        self._client = httpx.AsyncClient(timeout=10.0, transport=transport)

    @property
    def _jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{self._tenant_id}/discovery/v2.0/keys"

    async def _keys(self) -> dict[str, Any]:
        if self._jwks is None:
            response = await self._client.get(self._jwks_url)
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication service unavailable.",
                )
            self._jwks = response.json()
        return self._jwks

    async def validate(self, request: Request) -> Principal:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise _unauthenticated()

        from jose import jwt
        from jose.exceptions import JWTError

        token = header.removeprefix("Bearer ").strip()
        try:
            claims = jwt.decode(
                token,
                await self._keys(),
                audience=self._audience,
                issuer=f"https://login.microsoftonline.com/{self._tenant_id}/v2.0",
                options={"verify_at_hash": False},
            )
        except JWTError as exc:
            raise _unauthenticated() from exc

        roles = claims.get(self._role_claim) or []
        if isinstance(roles, str):
            roles = [roles]
        return Principal(
            subject=str(claims.get("oid") or claims.get("sub") or "unknown"),
            name=str(claims.get("preferred_username") or claims.get("name") or "unknown"),
            roles=frozenset(str(role) for role in roles),
        )


def _unauthenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def current_principal(request: Request) -> Principal:
    validator: TokenValidator = request.app.state.token_validator
    principal = await validator.validate(request)
    if not principal.can_read:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No platform access role.",
        )
    return principal


async def require_analyst(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """Guard for the two human checkpoints: indicator and verdict validation."""

    if not principal.is_analyst:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action is reserved for the analyst role.",
        )
    return principal


async def require_admin(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """Guard for the Configuration screen: managing keys is not an analyst act."""

    if not principal.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action is reserved for the admin role.",
        )
    return principal
