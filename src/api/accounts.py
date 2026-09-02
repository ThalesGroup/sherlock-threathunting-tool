"""Local accounts and sessions.

Platform access is granted, not requested: accounts are created by an admin
(Configuration screen or bootstrap script), never by self-registration. This mechanism
is the pilot stage before Entra ID SSO, which remains the target.

Passwords are hashed with PBKDF2-HMAC-SHA256 (standard library, per-account salt,
constant-time comparison). The session is a signed token carried by an httpOnly cookie:
the browser cannot read it, and it never travels in a URL.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets as pysecrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from api.auth import ROLE_ADMIN, Principal
from storage.models import UserRow
from storage.repository import Database

_PBKDF2_ITERATIONS = 600_000
_ALGORITHM = "pbkdf2_sha256"

ALLOWED_ROLES = frozenset({"analyst", "reader", "admin"})
MIN_PASSWORD_LENGTH = 12

SESSION_COOKIE = "shl_session"


def hash_password(password: str) -> str:
    salt = pysecrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    )
    return f"{_ALGORITHM}${_PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        if algorithm != _ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


class AccountRepository:
    """Account CRUD. The hash never leaves the API layer."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def create(
        self, *, username: str, password: str, roles: list[str], created_by: str
    ) -> None:
        async with self._database.session() as session:
            existing = await session.get(UserRow, username)
            if existing is not None:
                raise ValueError("This account already exists.")
            session.add(
                UserRow(
                    username=username,
                    password_hash=hash_password(password),
                    roles=",".join(sorted(set(roles))),
                    created_by=created_by,
                )
            )
            await session.commit()

    async def set_password(self, username: str, password: str) -> bool:
        async with self._database.session() as session:
            row = await session.get(UserRow, username)
            if row is None:
                return False
            row.password_hash = hash_password(password)
            await session.commit()
            return True

    async def authenticate(self, username: str, password: str) -> Principal | None:
        async with self._database.session() as session:
            row = await session.get(UserRow, username)
        if row is None or not verify_password(password, row.password_hash):
            return None
        return Principal(
            subject=row.username,
            name=row.username,
            roles=frozenset(role for role in row.roles.split(",") if role),
        )

    async def list_accounts(self) -> list[dict[str, str]]:
        async with self._database.session() as session:
            rows = (await session.execute(select(UserRow).order_by(UserRow.username))).scalars()
            return [
                {
                    "username": row.username,
                    "roles": row.roles,
                    "created_by": row.created_by,
                    "created_at": row.created_at.isoformat(),
                }
                for row in rows
            ]

    async def delete(self, username: str) -> bool:
        async with self._database.session() as session:
            row = await session.get(UserRow, username)
            if row is None:
                return False
            await session.delete(row)
            await session.commit()
            return True

    async def count_admins(self) -> int:
        async with self._database.session() as session:
            rows = (await session.execute(select(UserRow.roles))).scalars()
            return sum(1 for roles in rows if ROLE_ADMIN in roles.split(","))


class SessionManager:
    """Signed session tokens (HS256). The signing key lives in the encrypted store."""

    def __init__(self, signing_key: str, *, ttl_hours: int = 12) -> None:
        self._key = signing_key
        self._ttl = timedelta(hours=ttl_hours)

    @property
    def max_age_seconds(self) -> int:
        return int(self._ttl.total_seconds())

    def issue(self, principal: Principal) -> str:
        from jose import jwt

        now = datetime.now(UTC)
        return jwt.encode(
            {
                "sub": principal.subject,
                "name": principal.name,
                "roles": sorted(principal.roles),
                "iat": now,
                "exp": now + self._ttl,
            },
            self._key,
            algorithm="HS256",
        )

    def read(self, token: str) -> Principal | None:
        from jose import jwt
        from jose.exceptions import JWTError

        try:
            claims = jwt.decode(token, self._key, algorithms=["HS256"])
        except JWTError:
            return None
        subject = str(claims.get("sub") or "")
        if not subject:
            return None
        return Principal(
            subject=subject,
            name=str(claims.get("name") or subject),
            roles=frozenset(str(role) for role in claims.get("roles") or []),
        )
