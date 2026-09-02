"""Local accounts: hashing, signed sessions. Access is granted, not requested."""

import pytest

from api.accounts import (
    AccountRepository,
    SessionManager,
    hash_password,
    verify_password,
)
from api.auth import Principal
from storage.repository import Database


class TestPasswordHashing:
    def test_roundtrip(self):
        encoded = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", encoded)
        assert not verify_password("something else", encoded)

    def test_hash_is_salted(self):
        assert hash_password("same password") != hash_password("same password")

    def test_malformed_hash_never_verifies(self):
        assert not verify_password("x", "not-a-hash")
        assert not verify_password("x", "")


class TestSessionManager:
    def _principal(self):
        return Principal(
            subject="j.doe", name="j.doe", roles=frozenset({"analyst", "admin"})
        )

    def test_issue_and_read(self):
        sessions = SessionManager("test-signing-key")
        token = sessions.issue(self._principal())
        principal = sessions.read(token)

        assert principal is not None
        assert principal.name == "j.doe"
        assert principal.roles == frozenset({"analyst", "admin"})

    def test_tampered_or_foreign_token_is_rejected(self):
        sessions = SessionManager("test-signing-key")
        token = sessions.issue(self._principal())

        assert sessions.read(token + "a") is None
        assert SessionManager("other-key").read(token) is None
        assert sessions.read("whatever") is None

    def test_expired_token_is_rejected(self):
        sessions = SessionManager("test-signing-key", ttl_hours=-1)
        token = sessions.issue(self._principal())
        assert sessions.read(token) is None


class TestAccountRepository:
    @pytest.fixture
    async def accounts(self, tmp_path):
        database = Database(f"sqlite+aiosqlite:///{tmp_path}/users.db")
        await database.create_all()
        yield AccountRepository(database)
        await database.dispose()

    async def test_create_and_authenticate(self, accounts):
        await accounts.create(
            username="j.doe",
            password="a long passphrase",
            roles=["analyst", "admin"],
            created_by="script",
        )
        principal = await accounts.authenticate("j.doe", "a long passphrase")
        assert principal is not None
        assert principal.roles == frozenset({"analyst", "admin"})
        assert await accounts.authenticate("j.doe", "wrong") is None
        assert await accounts.authenticate("unknown", "whatever") is None

    async def test_duplicate_username_is_refused(self, accounts):
        await accounts.create(
            username="a", password="long password", roles=["reader"], created_by="s"
        )
        with pytest.raises(ValueError):
            await accounts.create(
                username="a", password="another password", roles=["reader"], created_by="s"
            )

    async def test_listing_exposes_no_hash(self, accounts):
        await accounts.create(
            username="a", password="long password", roles=["reader"], created_by="s"
        )
        listing = await accounts.list_accounts()
        assert "password_hash" not in str(listing)
        assert "pbkdf2" not in str(listing)

    async def test_count_admins(self, accounts):
        await accounts.create(
            username="a", password="long password", roles=["analyst"], created_by="s"
        )
        await accounts.create(
            username="b", password="long password", roles=["analyst", "admin"], created_by="s"
        )
        assert await accounts.count_admins() == 1
