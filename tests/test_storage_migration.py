"""Database already in service: columns added across versions are created at startup."""

import sqlite3

from storage.repository import Database


async def test_missing_query_columns_are_added_on_startup(tmp_path):
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    legacy.execute(
        "CREATE TABLE hunts (id VARCHAR(64) PRIMARY KEY, hypothesis TEXT, campaign VARCHAR(200), "
        "analyst VARCHAR(200), status VARCHAR(40), created_at DATETIME, updated_at DATETIME, "
        "interruption_reason TEXT)"
    )
    legacy.execute(
        "CREATE TABLE executed_queries ("
        "query_id VARCHAR(64) PRIMARY KEY, hunt_id VARCHAR(64), siem VARCHAR(32), "
        "query TEXT, executed_at VARCHAR(64), returned_rows INTEGER, source_rows INTEGER, "
        "truncated BOOLEAN, duration_ms INTEGER)"
    )
    legacy.execute(
        "INSERT INTO executed_queries VALUES ('q_1', 'hunt_1', 'sentinel', 'SigninLogs', "
        "'2026-07-01T10:00:00Z', 1, 1, 0, 5)"
    )
    legacy.commit()
    legacy.close()

    database = Database(f"sqlite+aiosqlite:///{path}")
    await database.create_all()
    await database.create_all()  # idempotent
    await database.dispose()

    upgraded = sqlite3.connect(path)
    columns = {row[1] for row in upgraded.execute("PRAGMA table_info(executed_queries)")}
    assert {
        "intent",
        "columns",
        "sample",
        "model_sample",
        "anonymization",
        "interpretation",
    } <= columns
    hunt_columns = {row[1] for row in upgraded.execute("PRAGMA table_info(hunts)")}
    assert {"playbook", "parent_hunt_id", "resume_context"} <= hunt_columns
    tables = {
        row[0] for row in upgraded.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "hunt_states" in tables
    intent, cols = upgraded.execute(
        "SELECT intent, columns FROM executed_queries WHERE query_id = 'q_1'"
    ).fetchone()
    assert intent is None
    assert cols == "[]"


class TestSecretProviderInProduction:
    def test_prod_without_vault_builds_without_env_fallback(self, tmp_path):
        from middleware.config import Settings
        from middleware.secrets import build_secret_provider

        settings = Settings(
            _env_file=None,
            environment="prod",
            secret_store_path=str(tmp_path / "secrets.enc"),
        )
        provider = build_secret_provider(settings)
        assert provider.get_optional("GATEWAY_API_KEY") is None
