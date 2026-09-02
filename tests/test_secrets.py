"""EnvSecretProvider: environment first, .env as fallback, never a shell."""

import pytest

from middleware.secrets import (
    ConfigurableSecretProvider,
    EncryptedSecretStore,
    EnvSecretProvider,
    SecretNotFound,
)


class TestEnvSecretProvider:
    def test_refuses_outside_dev(self):
        with pytest.raises(RuntimeError):
            EnvSecretProvider(environment="production")

    def test_environment_takes_precedence(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text("SHL_SECRET_GATEWAY_API_KEY=from-the-file\n")
        monkeypatch.setenv("SHL_SECRET_GATEWAY_API_KEY", "from-the-environment")

        provider = EnvSecretProvider(env_file=str(env_file))

        assert provider.get("GATEWAY_API_KEY") == "from-the-environment"

    def test_env_file_is_parsed_not_executed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHL_SECRET_GATEWAY_API_KEY", raising=False)
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# comment\n"
            'SHL_WORKSPACE_ALIASES={"soc": "guid"}\n'
            "SHL_SECRET_GATEWAY_API_KEY = sk-example-quote \n"
        )

        provider = EnvSecretProvider(env_file=str(env_file))

        assert provider.get("GATEWAY_API_KEY") == "sk-example-quote"

    def test_missing_everywhere_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHL_SECRET_ABSENT", raising=False)
        provider = EnvSecretProvider(env_file=str(tmp_path / "nonexistent.env"))
        with pytest.raises(SecretNotFound):
            provider.get("ABSENT")


class TestEncryptedSecretStore:
    def test_roundtrip_and_nothing_in_clear_on_disk(self, tmp_path):
        store = EncryptedSecretStore(tmp_path / "secrets.enc")
        store.set("OTX_API_KEY", "very-secret-value", actor="a.admin")

        assert store.get("OTX_API_KEY") == "very-secret-value"
        raw = (tmp_path / "secrets.enc").read_bytes()
        assert b"very-secret-value" not in raw
        assert b"OTX_API_KEY" not in raw

    def test_master_key_file_is_restricted(self, tmp_path):
        EncryptedSecretStore(tmp_path / "secrets.enc").set("A_KEY", "abcd", actor="x")
        key_path = tmp_path / "secrets.enc.key"
        assert key_path.exists()
        assert (key_path.stat().st_mode & 0o777) == 0o600

    def test_describe_never_returns_the_value(self, tmp_path):
        store = EncryptedSecretStore(tmp_path / "secrets.enc")
        store.set("OTX_API_KEY", "very-secret-value", actor="a.admin")

        described = store.describe("OTX_API_KEY")
        assert described["updated_by"] == "a.admin"
        assert "very-secret-value" not in str(described)

    def test_wrong_master_key_is_a_clear_error(self, tmp_path):
        from cryptography.fernet import Fernet

        EncryptedSecretStore(
            tmp_path / "secrets.enc", master_key=Fernet.generate_key().decode()
        ).set("A_KEY", "abcd", actor="x")
        other = EncryptedSecretStore(
            tmp_path / "secrets.enc", master_key=Fernet.generate_key().decode()
        )
        with pytest.raises(RuntimeError):
            other.get("A_KEY")


class TestConfigurableSecretProvider:
    def _provider(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SHL_SECRET_OTX_API_KEY", "from-the-environment")
        return ConfigurableSecretProvider(
            store=EncryptedSecretStore(tmp_path / "secrets.enc"),
            fallback=EnvSecretProvider(env_file=str(tmp_path / "nonexistent.env")),
        )

    def test_store_takes_precedence_over_environment(self, tmp_path, monkeypatch):
        provider = self._provider(tmp_path, monkeypatch)
        assert provider.get("OTX_API_KEY") == "from-the-environment"
        assert provider.origin("OTX_API_KEY") == "environment"

        provider.set("OTX_API_KEY", "from-the-screen", actor="a.admin")
        assert provider.get("OTX_API_KEY") == "from-the-screen"
        assert provider.origin("OTX_API_KEY") == "configuration"

    def test_delete_falls_back_to_environment(self, tmp_path, monkeypatch):
        provider = self._provider(tmp_path, monkeypatch)
        provider.set("OTX_API_KEY", "from-the-screen", actor="a.admin")

        assert provider.delete("OTX_API_KEY")
        assert provider.get("OTX_API_KEY") == "from-the-environment"
        assert not provider.delete("OTX_API_KEY")

    def test_absent_everywhere(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHL_SECRET_ABSENT", raising=False)
        provider = ConfigurableSecretProvider(
            store=EncryptedSecretStore(tmp_path / "secrets.enc"),
            fallback=EnvSecretProvider(env_file=str(tmp_path / "nonexistent.env")),
        )
        assert provider.origin("ABSENT") is None
        with pytest.raises(SecretNotFound):
            provider.get("ABSENT")


class TestKeyVaultSwitch:
    def test_vault_secret_names_have_no_underscores(self):
        from middleware.secrets import vault_secret_name

        assert vault_secret_name("GATEWAY_API_KEY") == "GATEWAY-API-KEY"
        assert vault_secret_name("session_signing_key") == "SESSION-SIGNING-KEY"

    def test_provider_without_fallback_serves_only_the_store(self, tmp_path):
        provider = ConfigurableSecretProvider(
            store=EncryptedSecretStore(tmp_path / "secrets.enc"),
        )
        provider.set("OTX_API_KEY", "from-the-vault", actor="a.admin")

        assert provider.get("OTX_API_KEY") == "from-the-vault"
        assert provider.origin("OTX_API_KEY") == "configuration"
        assert provider.origin("ABSENT") is None
        with pytest.raises(SecretNotFound):
            provider.get("ABSENT")

    def test_vault_url_without_azure_extras_fails_with_a_clear_message(self):
        import builtins

        from middleware.secrets import KeyVaultSecretStore

        real_import = builtins.__import__

        def refuse_azure(name, *args, **kwargs):
            if name.startswith("azure"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        builtins.__import__ = refuse_azure
        try:
            with pytest.raises(RuntimeError, match="azure"):
                KeyVaultSecretStore("https://example.vault.azure.net")
        finally:
            builtins.__import__ = real_import
