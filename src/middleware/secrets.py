"""Secrets access.

No secret is hardcoded, logged, or inserted into a prompt. The values returned here never
cross the middleware boundary: they serve to sign an outbound call and nothing else.

The order of preference is: identity managed by the hosting platform (Azure managed
identity, GCP Workload Identity) > secret in the vault > development environment variable.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

_REDACTED: Final = "[secret]"


class SecretNotFound(RuntimeError):
    def __init__(self, name: str) -> None:
        super().__init__(f"Secret not found in the vault: {name}")
        self.name = name


class SecretProvider(ABC):
    @abstractmethod
    def get(self, name: str) -> str: ...

    def get_optional(self, name: str) -> str | None:
        try:
            return self.get(name)
        except SecretNotFound:
            return None


class EnvSecretProvider(SecretProvider):
    """Development only. Refuses to serve if the environment is not `dev`.

    Reads the process environment, then the `.env` file as a fallback: sourcing a secrets
    file in a shell is forbidden (a single malformed line is enough to print a key in the
    clear). The file is parsed here, never interpreted.
    """

    def __init__(
        self,
        *,
        environment: str = "dev",
        prefix: str = "SHL_SECRET_",
        env_file: str = ".env",
    ) -> None:
        if environment != "dev":
            raise RuntimeError(
                "Secrets in environment variables are forbidden outside development."
            )
        self._prefix = prefix
        self._env_file = env_file
        self._file_values: dict[str, str] | None = None

    def get(self, name: str) -> str:
        key = self._prefix + name.upper().replace("-", "_")
        value = os.environ.get(key) or self._from_file(key)
        if not value:
            raise SecretNotFound(name)
        return value

    def _from_file(self, key: str) -> str | None:
        if self._file_values is None:
            self._file_values = _parse_env_file(self._env_file, prefix=self._prefix)
        return self._file_values.get(key)


def _parse_env_file(path: str, *, prefix: str) -> dict[str, str]:
    """Extracts `PREFIX_*=value` lines from a .env file, without executing it."""

    values: dict[str, str] = {}
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line.startswith(prefix) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("\"'")
        if value:
            values[key.strip()] = value
    return values


class MutableSecretStore(ABC):
    """Store administrable from the Configuration screen. Write-only as seen from outside:
    the API writes, deletes and describes, but no value ever comes back out to the front."""

    @abstractmethod
    def get(self, name: str) -> str | None: ...

    @abstractmethod
    def set(self, name: str, value: str, *, actor: str) -> None: ...

    @abstractmethod
    def delete(self, name: str) -> bool: ...

    @abstractmethod
    def describe(self, name: str) -> dict[str, str] | None: ...


class EncryptedSecretStore(MutableSecretStore):
    """Local development store. Encrypted at rest (Fernet).

    The master key lives in a separate file with restricted permissions (or in
    `SHL_SECRET_STORE_KEY`), never in the encrypted file. Accepted limitation: the master
    key resides on the same disk. In production, `SHL_KEY_VAULT_URL` switches to
    `KeyVaultSecretStore` and this store is no longer used.
    """

    def __init__(self, path: str | Path, *, master_key: str | None = None) -> None:
        from cryptography.fernet import Fernet

        self._path = Path(path)
        raw_key = master_key or os.environ.get("SHL_SECRET_STORE_KEY")
        self._fernet = Fernet(raw_key.encode() if raw_key else self._load_or_create_key())

    def get(self, name: str) -> str | None:
        entry = self._read_all().get(name)
        return entry["value"] if entry else None

    def set(self, name: str, value: str, *, actor: str) -> None:
        entries = self._read_all()
        entries[name] = {
            "value": value,
            "updated_at": datetime.now(UTC).isoformat(),
            "updated_by": actor,
        }
        self._write_all(entries)

    def delete(self, name: str) -> bool:
        entries = self._read_all()
        if name not in entries:
            return False
        del entries[name]
        self._write_all(entries)
        return True

    def describe(self, name: str) -> dict[str, str] | None:
        """Metadata for a key, without its value. This is all the API can read back."""

        entry = self._read_all().get(name)
        if entry is None:
            return None
        return {
            "updated_at": entry.get("updated_at", ""),
            "updated_by": entry.get("updated_by", ""),
        }

    def _load_or_create_key(self) -> bytes:
        from cryptography.fernet import Fernet

        key_path = self._path.with_name(self._path.name + ".key")
        if key_path.exists():
            return key_path.read_bytes().strip()
        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        _write_restricted(key_path, key)
        return key

    def _read_all(self) -> dict[str, dict[str, str]]:
        from cryptography.fernet import InvalidToken

        try:
            token = self._path.read_bytes()
        except OSError:
            return {}
        try:
            payload = json.loads(self._fernet.decrypt(token))
        except (InvalidToken, ValueError) as exc:
            raise RuntimeError(
                "Secret store unreadable: the master key changed or the file is corrupted."
            ) from exc
        return payload if isinstance(payload, dict) else {}

    def _write_all(self, entries: dict[str, dict[str, str]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        token = self._fernet.encrypt(json.dumps(entries).encode())
        temp = self._path.with_name(self._path.name + ".tmp")
        _write_restricted(temp, token)
        os.replace(temp, self._path)


def _write_restricted(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


class ConfigurableSecretProvider(SecretProvider):
    """Chains the administrable store and an optional fallback provider.

    In development: local encrypted store, falling back to `.env` (bootstrap). In
    production: Key Vault store, no fallback — a key entered in the Configuration screen
    always takes precedence over the bootstrap mechanism.
    """

    def __init__(self, store: MutableSecretStore, fallback: SecretProvider | None = None) -> None:
        self._store = store
        self._fallback = fallback

    @property
    def store(self) -> MutableSecretStore:
        return self._store

    def get(self, name: str) -> str:
        value = self._store.get(name)
        if value:
            return value
        if self._fallback is None:
            raise SecretNotFound(name)
        return self._fallback.get(name)

    def set(self, name: str, value: str, *, actor: str) -> None:
        self._store.set(name, value, actor=actor)

    def delete(self, name: str) -> bool:
        return self._store.delete(name)

    def origin(self, name: str) -> str | None:
        """`configuration` (store), `environment` (fallback), or None if absent."""

        if self._store.get(name):
            return "configuration"
        if self._fallback is not None and self._fallback.get_optional(name):
            return "environment"
        return None

    def describe(self, name: str) -> dict[str, Any]:
        state: dict[str, Any] = {"origin": self.origin(name)}
        state.update(self._store.describe(name) or {})
        return state


def vault_secret_name(name: str) -> str:
    """Translates a logical name into a Key Vault name: the vault accepts only letters,
    digits and dashes. `GATEWAY_API_KEY` -> `GATEWAY-API-KEY`, both ways without ambiguity."""

    return name.strip().upper().replace("_", "-")


def _vault_client(vault_url: str) -> Any:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError as exc:
        raise RuntimeError(
            "SHL_KEY_VAULT_URL is set but the `azure` extras are not "
            "installed: pip install -e '.[azure]'."
        ) from exc
    return SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())


class KeyVaultSecretProvider(SecretProvider):
    """Enterprise vault, read access. Authentication goes through the managed identity:
    no bootstrap secret."""

    def __init__(self, vault_url: str) -> None:
        self._client = _vault_client(vault_url)
        self._cache: dict[str, str] = {}

    def get(self, name: str) -> str:  # pragma: no cover - requires a vault
        if name in self._cache:
            return self._cache[name]
        try:
            value = self._client.get_secret(vault_secret_name(name)).value
        except Exception as exc:
            raise SecretNotFound(name) from exc
        if not value:
            raise SecretNotFound(name)
        self._cache[name] = value
        return value


class KeyVaultSecretStore(MutableSecretStore):
    """Administrable store backed by Key Vault: the Configuration screen writes and deletes
    directly in the vault. Requires the Secrets Officer role for the managed identity.

    No read cache: a key changed in the vault (rotation, another instance) is seen
    immediately, and a deleted key ceases to exist everywhere.
    """

    def __init__(self, vault_url: str) -> None:
        self._client = _vault_client(vault_url)

    def get(self, name: str) -> str | None:  # pragma: no cover - requires a vault
        try:
            return self._client.get_secret(vault_secret_name(name)).value
        except Exception:
            return None

    def set(self, name: str, value: str, *, actor: str) -> None:  # pragma: no cover
        self._client.set_secret(
            vault_secret_name(name),
            value,
            tags={"updated_by": actor, "updated_at": datetime.now(UTC).isoformat()},
        )

    def delete(self, name: str) -> bool:  # pragma: no cover - requires a vault
        try:
            self._client.begin_delete_secret(vault_secret_name(name)).wait()
            return True
        except Exception:
            return False

    def describe(self, name: str) -> dict[str, str] | None:  # pragma: no cover
        try:
            properties = self._client.get_secret(vault_secret_name(name)).properties
        except Exception:
            return None
        tags = properties.tags or {}
        return {
            "updated_at": tags.get("updated_at")
            or (properties.updated_on.isoformat() if properties.updated_on else ""),
            "updated_by": tags.get("updated_by", ""),
        }


def build_secret_provider(settings: Any) -> ConfigurableSecretProvider:
    """Assembles the secret provider according to the environment, as the API does.

    A single path shared between the application and the tooling scripts: a key entered in
    the Configuration screen (encrypted store) is seen everywhere, without having to
    duplicate it in `.env`. In production, `key_vault_url` switches to the vault, no
    fallback.
    """

    if settings.key_vault_url:
        store: MutableSecretStore = KeyVaultSecretStore(settings.key_vault_url)
        fallback: SecretProvider | None = None
    else:
        store = EncryptedSecretStore(settings.secret_store_path)
        fallback = (
            EnvSecretProvider(environment=settings.environment)
            if settings.environment == "dev"
            else None
        )
    return ConfigurableSecretProvider(store=store, fallback=fallback)


def redact(text: str, secrets: list[str]) -> str:
    """Last barrier before logging: no secret value must get through."""

    for secret in secrets:
        if secret and len(secret) >= 8:
            text = text.replace(secret, _REDACTED)
    return text
