"""Google SecOps authentication: service account -> access token.

What is locked down: the JSON key is validated before use, the signed assertion goes to
the token endpoint declared in the key, the token is cached, and an unreadable key does
not prevent the platform from starting (SecOps simply stays inactive).
"""

import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from middleware.clients.gcp import GcpCredentials, GcpTokenProvider
from middleware.config import Settings
from middleware.errors import ToolError


def _service_account_json() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return json.dumps(
        {
            "type": "service_account",
            "client_email": "sherlock@project.iam.gserviceaccount.com",
            "private_key": pem,
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


class TestCredentials:
    def test_valid_key_is_parsed(self):
        credentials = GcpCredentials.from_service_account_json(_service_account_json())
        assert credentials.client_email == "sherlock@project.iam.gserviceaccount.com"

    def test_invalid_json_is_rejected(self):
        with pytest.raises(ToolError):
            GcpCredentials.from_service_account_json("not json")

    def test_incomplete_key_is_rejected(self):
        with pytest.raises(ToolError):
            GcpCredentials.from_service_account_json('{"client_email": "x@y.z"}')


class TestTokenProvider:
    async def test_token_is_obtained_and_cached(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            assert request.url == "https://oauth2.googleapis.com/token"
            body = request.content.decode()
            assert "jwt-bearer" in body
            assert "assertion=" in body
            return httpx.Response(200, json={"access_token": "token", "expires_in": 3600})

        credentials = GcpCredentials.from_service_account_json(_service_account_json())
        provider = GcpTokenProvider(credentials, transport=httpx.MockTransport(handler))

        first = await provider.token_for("https://www.googleapis.com/auth/cloud-platform")
        second = await provider.token_for("https://www.googleapis.com/auth/cloud-platform")
        await provider.aclose()

        assert first == second == "token"
        assert len(calls) == 1

    async def test_refusal_is_a_tool_error_without_infrastructure_details(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "invalid_grant"})

        credentials = GcpCredentials.from_service_account_json(_service_account_json())
        provider = GcpTokenProvider(credentials, transport=httpx.MockTransport(handler))

        with pytest.raises(ToolError) as excinfo:
            await provider.token_for("https://www.googleapis.com/auth/cloud-platform")
        await provider.aclose()
        assert "refused" in excinfo.value.message


class FakeSecrets:
    def __init__(self, values=None):
        self._values = values or {}

    def get_optional(self, name):
        return self._values.get(name)


class TestResolveInstance:
    def test_regional_endpoint_is_derived_from_the_path(self):
        from middleware.clients.secops import resolve_instance

        path, base = resolve_instance("projects/p/locations/europe/instances/i")
        assert path == "projects/p/locations/europe/instances/i"
        assert base == "https://europe-chronicle.googleapis.com/v1alpha"

    def test_us_stays_on_the_global_endpoint(self):
        from middleware.clients.secops import resolve_instance

        _, base = resolve_instance("projects/p/locations/us/instances/i")
        assert base == "https://chronicle.googleapis.com/v1alpha"

    def test_explicit_base_url_wins(self):
        from middleware.clients.secops import resolve_instance

        _, base = resolve_instance(
            "projects/p/locations/europe/instances/i", "https://other.example/v1"
        )
        assert base == "https://other.example/v1"

    def test_malformed_path_is_rejected(self):
        from middleware.clients.secops import resolve_instance

        for bad in ("anything", "projects/p/instances/i", "https://evil.example/x"):
            with pytest.raises(ToolError):
                resolve_instance(bad)


class TestBuildClients:
    def test_secops_activates_on_key_and_instance_path(self):
        from api.runtime import build_clients

        settings = Settings(
            _env_file=None,
            secops_instance_path="projects/p/locations/europe/instances/i",
        )
        clients = build_clients(settings, FakeSecrets({"SECOPS_SA_KEY": _service_account_json()}))
        assert "secops" in clients.available()
        assert clients.secops._base_url == "https://europe-chronicle.googleapis.com/v1alpha"

    def test_instance_path_can_come_from_the_configuration_store(self):
        from api.runtime import build_clients

        settings = Settings(_env_file=None)
        clients = build_clients(
            settings,
            FakeSecrets(
                {
                    "SECOPS_SA_KEY": _service_account_json(),
                    "SECOPS_INSTANCE_PATH": "projects/p/locations/europe/instances/i",
                }
            ),
        )
        assert "secops" in clients.available()

    def test_a_malformed_instance_path_does_not_crash_startup(self):
        from api.runtime import build_clients

        settings = Settings(_env_file=None)
        clients = build_clients(
            settings,
            FakeSecrets(
                {
                    "SECOPS_SA_KEY": _service_account_json(),
                    "SECOPS_INSTANCE_PATH": "anything",
                }
            ),
        )
        assert "secops" not in clients.available()

    def test_secops_needs_the_instance_path(self):
        from api.runtime import build_clients

        settings = Settings(_env_file=None)
        clients = build_clients(settings, FakeSecrets({"SECOPS_SA_KEY": _service_account_json()}))
        assert "secops" not in clients.available()

    def test_an_unreadable_key_does_not_crash_startup(self):
        from api.runtime import build_clients

        settings = Settings(
            _env_file=None,
            secops_instance_path="projects/p/locations/europe/instances/i",
        )
        clients = build_clients(settings, FakeSecrets({"SECOPS_SA_KEY": "not json"}))
        assert "secops" not in clients.available()
