"""Resolving the Sentinel Workspace ID from subscription / resource group / name."""

import httpx
import pytest

from api.runtime import effective_workspace_aliases
from middleware.clients.base import UpstreamClient
from middleware.clients.sentinel import ARM_SCOPE, resolve_workspace_id
from middleware.errors import ErrorCode, ToolError

SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
WORKSPACE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeTokens:
    def __init__(self):
        self.scopes = []

    async def token_for(self, scope):
        self.scopes.append(scope)
        return "token-arm"


def _client(handler):
    return UpstreamClient(label="ARM test", transport=httpx.MockTransport(handler))


class TestResolveWorkspaceId:
    async def test_reads_customer_id_from_the_workspace_resource(self):
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            seen["auth"] = request.headers.get("Authorization")
            return httpx.Response(
                200, json={"name": "ws-soc", "properties": {"customerId": WORKSPACE_ID}}
            )

        tokens = FakeTokens()
        resolved = await resolve_workspace_id(
            tokens,
            subscription_id=SUBSCRIPTION,
            resource_group="rg-soc",
            workspace_name="ws-soc",
            client=_client(handler),
        )

        assert resolved == WORKSPACE_ID
        assert tokens.scopes == [ARM_SCOPE]
        assert seen["auth"] == "Bearer token-arm"
        assert (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-soc"
            "/providers/Microsoft.OperationalInsights/workspaces/ws-soc?api-version="
        ) in seen["url"]

    async def test_invalid_names_are_refused_before_any_call(self):
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(200, json={})

        with pytest.raises(ToolError) as excinfo:
            await resolve_workspace_id(
                FakeTokens(),
                subscription_id="not-a-guid",
                resource_group="rg",
                workspace_name="ws",
                client=_client(handler),
            )
        assert excinfo.value.code is ErrorCode.SCHEMA_INVALID

        with pytest.raises(ToolError):
            await resolve_workspace_id(
                FakeTokens(),
                subscription_id=SUBSCRIPTION,
                resource_group="rg/../other",
                workspace_name="ws",
                client=_client(handler),
            )
        assert calls == []

    async def test_missing_customer_id_is_an_upstream_error(self):
        def handler(request):
            return httpx.Response(200, json={"properties": {}})

        with pytest.raises(ToolError) as excinfo:
            await resolve_workspace_id(
                FakeTokens(),
                subscription_id=SUBSCRIPTION,
                resource_group="rg-soc",
                workspace_name="ws-soc",
                client=_client(handler),
            )
        assert excinfo.value.code is ErrorCode.UPSTREAM_UNAVAILABLE

    async def test_not_found_surfaces_as_rejection(self):
        def handler(request):
            return httpx.Response(
                404, json={"error": {"code": "ResourceNotFound", "message": "not found"}}
            )

        with pytest.raises(ToolError) as excinfo:
            await resolve_workspace_id(
                FakeTokens(),
                subscription_id=SUBSCRIPTION,
                resource_group="rg-soc",
                workspace_name="unknown",
                client=_client(handler),
            )
        assert excinfo.value.code is ErrorCode.UPSTREAM_REJECTED


class TestEffectiveAliases:
    def test_server_aliases_win_over_the_resolved_workspace(self):
        assert effective_workspace_aliases({"prod": "guid-1"}, "guid-2") == {"prod": "guid-1"}

    def test_resolved_workspace_gets_the_default_alias(self):
        assert effective_workspace_aliases({}, "guid-2") == {"soc-principal": "guid-2"}

    def test_nothing_configured_means_no_workspace(self):
        assert effective_workspace_aliases({}, None) == {}
