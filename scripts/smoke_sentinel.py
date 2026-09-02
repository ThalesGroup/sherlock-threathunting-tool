"""Verification of Sentinel access: one minimal call per configured workspace.

Distinguishes the failure causes the agent only sees as a "query refused":
token not obtained (Entra credentials), 403 (Log Analytics Reader role missing on the
workspace), 404 (wrong workspace identifier: the "Workspace ID", a GUID, is required,
not the name nor the resource identifier), 400 (KQL refused by the service).

Usage: .venv/bin/python scripts/smoke_sentinel.py
No secret is displayed.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from smoke_gateway import load_dotenv  # noqa: E402

from middleware.clients.base import outbound_verify  # noqa: E402
from middleware.clients.entra import EntraCredentials, EntraTokenProvider  # noqa: E402
from middleware.clients.sentinel import SCOPE  # noqa: E402
from middleware.config import Settings  # noqa: E402
from middleware.errors import ToolError  # noqa: E402
from middleware.secrets import build_secret_provider  # noqa: E402

_QUERY = "print now()"


async def main() -> int:
    load_dotenv(Path(".env"))
    settings = Settings()
    secrets = build_secret_provider(settings)

    tenant = secrets.get_optional("ENTRA_TENANT_ID")
    client_id = secrets.get_optional("ENTRA_CLIENT_ID")
    client_secret = secrets.get_optional("ENTRA_CLIENT_SECRET")
    if not (tenant and client_id and client_secret):
        print("Incomplete Entra ID credentials (Configuration screen).")
        return 1
    if not settings.workspace_aliases:
        print("SHL_WORKSPACE_ALIASES empty: no workspace to test.")
        return 1

    provider = EntraTokenProvider(
        EntraCredentials(tenant_id=tenant, client_id=client_id, client_secret=client_secret)
    )
    try:
        token = await provider.token_for(SCOPE)
    except ToolError as error:
        print(f"1. Entra ID token: FAILED - {error.message}")
        return 1
    finally:
        await provider.aclose()
    print("1. Entra ID token: obtained for the api.loganalytics.io scope")

    status = 0
    async with httpx.AsyncClient(timeout=30.0, verify=outbound_verify()) as client:
        for alias, workspace_id in settings.workspace_aliases.items():
            masked = f"{workspace_id[:8]}…" if len(workspace_id) > 8 else "…"
            response = await client.post(
                f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query",
                headers={"Authorization": f"Bearer {token}"},
                json={"query": _QUERY, "timespan": "PT1H"},
            )
            verdict = _explain(response)
            print(f"2. Workspace '{alias}' ({masked}): HTTP {response.status_code} - {verdict}")
            if response.status_code != 200:
                status = 1
    return status


def _explain(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    error = payload.get("error") if isinstance(payload, dict) else None
    code = message = ""
    if isinstance(error, dict):
        code = str(error.get("code", ""))
        message = str(error.get("message", ""))[:160]
        inner = error.get("innererror")
        if isinstance(inner, dict) and inner.get("message"):
            message = f"{message} / {str(inner.get('message'))[:160]}"
    if response.status_code == 200:
        return "read access confirmed"
    if response.status_code == 403:
        return (
            f"{code}: Log Analytics Reader role missing on this workspace for the app registration"
            f" ({message})"
        )
    if response.status_code == 404:
        return (
            f"{code}: unknown workspace identifier - check the 'Workspace ID' (GUID) "
            f"in SHL_WORKSPACE_ALIASES ({message})"
        )
    if response.status_code == 401:
        return f"{code}: token refused - Data.Read permission missing or consent absent"
    return f"{code} {message}".strip() or "unexpected response"


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
