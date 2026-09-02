"""Lists the models of the anonymization endpoint, to find their identifier.

Resolves the "Call refused" case: the gateway responds but the requested model identifier
does not exist in this form (versioning, case, suffix). The key is read from the store
to sign the call, never displayed.

Usage: .venv/bin/python scripts/list_anonymizer_models.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx  # noqa: E402
from smoke_gateway import load_dotenv  # noqa: E402

from middleware.clients.base import configure_outbound_ca, outbound_verify  # noqa: E402
from middleware.config import Settings  # noqa: E402
from middleware.secrets import build_secret_provider  # noqa: E402


async def main() -> int:
    load_dotenv(Path(".env"))
    settings = Settings()
    configure_outbound_ca(settings.ca_bundle)
    secrets = build_secret_provider(settings)

    base_url = settings.anonymizer_base_url or settings.gateway_base_url
    api_key = secrets.get_optional("ANONYMIZER_API_KEY")
    if not base_url:
        print("[FAILED] endpoint missing: SHL_ANONYMIZER_BASE_URL or SHL_GATEWAY_BASE_URL.")
        return 1
    if not api_key:
        print("[FAILED] anonymization key missing: enter it in the Configuration screen.")
        return 1

    print(f"Endpoint : {base_url}")
    async with httpx.AsyncClient(timeout=20.0, trust_env=False, verify=outbound_verify()) as client:
        try:
            response = await client.get(
                f"{base_url.rstrip('/')}/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        except httpx.HTTPError as exc:
            print(f"[FAILED] endpoint unreachable: {type(exc).__name__}")
            return 1

    if response.status_code >= 400:
        print(f"[FAILED] HTTP {response.status_code} on /models.")
        return 1

    payload = response.json()
    models = [m.get("id", "") for m in payload.get("data", []) if m.get("id")]
    if not models:
        print("No model returned (unexpected structure).")
        return 1

    print(f"{len(models)} models available:\n")
    for model in sorted(models):
        flag = (
            "  <-- anonymization candidate"
            if any(k in model.lower() for k in ("small", "mini", "7b", "8b"))
            else ""
        )
        print(f"  {model}{flag}")
    print("\nCopy the exact identifier you want into SHL_ANONYMIZER_MODEL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
