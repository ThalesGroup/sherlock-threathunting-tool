"""Verification of the IOC search, with the platform's real connector.

Goes through the same path as the validation screen: anti-leak filter on the campaign
name, sources activated according to keys + whitelist, IOCs discarded if they have no
citable source. Nothing but the campaign name goes out.

Usage: .venv/bin/python scripts/smoke_ti.py "Volt Typhoon"
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from smoke_gateway import load_dotenv  # noqa: E402

from middleware.clients.base import configure_outbound_ca  # noqa: E402
from middleware.config import Settings  # noqa: E402
from middleware.errors import ToolError  # noqa: E402
from middleware.secrets import build_secret_provider  # noqa: E402
from orchestrator.gateway import GatewayClient  # noqa: E402


async def main() -> int:
    load_dotenv(Path(".env"))
    settings = Settings()
    configure_outbound_ca(settings.ca_bundle)
    secrets = build_secret_provider(settings)
    campaign = sys.argv[1] if len(sys.argv) > 1 else "Volt Typhoon"

    gateway = None
    if settings.gateway_base_url and secrets.get_optional("GATEWAY_API_KEY"):
        gateway = GatewayClient(
            base_url=settings.gateway_base_url,
            api_key=secrets.get_optional("GATEWAY_API_KEY") or "",
            prompt_caching=settings.gateway_prompt_caching,
        )

    from api.runtime import build_threat_intel  # noqa: E402

    connector = build_threat_intel(settings, secrets, gateway)
    if connector is None:
        print("No active threat intelligence source. To activate one:")
        print("  - VirusTotal: SHL_SECRET_VIRUSTOTAL_API_KEY")
        print("  - OTX: SHL_SECRET_OTX_API_KEY")
        print("  - ThreatFox: SHL_SECRET_THREATFOX_API_KEY")
        print("  - CIRCL (no key): www.circl.lu in SHL_TI_ALLOWED_DOMAINS")
        print("  - Publisher reports: SHL_TI_PUBLISHER_DOMAINS non-empty")
        print(
            "    + SHL_SECRET_SEARCH_API_KEY + SHL_SECRET_SEARCH_ENGINE_ID + gateway key"
        )
        print("Keys are entered in the Configuration screen or in .env.")
        return 1

    names = [source.name for source in connector._sources]
    print(f"Active sources: {', '.join(names)}")
    print(f"Search: '{campaign}'\n")

    try:
        iocs, dropped = await connector.search(campaign, max_results=30)
    except ToolError as error:
        print(f"[FAILED] {error.code.value}: {error}")
        if error.hint:
            print(f"        {error.hint}")
        return 1
    finally:
        if gateway:
            await gateway.aclose()

    if not iocs:
        print("No IOC returned. Try another name (actor, malware, ThreatFox tag).")
    for ioc in iocs:
        value = ioc.value if len(ioc.value) <= 60 else ioc.value[:57] + "..."
        confidence = f" ({ioc.confidence})" if ioc.confidence else ""
        print(f"  {ioc.type.value:<12} {value:<62} {ioc.source_name}{confidence}")
        print(f"  {'':<12} source: {ioc.source_url}")

    print(f"\n{len(iocs)} IOCs kept, {len(dropped)} discarded without a citable source.")
    print("Each IOC above would arrive with status pending_validation:")
    print("none can feed a SIEM query without analyst validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
