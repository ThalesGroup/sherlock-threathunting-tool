"""Verification of the gateway key, without touching the SIEMs or the threat intelligence.

Four checks, in the order the platform depends on them:

1. the query generation model responds;
2. the analysis model responds;
3. function calling works (the whole agentic loop relies on it);
4. prompt caching is active or not (informative: its absence blocks nothing).

Usage: .venv/bin/python scripts/smoke_gateway.py
The key is never displayed.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from middleware.config import Settings  # noqa: E402
from middleware.errors import ToolError  # noqa: E402
from middleware.secrets import build_secret_provider  # noqa: E402
from orchestrator.gateway import GatewayClient  # noqa: E402

PING_TOOL = [
    {
        "type": "function",
        "function": {
            "name": "ping",
            "description": "Responds to a link check.",
            "parameters": {
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
                "additionalProperties": False,
            },
        },
    }
]

_STABLE_PREFIX = (
    "You are the verification agent of a threat hunting platform. "
    "This text exists solely to exceed the minimum caching threshold. "
) * 60


def load_dotenv(path: Path) -> None:
    """Loads .env into the process environment, for the non-secret config. The keys,
    however, come from the encrypted store then from .env, via `build_secret_provider`."""

    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def ok(label: str, detail: str = "") -> None:
    print(f"  [ok] {label}" + (f" - {detail}" if detail else ""))


def ko(label: str, detail: str = "") -> None:
    print(f"  [FAILED] {label}" + (f" - {detail}" if detail else ""))


async def main() -> int:
    load_dotenv(Path(".env"))
    settings = Settings()

    print("Configuration:")
    if not settings.gateway_base_url:
        ko("SHL_GATEWAY_BASE_URL is empty", "set the gateway URL in .env")
        return 1
    ok("gateway", settings.gateway_base_url)

    secrets = build_secret_provider(settings)
    api_key = secrets.get_optional("GATEWAY_API_KEY")
    if not api_key:
        ko("gateway key missing", "enter it in the Configuration screen or in .env")
        return 1
    origin = secrets.origin("GATEWAY_API_KEY")
    ok("key present", f"{len(api_key)} characters, source: {origin}")

    client = GatewayClient(
        base_url=settings.gateway_base_url,
        api_key=api_key,
        prompt_caching=settings.gateway_prompt_caching,
    )
    failures = 0

    try:
        for label, model in (
            ("query model", settings.gateway_model_query),
            ("analysis model", settings.gateway_model_analysis),
        ):
            print(f"\nTest: {label} ({model})")
            try:
                completion = await client.complete(
                    model=model,
                    messages=[{"role": "user", "content": "Reply exactly: OK"}],
                    max_tokens=16,
                )
                usage = completion.usage
                ok(
                    "response received",
                    f"'{completion.content.strip()[:40]}' - "
                    f"{usage.prompt_tokens} in / {usage.completion_tokens} out",
                )
            except ToolError as error:
                ko("call refused", f"{error.code.value}: {error}")
                failures += 1

        print("\nTest: function calling")
        try:
            completion = await client.complete(
                model=settings.gateway_model_query,
                messages=[
                    {
                        "role": "user",
                        "content": "Call the ping tool with message='pong'.",
                    }
                ],
                tools=PING_TOOL,
                max_tokens=128,
            )
            call = completion.tool_calls[0] if completion.tool_calls else None
            if call and call.name == "ping" and call.arguments_valid:
                ok("tool called", f"ping({call.arguments})")
            else:
                ko(
                    "no usable tool call",
                    "the agentic loop will not work on this gateway",
                )
                failures += 1
        except ToolError as error:
            ko("call refused", f"{error.code.value}: {error}")
            failures += 1

        print("\nTest: prompt caching (informative)")
        try:
            messages = [
                {"role": "system", "content": _STABLE_PREFIX},
                {"role": "user", "content": "Reply exactly: OK"},
            ]
            first = await client.complete(
                model=settings.gateway_model_query, messages=messages, max_tokens=16
            )
            second = await client.complete(
                model=settings.gateway_model_query, messages=messages, max_tokens=16
            )
            created = first.usage.cache_creation_tokens
            read = second.usage.cache_read_tokens
            if read:
                ok("cache active", f"{created} tokens written then {read} reread at reduced rate")
            else:
                print(
                    "  [info] no cache token reported: the gateway does not relay "
                    "the counters, or caching is inactive. The hunts will work, "
                    "at full rate."
                )
        except ToolError as error:
            print(f"  [info] cache test not possible ({error.code.value})")
    finally:
        await client.aclose()

    print()
    if failures:
        print(f"Summary: {failures} check(s) failed.")
        return 1
    print("Summary: the gateway key is operational for the platform.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
