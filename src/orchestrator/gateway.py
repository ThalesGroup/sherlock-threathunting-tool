"""AI gateway client (OpenAI-compatible interface, native function calling).

Single access point to the AI gateway models. No other module talks to the
reasoning engine, and nothing that transits here leaves the internal scope.

Message content is never logged in clear text by this module: the audit log
records decisions and queries, not the raw exchanges.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from middleware.clients.base import outbound_verify, scrub_secrets
from middleware.errors import ErrorCode, ToolError

logger = logging.getLogger("shl.gateway")

_DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=180.0, write=15.0, pool=5.0)


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    arguments_valid: bool = True
    raw_arguments: str = ""


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    @property
    def total(self) -> int:
        """Raw token count, cache included. Does not reflect cost."""

        return self.prompt_tokens + self.completion_tokens

    def billable_tokens(
        self, *, cache_read_ratio: float = 0.1, cache_write_ratio: float = 1.25
    ) -> int:
        """Tokens weighted by their actual cost.

        `cache_read_tokens` and `cache_creation_tokens` are subsets of
        `prompt_tokens`. A token re-read from the cache costs a fraction of full price
        (`cache_read_ratio`); a token written to the cache carries a one-time premium
        (`cache_write_ratio`). Used for the cost budget: a resent context is not counted
        as new work.
        """

        cached = self.cache_read_tokens + self.cache_creation_tokens
        uncached_input = max(0, self.prompt_tokens - cached)
        weighted = (
            uncached_input
            + self.cache_read_tokens * cache_read_ratio
            + self.cache_creation_tokens * cache_write_ratio
            + self.completion_tokens
        )
        return int(round(weighted))


@dataclass
class Completion:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    finish_reason: str = "stop"
    raw_message: dict[str, Any] = field(default_factory=dict)


class GatewayClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
        prompt_caching: bool = False,
        trust_proxy_env: bool = False,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._prompt_caching = prompt_caching
        self._client = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            trust_env=trust_proxy_env,
            verify=outbound_verify(),
        )
        """The gateway is internal: by default, the client ignores the internet egress
        proxy (`https_proxy`), which usually cannot reach a private host."""

    async def aclose(self) -> None:
        await self._client.aclose()

    async def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> Completion:
        body: dict[str, Any] = {
            "model": model,
            "messages": _with_cache_control(messages) if self._prompt_caching else messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        try:
            response = await self._client.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "Gateway unreachable (%s) - %s: %s",
                self._base_url,
                type(exc).__name__,
                scrub_secrets(str(exc)),
            )
            raise ToolError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "AI gateway unreachable.",
            ) from exc

        if response.status_code == 429:
            logger.warning("Gateway: HTTP 429 (quota) - %s", scrub_secrets(response.text))
            raise ToolError(
                ErrorCode.RATE_LIMITED,
                "AI gateway quota reached.",
            )
        if response.status_code >= 400:
            logger.warning(
                "Gateway: HTTP %s on %s (model %s) - %s",
                response.status_code,
                self._base_url,
                model,
                scrub_secrets(response.text),
            )
            raise ToolError(
                ErrorCode.UPSTREAM_REJECTED,
                "Call to the AI gateway refused.",
            )

        return _parse_completion(response.json())


def _parse_completion(payload: dict[str, Any]) -> Completion:
    choices = payload.get("choices") or []
    if not choices:
        raise ToolError(
            ErrorCode.UPSTREAM_UNAVAILABLE,
            "Empty response from the AI gateway.",
        )

    message = choices[0].get("message") or {}

    return Completion(
        content=message.get("content") or "",
        tool_calls=[_parse_tool_call(item) for item in (message.get("tool_calls") or [])],
        usage=_parse_usage(payload.get("usage") or {}),
        finish_reason=choices[0].get("finish_reason") or "stop",
        raw_message=message,
    )


def _parse_usage(usage_payload: dict[str, Any]) -> Usage:
    """Normalizes token counting, cache included, across two gateway conventions.

    OpenAI style: tokens re-read from the cache are a subset of `prompt_tokens`,
    exposed in `prompt_tokens_details.cached_tokens`.
    Provider-native counters: `cache_read_input_tokens` and
    `cache_creation_input_tokens` are
    counted separately from the input; we fold them into `prompt_tokens` to keep a single model
    where both cache counters are subsets of `prompt_tokens`.
    """

    prompt = int(usage_payload.get("prompt_tokens") or 0)
    completion = int(usage_payload.get("completion_tokens") or 0)

    details = usage_payload.get("prompt_tokens_details") or {}
    cache_read = int(details.get("cached_tokens") or 0)
    cache_creation = 0

    native_read = int(usage_payload.get("cache_read_input_tokens") or 0)
    native_creation = int(usage_payload.get("cache_creation_input_tokens") or 0)
    if native_read or native_creation:
        base_input = int(usage_payload.get("input_tokens") or prompt)
        prompt = base_input + native_read + native_creation
        cache_read = native_read
        cache_creation = native_creation

    return Usage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        cache_read_tokens=cache_read,
        cache_creation_tokens=cache_creation,
    )


_CACHE_CONTROL = {"type": "ephemeral"}


def _with_cache_control(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Marks the stable prompt prefix as cacheable, without mutating the input.

    Two cut points suffice: the system header, invariant over the whole hunt, and the
    last message, which advances the cache window at each turn. The provider reuses
    the longest prefix already seen and only re-bills the delta at full price.
    """

    if not messages:
        return messages

    marked = [dict(message) for message in messages]
    targets = {len(marked) - 1}
    system_index = next(
        (index for index, message in enumerate(marked) if message.get("role") == "system"),
        None,
    )
    if system_index is not None:
        targets.add(system_index)

    for index in targets:
        _mark_message(marked[index])
    return marked


def _mark_message(message: dict[str, Any]) -> None:
    """Sets a cache marker on the last content block of the message.

    The block format (`content` as a list) is what an OpenAI-compatible gateway
    relaying to the model provider expects. A message with no text content (tool
    call only) is not
    a cut point and is left as is.
    """

    content = message.get("content")
    if isinstance(content, str) and content:
        message["content"] = [
            {"type": "text", "text": content, "cache_control": dict(_CACHE_CONTROL)}
        ]
    elif isinstance(content, list) and content:
        block = dict(content[-1])
        block["cache_control"] = dict(_CACHE_CONTROL)
        message["content"] = [*content[:-1], block]


def _parse_tool_call(item: dict[str, Any]) -> ToolCall:
    """Converts a tool call without ever trusting its payload.

    Unreadable arguments are not a fatal error: they are marked invalid and
    the orchestrator returns a schema error to the model, which can correct it.
    """

    function = item.get("function") or {}
    raw_arguments = function.get("arguments") or "{}"
    try:
        parsed = json.loads(raw_arguments)
        valid = isinstance(parsed, dict)
    except (json.JSONDecodeError, TypeError):
        parsed, valid = {}, False

    return ToolCall(
        id=str(item.get("id") or ""),
        name=str(function.get("name") or ""),
        arguments=parsed if valid else {},
        arguments_valid=valid,
        raw_arguments=raw_arguments if isinstance(raw_arguments, str) else "",
    )
