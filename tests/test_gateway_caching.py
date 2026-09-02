"""Prompt caching on the AI gateway client side: prefix marking, cache parsing, counting.

The caching gain plays out on the input re-sent at each iteration. These tests lock down the
three links: the request marks the stable prefix, the response is parsed against the two
gateway conventions, and the cost budget does not count a re-read context as new work.
"""

import json

import httpx

from middleware.budgets import HuntBudget
from middleware.config import Budgets
from orchestrator.gateway import GatewayClient, Usage, _parse_usage, _with_cache_control


def _completion_payload(usage: dict) -> dict:
    return {
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "usage": usage,
    }


class TestUsageBilling:
    def test_raw_total_ignores_cache(self):
        usage = Usage(prompt_tokens=1000, completion_tokens=200, cache_read_tokens=900)
        assert usage.total == 1200

    def test_cache_reads_are_billed_a_fraction(self):
        usage = Usage(prompt_tokens=1000, completion_tokens=200, cache_read_tokens=900)
        # 100 full input + 900 re-read at 0.1 + 200 output = 390
        assert usage.billable_tokens(cache_read_ratio=0.1) == 390

    def test_cache_writes_carry_a_premium(self):
        usage = Usage(prompt_tokens=1000, completion_tokens=0, cache_creation_tokens=400)
        # 600 full input + 400 written at 1.25 = 1100
        assert usage.billable_tokens(cache_write_ratio=1.25) == 1100

    def test_without_cache_billable_equals_total(self):
        usage = Usage(prompt_tokens=800, completion_tokens=150)
        assert usage.billable_tokens() == usage.total


class TestUsageParsing:
    def test_openai_convention_cached_tokens_is_a_subset(self):
        usage = _parse_usage(
            {
                "prompt_tokens": 1000,
                "completion_tokens": 200,
                "prompt_tokens_details": {"cached_tokens": 900},
            }
        )
        assert usage.prompt_tokens == 1000
        assert usage.cache_read_tokens == 900
        assert usage.cache_creation_tokens == 0

    def test_native_cache_fields_are_folded_into_prompt(self):
        usage = _parse_usage(
            {
                "input_tokens": 100,
                "completion_tokens": 200,
                "cache_read_input_tokens": 800,
                "cache_creation_input_tokens": 100,
            }
        )
        assert usage.prompt_tokens == 1000
        assert usage.cache_read_tokens == 800
        assert usage.cache_creation_tokens == 100
        assert usage.completion_tokens == 200

    def test_absent_usage_is_zeroed(self):
        usage = _parse_usage({})
        assert usage.total == 0
        assert usage.cache_read_tokens == 0


class TestCacheControlMarking:
    def test_system_and_last_message_are_marked(self):
        messages = [
            {"role": "system", "content": "instructions"},
            {"role": "user", "content": "briefing"},
            {"role": "tool", "content": "result"},
        ]
        marked = _with_cache_control(messages)

        assert marked[0]["content"][-1]["cache_control"] == {"type": "ephemeral"}
        assert marked[2]["content"][-1]["cache_control"] == {"type": "ephemeral"}
        # An intermediate message is not a cut point.
        assert marked[1]["content"] == "briefing"

    def test_input_is_not_mutated(self):
        messages = [{"role": "system", "content": "instructions"}]
        _with_cache_control(messages)
        assert messages[0]["content"] == "instructions"

    def test_message_without_text_content_is_left_alone(self):
        messages = [
            {"role": "system", "content": "instructions"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "x"}]},
        ]
        marked = _with_cache_control(messages)
        assert "cache_control" not in marked[1]
        assert marked[1]["content"] is None


class TestCompleteRequestShape:
    async def _capture(self, *, prompt_caching):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            payload = _completion_payload({"prompt_tokens": 5, "completion_tokens": 3})
            return httpx.Response(200, json=payload)

        client = GatewayClient(
            base_url="https://gateway.internal/v1",
            api_key="dev",
            transport=httpx.MockTransport(handler),
            prompt_caching=prompt_caching,
        )
        await client.complete(
            model="analysis-model",
            messages=[
                {"role": "system", "content": "instructions"},
                {"role": "user", "content": "briefing"},
            ],
        )
        await client.aclose()
        return captured["body"]

    async def test_markers_present_when_enabled(self):
        body = await self._capture(prompt_caching=True)
        system = body["messages"][0]["content"]
        assert isinstance(system, list)
        assert system[-1]["cache_control"] == {"type": "ephemeral"}

    async def test_no_markers_when_disabled(self):
        body = await self._capture(prompt_caching=False)
        assert body["messages"][0]["content"] == "instructions"


class TestBudgetAccountsForCache:
    def test_cached_context_barely_dents_the_budget(self):
        budget = HuntBudget(limits=Budgets(max_tokens=400_000))
        # Massive context but almost entirely re-read from the cache.
        usage = Usage(prompt_tokens=380_000, completion_tokens=2_000, cache_read_tokens=370_000)

        budget.consume_tokens(
            usage.billable_tokens(
                cache_read_ratio=budget.limits.cache_read_cost_ratio,
                cache_write_ratio=budget.limits.cache_write_cost_ratio,
            )
        )

        # 10,000 full input + 370,000 at 0.1 + 2,000 output = 49,000, far below the cap.
        assert budget.tokens == 49_000
        assert budget.tokens < usage.total
