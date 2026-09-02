"""Playbook: model proposal via forced call, estimate computed by the code."""

import json

import pytest

from middleware.errors import ErrorCode, ToolError
from orchestrator.gateway import Completion, ToolCall, Usage
from orchestrator.planning import (
    PLATFORM_CAP,
    estimate_iterations,
    playbook_tool_schema,
    propose_playbook,
)
from orchestrator.prompts import hunt_briefing


class FakeGateway:
    def __init__(self, completion):
        self.completion = completion
        self.calls = []

    async def complete(self, *, model, messages, tools=None, **kwargs):
        self.calls.append({"model": model, "messages": messages, "tools": tools})
        return self.completion


def _proposal(**overrides):
    arguments = {
        "summary": "Look for remote WMI executions then correlate with the connections.",
        "steps": [
            {
                "order": 2,
                "siem": "sentinel",
                "objective": "Correlate type 3 network connections around the executions",
                "expected_queries": 3,
            },
            {
                "order": 1,
                "siem": "defender",
                "objective": "Spot wmic process call create with /node",
                "technique": "T1047",
                "expected_queries": 4,
            },
        ],
        "not_covered": "Scheduled persistence is not covered for lack of a source.",
    }
    arguments.update(overrides)
    return Completion(
        content="",
        tool_calls=[
            ToolCall(
                id="c1",
                name="propose_playbook",
                arguments=arguments,
                raw_arguments=json.dumps(arguments),
            )
        ],
        usage=Usage(10, 10),
    )


class TestProposePlaybook:
    async def test_steps_are_ordered_and_estimates_computed_by_code(self):
        gateway = FakeGateway(_proposal())
        playbook = await propose_playbook(
            gateway,
            model="analysis",
            briefing="# Briefing",
            available_sources=["sentinel", "defender"],
            instruction="  ignore SecOps  ",
        )

        assert [step.order for step in playbook.steps] == [1, 2]
        assert playbook.steps[0].siem == "defender"
        assert playbook.estimated_queries == 7
        assert playbook.estimated_iterations == estimate_iterations(7)
        assert playbook.instruction == "ignore SecOps"
        assert playbook.validated_by is None

        call = gateway.calls[0]
        assert call["model"] == "analysis"
        assert call["tools"][0]["function"]["name"] == "propose_playbook"
        assert "ignore SecOps" in call["messages"][1]["content"]
        assert "<analyst_instruction>" in call["messages"][1]["content"]

    async def test_source_enum_is_closed_to_available_sources(self):
        schema = playbook_tool_schema(["secops"])
        siem = schema["function"]["parameters"]["properties"]["steps"]["items"]["properties"][
            "siem"
        ]
        assert siem["enum"] == ["secops"]

        gateway = FakeGateway(_proposal())
        with pytest.raises(ToolError) as excinfo:
            await propose_playbook(gateway, model="m", briefing="b", available_sources=["secops"])
        assert excinfo.value.code is ErrorCode.SCHEMA_INVALID

    async def test_no_tool_call_is_an_upstream_error(self):
        gateway = FakeGateway(Completion(content="I don't know", usage=Usage(1, 1)))
        with pytest.raises(ToolError) as excinfo:
            await propose_playbook(gateway, model="m", briefing="b", available_sources=["sentinel"])
        assert excinfo.value.code is ErrorCode.UPSTREAM_UNAVAILABLE

    async def test_empty_plan_is_refused(self):
        gateway = FakeGateway(_proposal(steps=[]))
        with pytest.raises(ToolError) as excinfo:
            await propose_playbook(gateway, model="m", briefing="b", available_sources=["sentinel"])
        assert excinfo.value.code is ErrorCode.SCHEMA_INVALID

    async def test_no_source_means_no_plan(self):
        with pytest.raises(ToolError):
            await propose_playbook(
                FakeGateway(_proposal()), model="m", briefing="b", available_sources=[]
            )

    async def test_verbose_objective_is_clipped_not_rejected(self):
        gateway = FakeGateway(
            _proposal(
                steps=[
                    {
                        "order": 1,
                        "siem": "sentinel",
                        "objective": "Look for connections. " * 40,
                        "technique": "T1047/T1059",
                        "expected_queries": 2,
                    }
                ]
            )
        )
        playbook = await propose_playbook(
            gateway, model="m", briefing="b", available_sources=["sentinel"]
        )
        assert len(playbook.steps[0].objective) <= 400
        assert playbook.steps[0].objective.endswith("…")
        assert playbook.steps[0].technique is None

    def test_iterations_never_exceed_the_platform_cap(self):
        assert estimate_iterations(1) == 4
        assert estimate_iterations(10) == 14
        assert estimate_iterations(PLATFORM_CAP) == PLATFORM_CAP


class TestBriefingCarriesTheResume:
    def test_resume_context_is_injected_before_the_playbook(self):
        briefing = hunt_briefing(
            hypothesis="Lateral movement via WMI",
            campaign=None,
            iocs_summary=[],
            available_sources=["defender"],
            budgets={"max_iterations": 10, "max_siem_queries": 7, "max_duration_seconds": 900},
            resume_context="Resuming hunt hunt_abc.\n### Queries already executed",
        )
        assert "## Resuming a previous hunt" in briefing
        assert "Resuming hunt hunt_abc." in briefing
        assert "do not replay these queries identically" in briefing


class TestBriefingCarriesThePlaybook:
    def test_validated_plan_is_spelled_out_to_the_agent(self):
        briefing = hunt_briefing(
            hypothesis="Lateral movement via WMI",
            campaign=None,
            iocs_summary=[],
            available_sources=["defender"],
            budgets={"max_iterations": 10, "max_siem_queries": 7, "max_duration_seconds": 900},
            playbook={
                "summary": "Look for remote WMI.",
                "steps": [
                    {
                        "order": 1,
                        "siem": "defender",
                        "objective": "Spot wmic /node",
                        "technique": "T1047",
                        "expected_queries": 4,
                    }
                ],
                "not_covered": "Persistence.",
            },
        )
        assert "## Playbook validated by the analyst" in briefing
        assert "1. [defender] Spot wmic /node (T1047) — 4 planned query(ies)" in briefing
        assert "Announced out of scope: Persistence." in briefing
        assert "Follow this plan in order" in briefing


class TestHashAlgorithms:
    def test_briefing_labels_each_hash_and_warns_on_mixed_algorithms(self):
        briefing = hunt_briefing(
            hypothesis="Astaroth hunt",
            campaign="Astaroth",
            iocs_summary=[
                {"value": "a" * 64, "type": "hash", "algo": "sha256", "source": "publisher"},
                {"value": "b" * 40, "type": "hash", "algo": "sha1", "source": "publisher"},
                {"value": "evil.example", "type": "domain", "algo": None, "source": "publisher"},
            ],
            available_sources=["defender"],
            budgets={"max_iterations": 10, "max_siem_queries": 7, "max_duration_seconds": 900},
        )
        assert f"`{'a' * 64}` (hash sha256)" in briefing
        assert f"`{'b' * 40}` (hash sha1)" in briefing
        assert "(domain)" in briefing
        assert "several algorithms (sha1, sha256)" in briefing
        assert "will never match" in briefing

    def test_single_algorithm_needs_no_warning(self):
        briefing = hunt_briefing(
            hypothesis="Hunt",
            campaign=None,
            iocs_summary=[
                {"value": "a" * 64, "type": "hash", "algo": "sha256", "source": "publisher"}
            ],
            available_sources=["defender"],
            budgets={"max_iterations": 10, "max_siem_queries": 7, "max_duration_seconds": 900},
        )
        assert "several algorithms" not in briefing

    def test_algorithm_is_deduced_from_length(self):
        from middleware.guardrails.ioc import hash_algorithm

        assert hash_algorithm("A" * 32) == "md5"
        assert hash_algorithm("b" * 40) == "sha1"
        assert hash_algorithm("c" * 64) == "sha256"
        assert hash_algorithm("evil.example") is None
        assert hash_algorithm("c" * 63) is None
