import json

import pytest

from middleware.audit import AuditEventType, AuditJournal, MemoryAuditSink
from middleware.budgets import HuntBudget
from middleware.clients.results import QueryOutcome
from middleware.config import Budgets, Settings
from middleware.errors import ErrorCode
from middleware.executor import QueryLedger, SiemExecutor
from middleware.guardrails.ioc import Ioc, IocStatus, IocType
from orchestrator.events import EventStream, HuntEventType
from orchestrator.gateway import Completion, ToolCall, Usage
from orchestrator.loop import HuntOrchestrator
from reporting.dossier import Dossier
from reporting.models import HuntStatus, Verdict
from reporting.report import to_markdown


class FakeGateway:
    """Replays a sequence of scripted responses and records what was sent to it."""

    def __init__(self, completions):
        self._completions = list(completions)
        self.calls = []

    async def complete(self, *, model, messages, tools, **kwargs):
        self.calls.append({"model": model, "messages": list(messages), "tools": tools})
        if not self._completions:
            return Completion(content="", usage=Usage(10, 10))
        return self._completions.pop(0)


class FakeSentinel:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else [{"Account": "svc-backup"}]

    async def run_query(self, *, query, workspace_id, timespan_days, row_cap):
        return QueryOutcome(rows=self.rows, duration_ms=7)


def tool_call(name, arguments, call_id="call_1"):
    return ToolCall(
        id=call_id,
        name=name,
        arguments=arguments,
        raw_arguments=json.dumps(arguments),
    )


def build(
    completions,
    *,
    budgets=None,
    iocs=None,
    sentinel=None,
    model="analysis-model",
    analysis_model=None,
    budget_pause_timeout=0.0,
):
    sink = MemoryAuditSink()
    journal = AuditJournal(sink, hunt_id="hunt_1", actor="j.doe")
    ledger = QueryLedger()
    settings = Settings(_env_file=None, workspace_aliases={"soc": "guid-real"})
    budget = HuntBudget(limits=budgets or Budgets())
    executor = SiemExecutor(
        settings=settings,
        journal=journal,
        budget=budget,
        ledger=ledger,
        sentinel=sentinel or FakeSentinel(),
        limiters={},
    )
    dossier = Dossier(
        hunt_id="hunt_1",
        hypothesis="Living off the land activity on the backup servers",
        analyst="j.doe",
        campaign="Volt Typhoon",
    )
    dossier.ledger = ledger
    dossier.iocs = iocs or []
    executor.set_iocs(dossier.iocs)

    from tools.definitions import build_registry

    registry = build_registry(executor=executor, dossier=dossier, journal=journal)
    stream = EventStream("hunt_1")
    orchestrator = HuntOrchestrator(
        dossier=dossier,
        registry=registry,
        journal=journal,
        budget=budget,
        stream=stream,
        gateway=FakeGateway(completions),
        model=model,
        analysis_model=analysis_model,
        available_sources=["sentinel"],
        budget_pause_timeout=budget_pause_timeout,
    )
    return orchestrator, dossier, stream, sink, budget


def event_types(stream):
    return [event.type for event in stream.history]


NOMINAL = [
    Completion(
        content="I'm starting with the backup account's connections.",
        tool_calls=[
            tool_call(
                "run_sentinel_kql",
                {
                    "kql_query": "SigninLogs",
                    "workspace": "soc",
                    "intent": "Service account connections over the period",
                },
            )
        ],
        usage=Usage(1000, 200),
    ),
    Completion(
        content="Three off-hours connections, I'm recording it.",
        tool_calls=[
            tool_call(
                "record_finding",
                {
                    "title": "Off-hours connections",
                    "description": "The backup account connects at 3 AM.",
                    "severity": "medium",
                    "confidence": "medium",
                    "evidence_query_ids": ["__PLACEHOLDER__"],
                },
                call_id="call_2",
            )
        ],
        usage=Usage(1200, 250),
    ),
    Completion(
        content="I'm concluding.",
        tool_calls=[
            tool_call(
                "conclude_hunt",
                {
                    "verdict": "suspicious",
                    "summary": "The backup account shows nighttime connections.",
                    "limitations": "Defender not queried, window limited to 7 days.",
                },
                call_id="call_3",
            )
        ],
        usage=Usage(1300, 300),
    ),
]


class TestNominalRun:
    async def test_full_hunt_produces_a_report(self):
        orchestrator, dossier, stream, sink, _ = build(NOMINAL)

        outcome = await orchestrator.run()

        assert outcome.interrupted is False
        assert outcome.report.proposed_verdict is Verdict.SUSPICIOUS
        assert dossier.status is HuntStatus.AWAITING_REVIEW
        assert len(outcome.report.executed_queries) == 1
        assert outcome.report.limitations

    async def test_investigation_thread_is_published(self):
        orchestrator, _, stream, _, _ = build(NOMINAL)

        await orchestrator.run()

        types = event_types(stream)
        assert types[0] is HuntEventType.HUNT_STARTED
        assert HuntEventType.AGENT_REASONING in types
        assert HuntEventType.TOOL_CALL in types
        assert HuntEventType.TOOL_RESULT in types
        assert types[-1] is HuntEventType.CONCLUDED
        assert stream.closed is True

    async def test_executed_query_is_shown_with_the_platform_cap(self):
        orchestrator, _, stream, _, _ = build(NOMINAL)

        await orchestrator.run()

        results = [e for e in stream.history if e.type is HuntEventType.TOOL_RESULT]
        assert results[0].payload["executed_query"].strip().endswith("take 500")

    async def test_every_query_is_audited(self):
        orchestrator, _, _, sink, _ = build(NOMINAL)

        await orchestrator.run()

        executed = [e for e in sink.events if e.type is AuditEventType.QUERY_EXECUTED]
        assert len(executed) == 1
        assert executed[0].query
        assert executed[0].rows_returned == 1

    async def test_model_receives_wrapped_untrusted_data(self):
        orchestrator, _, _, _, _ = build(NOMINAL)

        await orchestrator.run()

        tool_messages = [
            message
            for call in orchestrator._gateway.calls
            for message in call["messages"]
            if message.get("role") == "tool"
        ]
        assert tool_messages
        assert "untrusted_data" in tool_messages[0]["content"]


class TestBudgetStop:
    async def test_iteration_budget_produces_a_partial_report(self):
        looping = [
            Completion(
                content="I'm continuing.",
                tool_calls=[
                    tool_call(
                        "run_sentinel_kql",
                        {
                            "kql_query": "SigninLogs",
                            "workspace": "soc",
                            "intent": "Service account connections over the period",
                        },
                    )
                ],
                usage=Usage(100, 50),
            )
        ] * 10
        orchestrator, dossier, stream, sink, _ = build(
            looping, budgets=Budgets(max_iterations=3, max_siem_queries=99)
        )

        outcome = await orchestrator.run()

        assert outcome.interrupted is True
        assert "budget exhausted" in outcome.reason
        assert outcome.report.partial is True
        assert outcome.report.proposed_verdict is Verdict.INCONCLUSIVE
        assert dossier.status is HuntStatus.INTERRUPTED
        assert HuntEventType.INTERRUPTED in event_types(stream)
        assert any(e.type is AuditEventType.HUNT_INTERRUPTED for e in sink.events)

    async def test_partial_report_states_what_was_not_covered(self):
        orchestrator, _, _, _, _ = build(
            [Completion(content="...", usage=Usage(10, 10))] * 5,
            budgets=Budgets(max_iterations=2),
        )

        outcome = await orchestrator.run()

        assert "Investigation interrupted" in outcome.report.limitations

    async def test_token_alert_is_published(self):
        completions = [
            Completion(
                content="analysis",
                tool_calls=[
                    tool_call(
                        "conclude_hunt",
                        {
                            "verdict": "benign",
                            "summary": "No signal detected over the analyzed period.",
                            "limitations": "Seven-day window only.",
                        },
                    )
                ],
                usage=Usage(900, 0),
            )
        ]
        orchestrator, _, stream, _, _ = build(completions, budgets=Budgets(max_tokens=1000))

        await orchestrator.run()

        assert HuntEventType.BUDGET_ALERT in event_types(stream)


class TestBudgetCheckpoint:
    """Budget exhaustion with an active checkpoint: the hunt waits for the analyst's
    decision. Extension = resume with memory intact; stop or timeout = partial report,
    as before."""

    def _looping(self, count):
        return [
            Completion(
                content="I'm continuing.",
                tool_calls=[
                    tool_call(
                        "run_sentinel_kql",
                        {
                            "kql_query": "SigninLogs",
                            "workspace": "soc",
                            "intent": "Service account connections over the period",
                        },
                    )
                ],
                usage=Usage(100, 50),
            )
        ] * count + [
            Completion(
                content="I'm concluding.",
                tool_calls=[
                    tool_call(
                        "conclude_hunt",
                        {
                            "verdict": "benign",
                            "summary": "Nothing abnormal over the window explored in detail.",
                            "limitations": "Partial coverage of the sources.",
                        },
                        call_id="call_fin",
                    )
                ],
                usage=Usage(50, 20),
            )
        ]

    async def test_extension_resumes_the_hunt(self):
        import asyncio

        orchestrator, dossier, stream, sink, budget = build(
            self._looping(3),
            budgets=Budgets(max_iterations=2, max_siem_queries=99),
            budget_pause_timeout=5.0,
        )

        async def analyst():
            for _ in range(200):
                await asyncio.sleep(0.01)
                if orchestrator.awaiting_budget_decision:
                    budget.extend(extra_iterations=10)
                    orchestrator.resolve_budget(extend=True)
                    return
            raise AssertionError("the budget checkpoint was never reached")

        outcome, _ = await asyncio.gather(orchestrator.run(), analyst())

        assert outcome.interrupted is False
        assert outcome.report.partial is False
        types = event_types(stream)
        assert HuntEventType.BUDGET_PAUSED in types
        assert HuntEventType.BUDGET_EXTENDED in types
        assert any(
            e.type is AuditEventType.BUDGET_EVENT and e.detail.get("action") == "pause"
            for e in sink.events
        )

    async def test_token_exhaustion_pauses_and_an_extension_resumes(self):
        import asyncio

        orchestrator, dossier, stream, sink, budget = build(
            self._looping(1),
            budgets=Budgets(max_iterations=99, max_siem_queries=99, max_tokens=120),
            budget_pause_timeout=5.0,
        )

        async def analyst():
            for _ in range(200):
                await asyncio.sleep(0.01)
                if orchestrator.awaiting_budget_decision:
                    budget.extend(extra_tokens=10_000)
                    orchestrator.resolve_budget(extend=True)
                    return
            raise AssertionError("the token checkpoint was never reached")

        outcome, _ = await asyncio.gather(orchestrator.run(), analyst())

        assert outcome.interrupted is False, outcome.reason
        paused = [e for e in stream.history if e.type is HuntEventType.BUDGET_PAUSED]
        assert paused and paused[0].payload["budget"] == "tokens"
        assert budget.limits.max_tokens >= 10_120

    async def test_stop_decision_produces_a_partial_report(self):
        import asyncio

        orchestrator, dossier, stream, _, _ = build(
            self._looping(5),
            budgets=Budgets(max_iterations=2, max_siem_queries=99),
            budget_pause_timeout=5.0,
        )

        async def analyst():
            for _ in range(200):
                await asyncio.sleep(0.01)
                if orchestrator.awaiting_budget_decision:
                    orchestrator.resolve_budget(extend=False)
                    return
            raise AssertionError("the budget checkpoint was never reached")

        outcome, _ = await asyncio.gather(orchestrator.run(), analyst())

        assert outcome.interrupted is True
        assert "budget exhausted" in outcome.reason
        assert outcome.report.partial is True

    async def test_timeout_falls_back_to_partial_report(self):
        orchestrator, _, stream, sink, _ = build(
            self._looping(5),
            budgets=Budgets(max_iterations=2, max_siem_queries=99),
            budget_pause_timeout=0.05,
        )

        outcome = await orchestrator.run()

        assert outcome.interrupted is True
        assert outcome.report.partial is True
        assert HuntEventType.BUDGET_PAUSED in event_types(stream)
        assert any(
            e.type is AuditEventType.BUDGET_EVENT and e.detail.get("action") == "timeout expired"
            for e in sink.events
        )

    async def test_mid_tool_call_exhaustion_keeps_the_conversation_valid(self):
        """Exhaustion during a tool call must leave a response for every call in the
        turn: after extension, the conversation resumes with no orphan call."""

        import asyncio

        orchestrator, _, _, _, budget = build(
            self._looping(3),
            budgets=Budgets(max_iterations=99, max_siem_queries=2),
            budget_pause_timeout=5.0,
        )

        async def analyst():
            for _ in range(200):
                await asyncio.sleep(0.01)
                if orchestrator.awaiting_budget_decision:
                    budget.extend(extra_siem_queries=10)
                    orchestrator.resolve_budget(extend=True)
                    return
            raise AssertionError("the budget checkpoint was never reached")

        outcome, _ = await asyncio.gather(orchestrator.run(), analyst())

        assert outcome.interrupted is False
        messages = orchestrator._messages
        for message in messages:
            if message.get("role") == "assistant" and message.get("tool_calls"):
                for call in message["tool_calls"]:
                    answered = any(
                        m.get("role") == "tool" and m.get("tool_call_id") == call["id"]
                        for m in messages
                    )
                    assert answered, f"call without response: {call['id']}"


class TestAnalystStop:
    async def test_stop_button_produces_a_report_not_an_empty_screen(self):
        orchestrator, dossier, stream, _, _ = build(NOMINAL)
        orchestrator.request_stop()

        outcome = await orchestrator.run()

        assert outcome.interrupted is True
        assert "analyst" in outcome.reason
        assert outcome.report.hunt_id == "hunt_1"
        assert HuntEventType.CONCLUDED in event_types(stream)


class TestToolErrorsAreRecoverable:
    async def test_unsourced_indicator_is_reported_to_the_model_without_stopping(self):
        completions = [
            Completion(
                content="I'm testing a domain.",
                tool_calls=[
                    tool_call(
                        "run_sentinel_kql",
                        {
                            "kql_query": (
                                'DeviceNetworkEvents | where RemoteUrl has "made-up.example"'
                            ),
                            "workspace": "soc",
                            "intent": "Service account connections over the period",
                        },
                    )
                ],
                usage=Usage(100, 50),
            ),
            Completion(
                content="Refused, I fall back to behavioral analysis and conclude.",
                tool_calls=[
                    tool_call(
                        "conclude_hunt",
                        {
                            "verdict": "inconclusive",
                            "summary": "No usable element over the analyzed window.",
                            "limitations": "Indicator not validated, lead abandoned.",
                        },
                        call_id="call_2",
                    )
                ],
                usage=Usage(120, 60),
            ),
        ]
        orchestrator, _, stream, _, _ = build(completions)

        outcome = await orchestrator.run()

        errors = [e for e in stream.history if e.type is HuntEventType.TOOL_ERROR]
        assert errors[0].payload["error"] == ErrorCode.IOC_UNSOURCED.value
        assert outcome.interrupted is False

    async def test_invalid_json_arguments_do_not_crash_the_loop(self):
        broken = ToolCall(
            id="call_1",
            name="run_sentinel_kql",
            arguments={},
            arguments_valid=False,
            raw_arguments="{this is not json",
        )
        completions = [
            Completion(content="oops", tool_calls=[broken], usage=Usage(10, 10)),
            Completion(
                content="I'm concluding",
                tool_calls=[
                    tool_call(
                        "conclude_hunt",
                        {
                            "verdict": "inconclusive",
                            "summary": "Investigation with no usable result at this stage.",
                            "limitations": "No query succeeded.",
                        },
                        call_id="call_2",
                    )
                ],
                usage=Usage(10, 10),
            ),
        ]
        orchestrator, _, stream, _, _ = build(completions)

        outcome = await orchestrator.run()

        errors = [e for e in stream.history if e.type is HuntEventType.TOOL_ERROR]
        assert errors[0].payload["error"] == ErrorCode.SCHEMA_INVALID.value
        assert outcome.interrupted is False


class TestSilentAgent:
    async def test_agent_that_never_calls_a_tool_is_stopped(self):
        orchestrator, _, _, _, _ = build(
            [Completion(content="I'm thinking", usage=Usage(10, 10))] * 5
        )

        outcome = await orchestrator.run()

        assert outcome.interrupted is True
        assert "did not conclude" in outcome.reason


class TestIocCheckpointFromTheLoop:
    async def test_pending_ioc_blocks_the_agent_even_mid_hunt(self):
        pending = Ioc(
            value="evil.example",
            type=IocType.DOMAIN,
            source_name="VirusTotal",
            source_url="https://www.virustotal.com/gui/x",
        )
        completions = [
            Completion(
                content="I'm querying.",
                tool_calls=[
                    tool_call(
                        "run_sentinel_kql",
                        {
                            "kql_query": "SigninLogs",
                            "workspace": "soc",
                            "intent": "Service account connections over the period",
                        },
                    )
                ],
                usage=Usage(10, 10),
            ),
            Completion(
                content="Blocked, I'm concluding.",
                tool_calls=[
                    tool_call(
                        "conclude_hunt",
                        {
                            "verdict": "inconclusive",
                            "summary": "Indicators not validated, no query possible.",
                            "limitations": "Validation checkpoint not passed.",
                        },
                        call_id="call_2",
                    )
                ],
                usage=Usage(10, 10),
            ),
        ]
        orchestrator, dossier, stream, _, _ = build(completions, iocs=[pending])

        await orchestrator.run()

        errors = [e for e in stream.history if e.type is HuntEventType.TOOL_ERROR]
        assert errors[0].payload["error"] == ErrorCode.IOC_NOT_VALIDATED.value

    async def test_validated_ioc_lets_the_hunt_proceed(self):
        validated = Ioc(
            value="known.example",
            type=IocType.DOMAIN,
            source_name="VirusTotal",
            source_url="https://www.virustotal.com/gui/x",
            status=IocStatus.VALIDATED,
        )
        completions = [
            Completion(
                content="I'm querying on the validated indicator.",
                tool_calls=[
                    tool_call(
                        "run_sentinel_kql",
                        {
                            "kql_query": (
                                'DeviceNetworkEvents | where RemoteUrl has "known.example"'
                            ),
                            "workspace": "soc",
                            "intent": "Service account connections over the period",
                        },
                    )
                ],
                usage=Usage(10, 10),
            ),
            Completion(
                content="I'm concluding.",
                tool_calls=[
                    tool_call(
                        "conclude_hunt",
                        {
                            "verdict": "benign",
                            "summary": "No contact with the indicator over the window.",
                            "limitations": "Seven-day window only.",
                        },
                        call_id="call_2",
                    )
                ],
                usage=Usage(10, 10),
            ),
        ]
        orchestrator, _, stream, _, _ = build(completions, iocs=[validated])

        outcome = await orchestrator.run()

        assert not [e for e in stream.history if e.type is HuntEventType.TOOL_ERROR]
        assert outcome.report.proposed_verdict is Verdict.BENIGN


class TestMarkdownExport:
    async def test_verdict_is_presented_as_a_proposal(self):
        orchestrator, _, _, _, _ = build(NOMINAL)
        outcome = await orchestrator.run()

        markdown = to_markdown(outcome.report)

        assert "Proposed verdict" in markdown
        assert "proposal" in markdown
        assert "Investigation limitations" in markdown

    async def test_queries_appear_in_the_report(self):
        orchestrator, _, _, _, _ = build(NOMINAL)
        outcome = await orchestrator.run()

        markdown = to_markdown(outcome.report)

        assert outcome.report.executed_queries[0].query_id in markdown


class TestEventReplay:
    async def test_late_subscriber_receives_the_history(self):
        orchestrator, _, stream, _, _ = build(NOMINAL)
        await orchestrator.run()

        received = [event async for event in stream.subscribe()]

        assert len(received) == len(stream.history)
        assert received[0].type is HuntEventType.HUNT_STARTED


def _final_conclusion(verdict, call_id="final"):
    return Completion(
        content="Final review.",
        tool_calls=[
            tool_call(
                "conclude_hunt",
                {
                    "verdict": verdict,
                    "summary": "After reviewing the case, the verdict is settled.",
                    "limitations": "Seven-day window only.",
                },
                call_id=call_id,
            )
        ],
        usage=Usage(500, 100),
    )


class TestOpusSonnetSplit:
    async def test_analysis_model_overturns_the_exploration_verdict(self):
        completions = NOMINAL + [_final_conclusion("escalate")]
        orchestrator, dossier, _, _, _ = build(
            completions, model="query-model", analysis_model="analysis-model"
        )

        outcome = await orchestrator.run()

        # Exploration (sonnet) proposed "suspicious"; analysis (opus) settles on "escalate".
        assert outcome.report.proposed_verdict is Verdict.ESCALATE
        assert dossier.status is HuntStatus.AWAITING_REVIEW

    async def test_final_pass_runs_on_the_analysis_model_with_only_conclude(self):
        completions = NOMINAL + [_final_conclusion("suspicious")]
        orchestrator, _, _, _, _ = build(
            completions, model="query-model", analysis_model="analysis-model"
        )

        await orchestrator.run()

        exploration = orchestrator._gateway.calls[:-1]
        final = orchestrator._gateway.calls[-1]
        assert all(call["model"] == "query-model" for call in exploration)
        assert final["model"] == "analysis-model"
        assert [tool["function"]["name"] for tool in final["tools"]] == ["conclude_hunt"]

    async def test_degrades_to_exploration_verdict_when_analysis_returns_nothing(self):
        # No scripted completion for the final pass: the fake client returns empty.
        orchestrator, _, _, _, _ = build(
            NOMINAL, model="query-model", analysis_model="analysis-model"
        )

        outcome = await orchestrator.run()

        assert orchestrator._gateway.calls[-1]["model"] == "analysis-model"
        assert outcome.report.proposed_verdict is Verdict.SUSPICIOUS

    async def test_no_final_pass_when_a_single_model_is_used(self):
        orchestrator, _, _, _, _ = build(
            NOMINAL, model="analysis-model", analysis_model="analysis-model"
        )

        await orchestrator.run()

        assert len(orchestrator._gateway.calls) == len(NOMINAL)


@pytest.fixture(autouse=True)
def _placeholder_evidence(monkeypatch):
    """The scripted finding cites the previous turn's query, whose id is generated at runtime."""

    from tools import definitions

    original = definitions.ToolRegistry.dispatch

    async def patched(self, name, arguments):
        if name == "record_finding" and arguments.get("evidence_query_ids") == ["__PLACEHOLDER__"]:
            last = getattr(patched, "last_query_id", None)
            arguments = {**arguments, "evidence_query_ids": [last] if last else []}
        result = await original(self, name, arguments)
        if isinstance(result, dict) and "query_id" in result:
            patched.last_query_id = result["query_id"]
        return result

    monkeypatch.setattr(definitions.ToolRegistry, "dispatch", patched)


class TestResultEvents:
    async def test_tool_result_carries_intent_and_sample(self):
        orchestrator, _, stream, _, _ = build(NOMINAL)
        await orchestrator.run()
        results = [e for e in stream.history if e.type is HuntEventType.TOOL_RESULT]
        assert results
        payload = results[0].payload
        assert payload["intent"] == "Service account connections over the period"
        assert payload["columns"]
        assert isinstance(payload["sample"], list) and payload["sample"]
        assert payload["summary"]["source_rows"] >= len(payload["sample"])


class TestInterpretation:
    async def test_the_agents_reading_is_attached_to_the_previous_queries(self):
        orchestrator, dossier, _, _, _ = build(NOMINAL)
        await orchestrator.run()
        records = dossier.ledger.as_list()
        assert records, "at least one executed query"
        assert records[0].interpretation == "Three off-hours connections, I'm recording it."
        report_query = dossier.executed_queries()[0]
        assert report_query.interpretation == records[0].interpretation
