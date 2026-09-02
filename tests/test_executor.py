import pytest

from middleware.audit import AuditEventType, AuditJournal, MemoryAuditSink
from middleware.budgets import HuntBudget
from middleware.clients.results import QueryOutcome
from middleware.config import Budgets, Settings
from middleware.errors import BudgetExhausted, ErrorCode, ToolError
from middleware.executor import QueryLedger, SiemExecutor
from middleware.guardrails.ioc import Ioc, IocStatus, IocType
from middleware.untrusted import TAG


class FakeSentinel:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else [{"Account": "svc-app", "Ip": "10.0.0.1"}]
        self.calls = []

    async def run_query(self, *, query, workspace_id, timespan_days, row_cap):
        self.calls.append(
            {
                "query": query,
                "workspace": workspace_id,
                "timespan_days": timespan_days,
                "row_cap": row_cap,
            }
        )
        return QueryOutcome(rows=self.rows, truncated=False, duration_ms=12)


class FakeDefender:
    def __init__(self):
        self.calls = []

    async def run_query(self, *, query, row_cap):
        self.calls.append({"query": query, "row_cap": row_cap})
        return QueryOutcome(rows=[{"DeviceName": "host-1"}], duration_ms=8)


def _validated(value, ioc_type=IocType.DOMAIN):
    return Ioc(
        value=value,
        type=ioc_type,
        source_name="VirusTotal",
        source_url="https://www.virustotal.com/gui/x",
        status=IocStatus.VALIDATED,
    )


def build(
    *,
    iocs=None,
    sentinel=None,
    defender=None,
    secops=None,
    budgets=None,
    settings=None,
    window=None,
):
    sink = MemoryAuditSink()
    journal = AuditJournal(sink, hunt_id="hunt_test", actor="j.doe")
    settings = settings or Settings(
        _env_file=None, workspace_aliases={"soc-principal": "workspace-guid-real"}
    )
    executor = SiemExecutor(
        settings=settings,
        journal=journal,
        budget=HuntBudget(limits=budgets or Budgets()),
        ledger=QueryLedger(),
        sentinel=sentinel,
        defender=defender,
        secops=secops,
        limiters={},
        window=window,
    )
    executor.set_iocs(iocs or [])
    return executor, sink


class FakeSecOps:
    def __init__(self):
        self.calls = []

    async def run_query(self, *, query, start_time, end_time, row_cap):
        self.calls.append({"query": query, "start": start_time, "end": end_time})
        return QueryOutcome(rows=[{"principal.hostname": "host-1"}], duration_ms=5)


class TestInvestigationWindow:
    """The investigation period chosen by the analyst is enforced by the middleware:
    the model's windows are bounded to it, and a window entirely outside is refused."""

    from datetime import UTC, datetime

    WINDOW = (
        datetime(2026, 8, 1, tzinfo=UTC),
        datetime(2026, 8, 20, tzinfo=UTC),
    )

    async def test_secops_window_is_clamped_to_the_period(self):
        secops = FakeSecOps()
        executor, _ = build(secops=secops, window=self.WINDOW)
        result = await executor.run_secops(
            udm_query='metadata.event_type = "PROCESS_LAUNCH"',
            start_time="2026-07-15T00:00:00Z",
            end_time="2026-08-25T00:00:00Z",
        )

        call = secops.calls[0]
        assert call["start"] == "2026-08-01T00:00:00+00:00"
        assert call["end"] == "2026-08-20T00:00:00+00:00"
        assert any("bounded to the investigation period" in note for note in result["notes"])

    async def test_query_fully_outside_the_period_is_refused_and_audited(self):
        secops = FakeSecOps()
        executor, sink = build(secops=secops, window=self.WINDOW)
        with pytest.raises(ToolError) as excinfo:
            await executor.run_secops(
                udm_query='metadata.event_type = "PROCESS_LAUNCH"',
                start_time="2026-06-01T00:00:00Z",
                end_time="2026-06-10T00:00:00Z",
            )

        assert "entirely outside the investigation period" in excinfo.value.message
        assert secops.calls == []
        rejected = [e for e in sink.events if e.type is AuditEventType.QUERY_REJECTED]
        assert rejected and rejected[0].detail["stage"] == "investigation period"

    async def test_sentinel_receives_the_absolute_timespan(self):
        class FakeSentinelWithTimespan(FakeSentinel):
            async def run_query(
                self, *, query, workspace_id, timespan_days, row_cap, timespan=None
            ):
                self.calls.append({"timespan": timespan})
                return QueryOutcome(rows=[], truncated=False, duration_ms=1)

        sentinel = FakeSentinelWithTimespan()
        executor, _ = build(sentinel=sentinel, window=self.WINDOW)
        await executor.run_sentinel(kql_query="SigninLogs | take 10", workspace="soc-principal")
        assert sentinel.calls[0]["timespan"] == (
            "2026-08-01T00:00:00+00:00/2026-08-20T00:00:00+00:00"
        )

    async def test_without_a_period_nothing_changes(self):
        secops = FakeSecOps()
        executor, _ = build(secops=secops)
        await executor.run_secops(
            udm_query='metadata.event_type = "PROCESS_LAUNCH"',
            start_time="2026-08-18T00:00:00Z",
            end_time="2026-08-25T00:00:00Z",
        )
        assert secops.calls[0]["start"] == "2026-08-18T00:00:00+00:00"


class TestWorkspaceResolution:
    async def test_single_workspace_absorbs_a_wrong_alias(self):
        """A single configured workspace: an alias invented by the model is routed to it
        rather than costing an iteration."""

        sentinel = FakeSentinel()
        executor, _ = build(sentinel=sentinel)
        await executor.run_sentinel(kql_query="SigninLogs | take 10", workspace="sentinel")
        assert sentinel.calls[0]["workspace"] == "workspace-guid-real"

    async def test_ambiguous_alias_is_still_refused(self):
        sentinel = FakeSentinel()
        settings = Settings(
            _env_file=None, workspace_aliases={"soc-a": "guid-a", "soc-b": "guid-b"}
        )
        executor, _ = build(sentinel=sentinel, settings=settings)
        with pytest.raises(ToolError) as excinfo:
            await executor.run_sentinel(kql_query="SigninLogs | take 10", workspace="sentinel")
        assert "soc-a, soc-b" in (excinfo.value.hint or "")
        assert sentinel.calls == []


class TestHumanCheckpoint:
    async def test_pending_ioc_blocks_every_siem_call(self):
        pending = Ioc(
            value="evil.example",
            type=IocType.DOMAIN,
            source_name="VirusTotal",
            source_url="https://www.virustotal.com/gui/x",
        )
        sentinel = FakeSentinel()
        executor, sink = build(iocs=[pending], sentinel=sentinel)

        with pytest.raises(ToolError) as excinfo:
            await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")

        assert excinfo.value.code is ErrorCode.IOC_NOT_VALIDATED
        assert sentinel.calls == []
        assert sink.events[-1].type is AuditEventType.QUERY_REJECTED


class TestNoUnsourcedIndicatorReachesASiem:
    async def test_indicator_absent_from_validated_set_is_blocked(self):
        sentinel = FakeSentinel()
        executor, _ = build(iocs=[_validated("known.example")], sentinel=sentinel)

        with pytest.raises(ToolError) as excinfo:
            await executor.run_sentinel(
                kql_query='DeviceNetworkEvents | where RemoteUrl has "made-up.example"',
                workspace="soc-principal",
            )

        assert excinfo.value.code is ErrorCode.IOC_UNSOURCED
        assert sentinel.calls == []

    async def test_validated_indicator_reaches_the_siem(self):
        sentinel = FakeSentinel()
        executor, _ = build(iocs=[_validated("known.example")], sentinel=sentinel)

        await executor.run_sentinel(
            kql_query='DeviceNetworkEvents | where RemoteUrl has "known.example"',
            workspace="soc-principal",
        )

        assert len(sentinel.calls) == 1


class TestReadOnlyIsEnforcedBeforeAnyCall:
    async def test_write_query_never_reaches_the_client(self):
        sentinel = FakeSentinel()
        executor, sink = build(sentinel=sentinel)

        with pytest.raises(ToolError):
            await executor.run_sentinel(
                kql_query=".drop table SigninLogs", workspace="soc-principal"
            )

        assert sentinel.calls == []
        assert sink.events[-1].error_code == ErrorCode.QUERY_REJECTED.value


class TestCaps:
    async def test_row_cap_is_injected_into_the_executed_query(self):
        sentinel = FakeSentinel()
        executor, _ = build(sentinel=sentinel)

        result = await executor.run_sentinel(
            kql_query="SigninLogs | take 100000", workspace="soc-principal", max_rows=9999
        )

        assert sentinel.calls[0]["query"].strip().endswith("take 500")
        assert sentinel.calls[0]["row_cap"] == 500
        assert result["executed_query"].strip().endswith("take 500")

    async def test_timespan_is_clamped(self):
        sentinel = FakeSentinel()
        executor, _ = build(sentinel=sentinel)

        await executor.run_sentinel(
            kql_query="SigninLogs", workspace="soc-principal", timespan_days=365
        )

        assert sentinel.calls[0]["timespan_days"] == 30

    async def test_defender_requires_an_inline_time_filter(self):
        defender = FakeDefender()
        executor, _ = build(defender=defender)

        with pytest.raises(ToolError) as excinfo:
            await executor.run_defender(kql_query="DeviceProcessEvents | take 5")

        assert excinfo.value.code is ErrorCode.WINDOW_TOO_LARGE
        assert defender.calls == []

    async def test_defender_accepts_the_api_maximum_without_explicit_timespan(self):
        defender = FakeDefender()
        executor, _ = build(defender=defender)

        result = await executor.run_defender(
            kql_query="DeviceProcessEvents | where Timestamp > ago(30d)"
        )

        assert len(defender.calls) == 1
        assert "window checked: 30 days" in " ".join(result["notes"])

    async def test_defender_explicit_timespan_still_bounds_the_query(self):
        defender = FakeDefender()
        executor, _ = build(defender=defender)

        with pytest.raises(ToolError) as excinfo:
            await executor.run_defender(
                kql_query="DeviceProcessEvents | where Timestamp > ago(30d)",
                timespan_days=7,
            )

        assert excinfo.value.code is ErrorCode.WINDOW_TOO_LARGE
        assert defender.calls == []


class TestAnonymizationProof:
    async def test_model_sample_keeps_pseudonyms_and_analyst_sample_is_rehydrated(self):
        from middleware.tokenization import TokenVault

        class HostDefender:
            async def run_query(self, *, query, row_cap):
                return QueryOutcome(
                    rows=[{"DeviceName": "PAR-FS-03", "AccountName": "j.smith", "Count": 3}],
                    duration_ms=2,
                )

        sink = MemoryAuditSink()
        journal = AuditJournal(sink, hunt_id="hunt_test", actor="j.doe")
        executor = SiemExecutor(
            settings=Settings(_env_file=None),
            journal=journal,
            budget=HuntBudget(limits=Budgets()),
            ledger=QueryLedger(),
            defender=HostDefender(),
            limiters={},
            vault=TokenVault(),
        )
        executor.set_iocs([])
        result = await executor.run_defender(
            kql_query="DeviceProcessEvents | where Timestamp > ago(7d)"
        )
        record = executor._ledger.records[result["query_id"]]

        assert record.model_sample[0]["DeviceName"].startswith("HOST-")
        assert record.model_sample[0]["AccountName"].startswith("USER-")
        assert record.sample[0]["DeviceName"] == "PAR-FS-03"
        assert record.sample[0]["AccountName"] == "j.smith"
        assert record.anonymization["tokens"] == {"HOST": 1, "USER": 1, "IP-INT": 0, "DATA": 0}
        assert record.anonymization["semantic"] == "disabled"
        assert record.anonymization["tokenization"] is True
        assert "PAR-FS-03" not in str(result["data"])


class TestUpstreamRejection:
    async def test_upstream_hint_is_journaled(self):
        class RejectingSentinel:
            async def run_query(self, **_kwargs):
                raise ToolError(
                    ErrorCode.UPSTREAM_REJECTED,
                    "Query refused by Sentinel.",
                    hint="The workspace could not be found",
                )

        executor, sink = build(sentinel=RejectingSentinel())
        with pytest.raises(ToolError):
            await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")
        rejected = [e for e in sink.events if e.type is AuditEventType.QUERY_REJECTED]
        assert rejected[-1].detail["hint"] == "The workspace could not be found"


class TestAnonymizationDegradation:
    async def test_degraded_pass_is_noted_and_audited(self):
        from middleware.anonymizer import SemanticAnonymizer
        from middleware.tokenization import TokenVault

        class DownAnonymizer:
            async def complete(self, **_kwargs):
                raise ToolError(ErrorCode.UPSTREAM_UNAVAILABLE, "anonymizer unreachable")

        class WordyDefender:
            async def run_query(self, *, query, row_cap):
                return QueryOutcome(
                    rows=[{"ProcessCommandLine": "curl -X POST https://x/upload"}],
                    duration_ms=3,
                )

        sink = MemoryAuditSink()
        journal = AuditJournal(sink, hunt_id="hunt_test", actor="j.doe")
        settings = Settings(_env_file=None)
        vault = TokenVault()
        executor = SiemExecutor(
            settings=settings,
            journal=journal,
            budget=HuntBudget(limits=Budgets()),
            ledger=QueryLedger(),
            defender=WordyDefender(),
            limiters={},
            vault=vault,
            anonymizer=SemanticAnonymizer(client=DownAnonymizer(), model="m", vault=vault),
        )
        executor.set_iocs([])

        result = await executor.run_defender(
            kql_query="DeviceProcessEvents | where Timestamp > ago(7d)"
        )

        assert any("semantic anonymization unavailable" in n for n in result["notes"])
        assert "curl" not in str(result["data"])
        degraded = [e for e in sink.events if e.type is AuditEventType.ANONYMIZATION_DEGRADED]
        assert len(degraded) == 1
        record = executor._ledger.records[result["query_id"]]
        assert record.anonymization["semantic"] == "degraded"
        assert record.anonymization["masked_fields"] == 1
        assert degraded[0].detail["free_text_masked"] is True
        assert degraded[0].query_id == result["query_id"]


class TestDelivery:
    async def test_results_are_minimized_and_wrapped(self):
        sentinel = FakeSentinel(rows=[{"upn": "john.smith@company.example", "token": "abc"}])
        executor, _ = build(sentinel=sentinel)

        result = await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")

        assert result["data"].startswith(f"<{TAG} ")
        assert "john.smith" not in result["data"]
        assert "abc" not in result["data"]
        assert "rows" not in result

    async def test_query_id_is_recorded_as_evidence(self):
        executor, sink = build(sentinel=FakeSentinel())

        result = await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")

        assert result["query_id"].startswith("q_")
        executed = [event for event in sink.events if event.type is AuditEventType.QUERY_EXECUTED]
        assert executed[0].query_id == result["query_id"]
        assert executed[0].rows_returned == 1

    async def test_unknown_workspace_does_not_leak_real_names(self):
        settings = Settings(
            _env_file=None,
            workspace_aliases={"soc-principal": "workspace-guid-real", "soc-b": "guid-b"},
        )
        executor, _ = build(sentinel=FakeSentinel(), settings=settings)

        with pytest.raises(ToolError) as excinfo:
            await executor.run_sentinel(kql_query="SigninLogs", workspace="unknown")

        assert excinfo.value.code is ErrorCode.UNKNOWN_TARGET
        assert "workspace-guid-real" not in str(excinfo.value.hint)
        assert "guid-b" not in str(excinfo.value.hint)


class TestBudget:
    async def test_siem_query_budget_stops_the_hunt(self):
        executor, _ = build(sentinel=FakeSentinel(), budgets=Budgets(max_siem_queries=1))

        await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")
        with pytest.raises(BudgetExhausted):
            await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")

    async def test_rejected_query_does_not_consume_the_budget(self):
        executor, _ = build(sentinel=FakeSentinel(), budgets=Budgets(max_siem_queries=1))

        with pytest.raises(ToolError):
            await executor.run_sentinel(kql_query=".show tables", workspace="soc-principal")

        await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")


class TestUnconfiguredSource:
    async def test_missing_client_is_reported_as_unavailable(self):
        executor, _ = build()

        with pytest.raises(ToolError) as excinfo:
            await executor.run_sentinel(kql_query="SigninLogs", workspace="soc-principal")

        assert excinfo.value.code is ErrorCode.UNKNOWN_TARGET
