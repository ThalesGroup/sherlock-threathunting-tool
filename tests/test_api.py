import json

import httpx
import pytest

from api.app import create_app
from api.runtime import HuntRuntime, SiemClients
from middleware.clients.results import QueryOutcome
from middleware.config import Settings
from middleware.errors import ErrorCode, ToolError
from orchestrator.gateway import Completion, ToolCall, Usage
from reporting.models import HuntStatus
from storage.repository import Database, HuntRepository, SqlAuditSink

ANALYST = {"X-Dev-User": "j.doe", "X-Dev-Roles": "analyst"}
READER = {"X-Dev-User": "l.reader", "X-Dev-Roles": "reader"}
BUDGETS = {"max_iterations": 20, "max_siem_queries": 15}
"""Without a validated playbook, a launch must set its budgets explicitly."""


class FakeGateway:
    def __init__(self, completions):
        self._completions = list(completions)

    async def complete(self, *, model, messages, tools, **kwargs):
        if not self._completions:
            return Completion(content="", usage=Usage(5, 5))
        return self._completions.pop(0)


class FakeSentinel:
    async def run_query(self, *, query, workspace_id, timespan_days, row_cap):
        return QueryOutcome(rows=[{"Account": "svc-backup"}], duration_ms=4)


def _call(name, arguments, call_id="call_1"):
    return ToolCall(id=call_id, name=name, arguments=arguments, raw_arguments=json.dumps(arguments))


PLAN_ARGUMENTS = {
    "summary": "Look for off-hours logons of the backup account.",
    "steps": [
        {
            "order": 1,
            "siem": "sentinel",
            "objective": "Spot the nighttime logon sessions of the service account",
            "technique": "T1078",
            "expected_queries": 3,
        }
    ],
    "not_covered": "Defender is not available on this installation.",
}
PLAN_COMPLETION = Completion(
    content="",
    tool_calls=[_call("propose_playbook", PLAN_ARGUMENTS)],
    usage=Usage(50, 30),
)

SCRIPT = [
    Completion(
        content="I'm querying the logons.",
        tool_calls=[
            _call(
                "run_sentinel_kql",
                {
                    "kql_query": "SigninLogs",
                    "workspace": "soc",
                    "intent": "Service account logons over the period",
                },
            )
        ],
        usage=Usage(100, 50),
    ),
    Completion(
        content="I'm concluding.",
        tool_calls=[
            _call(
                "conclude_hunt",
                {
                    "verdict": "suspicious",
                    "summary": "Repeated nighttime logons on a service account.",
                    "limitations": "Defender not queried over this period.",
                },
                call_id="call_2",
            )
        ],
        usage=Usage(120, 60),
    ),
]


@pytest.fixture
async def app_context(tmp_path):
    database = Database(f"sqlite+aiosqlite:///{tmp_path}/test.db")
    await database.create_all()
    repository = HuntRepository(database)
    settings = Settings(_env_file=None, workspace_aliases={"soc": "guid-real"})
    runtime = HuntRuntime(
        settings=settings,
        repository=repository,
        audit_sink=SqlAuditSink(database),
        gateway=FakeGateway(SCRIPT),
        clients=SiemClients(sentinel=FakeSentinel()),
    )
    app = create_app(settings=settings, runtime=runtime, repository=repository, database=database)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, runtime, repository
    await database.dispose()


async def _create_hunt(client, **overrides):
    payload = {
        "hypothesis": "Living off the land activity on the backup servers",
        "campaign": "Volt Typhoon",
        **overrides,
    }
    response = await client.post("/api/hunts", json=payload, headers=ANALYST)
    assert response.status_code == 201, response.text
    return response.json()


class TestAuthentication:
    async def test_anonymous_is_refused(self, app_context):
        client, _, _ = app_context
        response = await client.get("/api/dashboard")
        assert response.status_code == 401

    async def test_reader_cannot_launch_a_hunt(self, app_context):
        client, _, _ = app_context
        response = await client.post("/api/hunts", json={"hypothesis": "x" * 20}, headers=READER)
        assert response.status_code == 403

    async def test_reader_can_consult(self, app_context):
        client, _, _ = app_context
        response = await client.get("/api/hunts", headers=READER)
        assert response.status_code == 200


class TestHuntStartingPoint:
    async def test_hypothesis_only_hunt_skips_the_ioc_checkpoint(self, app_context):
        """Without a campaign or indicator, there is nothing to validate: the hunt can be
        launched directly. The checkpoint only applies when there will be IOCs to decide on."""

        client, _, _ = app_context
        response = await client.post(
            "/api/hunts",
            json={"hypothesis": "Admin tooling activity over the recent window"},
            headers=ANALYST,
        )
        created = response.json()
        assert created["requires_ioc_validation"] is False

        started = await client.post(
            f"/api/hunts/{created['hunt_id']}/start", headers=ANALYST, json=BUDGETS
        )
        assert started.status_code == 200, started.text

    async def test_campaign_hunt_requires_the_ioc_checkpoint(self, app_context):
        client, _, _ = app_context
        response = await client.post(
            "/api/hunts", json={"campaign": "Volt Typhoon"}, headers=ANALYST
        )
        assert response.json()["requires_ioc_validation"] is True

    async def test_campaign_only_hunt_derives_a_hypothesis(self, app_context):
        client, runtime, _ = app_context
        response = await client.post(
            "/api/hunts", json={"campaign": "Volt Typhoon"}, headers=ANALYST
        )
        assert response.status_code == 201, response.text
        hunt_id = response.json()["hunt_id"]
        assert "Volt Typhoon" in runtime.get(hunt_id).dossier.hypothesis

    async def test_hunt_without_starting_point_is_rejected(self, app_context):
        client, _, _ = app_context
        response = await client.post("/api/hunts", json={}, headers=ANALYST)
        assert response.status_code == 422


class TestPlatformConfig:
    async def test_real_limits_are_exposed_to_the_analyst(self, app_context):
        client, _, _ = app_context
        config = (await client.get("/api/config", headers=ANALYST)).json()

        defender = next(source for source in config["sources"] if source["name"] == "defender")
        assert defender["max_window_days"] == 30
        assert "last 30 days" in defender["note"]
        assert config["threat_intel_enabled"] is False

    async def test_only_workspace_aliases_are_exposed(self, app_context):
        client, _, _ = app_context
        config = (await client.get("/api/config", headers=ANALYST)).json()
        assert config["workspaces"] == ["soc"]
        assert "guid-real" not in json.dumps(config)


class TestIocCheckpoint:
    async def test_manual_iocs_are_validated_by_their_provider(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        assert created["requires_ioc_validation"] is False

        iocs = (await client.get(f"/api/hunts/{created['hunt_id']}/iocs", headers=ANALYST)).json()
        assert iocs[0]["status"] == "validated"
        assert iocs[0]["source"].startswith("analyst:")

    async def test_analyst_can_add_iocs_before_launch(self, app_context):
        """The analyst complements the threat intel indicators with their own, on the
        validation screen. They arrive validated and attributed, duplicates discarded."""

        client, _, _ = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "already-there.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]

        response = await client.post(
            f"/api/hunts/{hunt_id}/iocs",
            json={
                "iocs": [
                    {"value": "my-c2.example", "type": "domain"},
                    {"value": "ALREADY-THERE.example", "type": "domain"},
                ]
            },
            headers=ANALYST,
        )
        assert response.status_code == 200, response.text

        outcome = response.json()
        by_value = {item["value"]: item for item in outcome["iocs"]}
        assert set(by_value) == {"already-there.example", "my-c2.example"}
        assert outcome["added"] == 1
        assert outcome["duplicates"] == ["ALREADY-THERE.example"]
        added = by_value["my-c2.example"]
        assert added["status"] == "validated"
        assert added["source"].startswith("analyst:")

    async def test_adding_iocs_is_confined_to_the_upstream_phase(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        response = await client.post(
            f"/api/hunts/{hunt_id}/iocs",
            json={"iocs": [{"value": "late.example", "type": "domain"}]},
            headers=ANALYST,
        )
        assert response.status_code == 400
        assert "before the hunt is launched" in response.json()["detail"]["message"]

    async def test_adding_iocs_is_reserved_to_analysts(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client)
        response = await client.post(
            f"/api/hunts/{created['hunt_id']}/iocs",
            json={"iocs": [{"value": "x.example", "type": "domain"}]},
            headers=READER,
        )
        assert response.status_code == 403

    async def test_probe_results_are_seeded_into_the_next_hunt(self, app_context):
        """The IOCs found by the CTI probe are carried into the hunt created right after,
        with their real sources, and remain subject to the human checkpoint."""

        import time as _time

        from middleware.guardrails.ioc import Ioc, IocType

        client, runtime, _ = app_context
        runtime._probe_cache["macsync stealer"] = (
            _time.monotonic(),
            [
                Ioc(
                    value="faturanova.xyz",
                    type=IocType.DOMAIN,
                    source_name="www.microsoft.com",
                    source_url="https://www.microsoft.com/security/blog/macsync",
                )
            ],
        )

        response = await client.post(
            "/api/hunts", json={"campaign": "MacSync Stealer"}, headers=ANALYST
        )
        created = response.json()
        assert created["requires_ioc_validation"] is True

        iocs = (await client.get(f"/api/hunts/{created['hunt_id']}/iocs", headers=ANALYST)).json()
        seeded = next(item for item in iocs if item["value"] == "faturanova.xyz")
        assert seeded["source"] == "www.microsoft.com"
        assert seeded["status"] == "pending_validation"

    async def test_upstream_hunt_survives_a_restart(self, app_context):
        """An upstream-phase hunt lost to a restart is restored from the database:
        the analyst resumes where they were instead of recreating the hunt."""

        client, runtime, _ = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]

        runtime._hunts.clear()  # simulates a restart: memory is empty

        response = await client.post(
            f"/api/hunts/{hunt_id}/iocs",
            json={"iocs": [{"value": "after-restart.example", "type": "domain"}]},
            headers=ANALYST,
        )
        assert response.status_code == 200, response.text
        values = {item["value"] for item in response.json()["iocs"]}
        assert {"evil.example", "after-restart.example"} <= values

        started = await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        assert started.status_code == 200, started.text

    async def test_a_flying_hunt_is_not_restorable(self, app_context):
        """A hunt whose loop was in flight cannot resume after a restart:
        it stays unknown rather than pretending to continue a lost investigation."""

        client, runtime, _ = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        runtime._hunts.clear()

        response = await client.post(
            f"/api/hunts/{hunt_id}/iocs",
            json={"iocs": [{"value": "x.example", "type": "domain"}]},
            headers=ANALYST,
        )
        assert response.status_code == 400
        assert "Unknown" in response.json()["detail"]["message"]

    async def test_start_persists_the_running_status(self, app_context):
        """The "running" status is persisted at launch: listings route to the
        investigation thread, not to the validation screen."""

        client, runtime, repository = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        row = await repository.get_hunt(hunt_id)
        assert row["status"] in ("running", "awaiting_review", "interrupted")
        await runtime.get(hunt_id).task

    async def test_iocs_are_frozen_while_the_hunt_runs(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        if runtime.get(hunt_id).running:
            response = await client.post(
                f"/api/hunts/{hunt_id}/iocs/validate",
                json={"validated": [], "rejected": ["evil.example"]},
                headers=ANALYST,
            )
            assert response.status_code == 400
            assert "in progress" in response.json()["detail"]["message"]
        await runtime.get(hunt_id).task

    async def test_orphan_running_hunts_are_interrupted_at_startup(self, app_context):
        client, runtime, repository = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]
        await repository.set_status(hunt_id, HuntStatus.RUNNING)

        count = await repository.mark_running_as_interrupted("server restarted")
        assert count >= 1
        row = await repository.get_hunt(hunt_id)
        assert row["status"] == "interrupted"
        assert row["interruption_reason"] == "server restarted"

    async def test_validation_marks_and_attributes(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(
            client,
            manual_iocs=[
                {"value": "keep.example", "type": "domain"},
                {"value": "discard.example", "type": "domain"},
            ],
        )
        hunt_id = created["hunt_id"]

        response = await client.post(
            f"/api/hunts/{hunt_id}/iocs/validate",
            json={"validated": ["keep.example"], "rejected": ["discard.example"]},
            headers=ANALYST,
        )

        statuses = {item["value"]: item["status"] for item in response.json()}
        assert statuses == {"keep.example": "validated", "discard.example": "rejected"}
        stored = runtime.get(hunt_id).dossier.iocs
        assert all(ioc.validated_by == "j.doe" for ioc in stored)

    async def test_validation_is_reserved_to_analysts(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client)
        response = await client.post(
            f"/api/hunts/{created['hunt_id']}/iocs/validate",
            json={"validated": [], "rejected": []},
            headers=READER,
        )
        assert response.status_code == 403

    async def test_enrichment_without_approved_source_is_blocked(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client)
        response = await client.post(
            f"/api/hunts/{created['hunt_id']}/enrich",
            json={"campaign_name": "Volt Typhoon"},
            headers=ANALYST,
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "egress_blocked"

    async def test_enrichment_is_confined_to_the_upstream_phase(self, app_context):
        """Once the hunt is launched, no more outbound flow: enrichment is closed."""

        client, runtime, _ = app_context
        created = await _create_hunt(
            client, manual_iocs=[{"value": "evil.example", "type": "domain"}]
        )
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        response = await client.post(
            f"/api/hunts/{hunt_id}/enrich",
            json={"campaign_name": "Volt Typhoon"},
            headers=ANALYST,
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert detail["error"] == "egress_blocked"
        assert "before the hunt is launched" in detail["message"]


class TestHuntLifecycle:
    async def test_full_run_produces_a_reviewable_report(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        hunt_id = created["hunt_id"]

        started = await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        assert started.status_code == 200
        await runtime.get(hunt_id).task

        report = (await client.get(f"/api/hunts/{hunt_id}/report", headers=ANALYST)).json()
        assert report["proposed_verdict"] == "suspicious"
        assert report["limitations"]
        assert len(report["executed_queries"]) == 1
        assert report["human_decision"] is None

    async def test_pending_iocs_block_the_start(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        hunt = runtime.get(created["hunt_id"])
        from middleware.guardrails.ioc import Ioc, IocType

        hunt.dossier.iocs.append(
            Ioc(
                value="pending.example",
                type=IocType.DOMAIN,
                source_name="VirusTotal",
                source_url="https://www.virustotal.com/gui/x",
            )
        )
        response = await client.post(
            f"/api/hunts/{created['hunt_id']}/start", headers=ANALYST, json=BUDGETS
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "ioc_not_validated"

    async def test_report_is_absent_before_the_run(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client)
        response = await client.get(f"/api/hunts/{created['hunt_id']}/report", headers=ANALYST)
        assert response.status_code == 404

    async def test_markdown_export(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        await client.post(f"/api/hunts/{created['hunt_id']}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(created["hunt_id"]).task

        response = await client.get(
            f"/api/hunts/{created['hunt_id']}/report?format=markdown", headers=ANALYST
        )
        assert response.status_code == 200
        assert "Proposed verdict" in response.text

    async def test_pdf_export(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        await client.post(f"/api/hunts/{created['hunt_id']}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(created["hunt_id"]).task

        response = await client.get(
            f"/api/hunts/{created['hunt_id']}/report?format=pdf", headers=ANALYST
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF")


class TestHumanVerdict:
    async def test_decision_is_dated_and_attributed(self, app_context):
        client, runtime, repository = app_context
        created = await _create_hunt(client)
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        response = await client.post(
            f"/api/hunts/{hunt_id}/decision",
            json={"verdict": "escalate", "comment": "Confirmed, I'm escalating."},
            headers=ANALYST,
        )
        assert response.status_code == 200

        report = await repository.load_report(hunt_id)
        assert report.proposed_verdict.value == "suspicious"
        assert report.human_decision.verdict.value == "escalate"
        assert report.human_decision.decided_by == "j.doe"
        assert report.human_decision.decided_at

    async def test_reader_cannot_decide(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        await client.post(f"/api/hunts/{created['hunt_id']}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(created["hunt_id"]).task

        response = await client.post(
            f"/api/hunts/{created['hunt_id']}/decision",
            json={"verdict": "benign"},
            headers=READER,
        )
        assert response.status_code == 403


class TestAuditAndDashboard:
    async def test_audit_trail_records_queries_and_human_actions(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        hunt_id = created["hunt_id"]
        await client.post(
            f"/api/hunts/{hunt_id}/iocs/validate",
            json={"validated": [], "rejected": []},
            headers=ANALYST,
        )
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        trail = (await client.get(f"/api/hunts/{hunt_id}/audit", headers=ANALYST)).json()
        types = [event["type"] for event in trail]

        assert "hunt_created" in types
        assert "ioc_validation" in types
        assert "query_executed" in types
        executed = next(event for event in trail if event["type"] == "query_executed")
        assert executed["query"].strip().endswith("take 500")
        assert executed["actor"] == "j.doe"

    async def test_dashboard_aggregates_hunts(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        await client.post(f"/api/hunts/{created['hunt_id']}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(created["hunt_id"]).task

        dashboard = (await client.get("/api/dashboard", headers=ANALYST)).json()
        assert dashboard["recent_hunts"]
        assert dashboard["queries_by_siem"] == {"sentinel": 1}


class TestEventStream:
    async def test_thread_is_served_as_sse(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        response = await client.get(f"/api/hunts/{hunt_id}/events", headers=ANALYST)

        assert response.headers["content-type"].startswith("text/event-stream")
        assert "event: hunt_started" in response.text
        assert "event: concluded" in response.text


ADMIN = {"X-Dev-User": "a.admin", "X-Dev-Roles": "admin"}


@pytest.fixture
async def config_context(tmp_path):
    from middleware.secrets import (
        ConfigurableSecretProvider,
        EncryptedSecretStore,
        EnvSecretProvider,
    )

    database = Database(f"sqlite+aiosqlite:///{tmp_path}/config.db")
    await database.create_all()
    repository = HuntRepository(database)
    settings = Settings(_env_file=None, ti_allowed_domains="www.circl.lu")
    secrets = ConfigurableSecretProvider(
        store=EncryptedSecretStore(tmp_path / "secrets.enc"),
        fallback=EnvSecretProvider(env_file=str(tmp_path / "empty.env")),
    )
    runtime = HuntRuntime(
        settings=settings,
        repository=repository,
        audit_sink=SqlAuditSink(database),
        gateway=FakeGateway([]),
        clients=SiemClients(),
        secrets=secrets,
    )
    app = create_app(settings=settings, runtime=runtime, repository=repository, database=database)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, runtime, repository
    await database.dispose()


class TestConfigurationEndpoints:
    async def test_sentinel_workspace_is_resolved_from_its_name(self, config_context, monkeypatch):
        import api.runtime as runtime_module

        client, runtime, _ = config_context
        seen = {}

        async def fake_resolve(provider, *, subscription_id, resource_group, workspace_name):
            seen.update(sub=subscription_id, rg=resource_group, name=workspace_name)
            return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

        monkeypatch.setattr(runtime_module, "resolve_workspace_id", fake_resolve)

        values = {
            "ENTRA_TENANT_ID": "11111111-2222-3333-4444-555555555555",
            "ENTRA_CLIENT_ID": "66666666-7777-8888-9999-000000000000",
            "ENTRA_CLIENT_SECRET": "test-secret",
            "SENTINEL_SUBSCRIPTION_ID": "22222222-2222-3333-4444-555555555555",
            "SENTINEL_RESOURCE_GROUP": "rg-soc",
            "SENTINEL_WORKSPACE_NAME": "ws-soc-prod",
        }
        for name, value in values.items():
            response = await client.put(
                f"/api/config/secrets/{name}", headers=ADMIN, json={"value": value}
            )
            assert response.status_code == 204, name

        assert seen == {
            "sub": values["SENTINEL_SUBSCRIPTION_ID"],
            "rg": "rg-soc",
            "name": "ws-soc-prod",
        }
        assert runtime.settings.workspace_aliases == {
            "soc-principal": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        }

        config = (await client.get("/api/config", headers=ANALYST)).json()
        assert config["workspaces"] == ["soc-principal"]
        assert "ws-soc-prod" not in json.dumps(config)

        by_id = {
            item["id"]: item
            for item in (await client.get("/api/config/sources", headers=ADMIN)).json()
        }
        assert by_id["entra"]["active"] is True
        assert by_id["entra"]["requirement"] is None
        assert "SENTINEL_WORKSPACE_ID_RESOLVED" not in json.dumps(by_id)

        removed = await client.delete("/api/config/secrets/SENTINEL_WORKSPACE_NAME", headers=ADMIN)
        assert removed.status_code == 204
        assert runtime.settings.workspace_aliases == {}
        by_id = {
            item["id"]: item
            for item in (await client.get("/api/config/sources", headers=ADMIN)).json()
        }
        assert "Incomplete" in by_id["entra"]["requirement"]

    async def test_direct_workspace_id_bypasses_resolution(self, config_context, monkeypatch):
        import api.runtime as runtime_module

        client, runtime, _ = config_context

        async def never(*_args, **_kwargs):
            raise AssertionError("ARM must not be called when the ID is provided")

        monkeypatch.setattr(runtime_module, "resolve_workspace_id", never)
        for name, value in {
            "ENTRA_TENANT_ID": "11111111-2222-3333-4444-555555555555",
            "ENTRA_CLIENT_ID": "66666666-7777-8888-9999-000000000000",
            "ENTRA_CLIENT_SECRET": "test-secret",
        }.items():
            await client.put(f"/api/config/secrets/{name}", headers=ADMIN, json={"value": value})

        refused = await client.put(
            "/api/config/secrets/SENTINEL_WORKSPACE_ID",
            headers=ADMIN,
            json={"value": "ws-soc-prod"},
        )
        assert refused.status_code == 400
        assert "GUID" in refused.json()["detail"]["message"]

        accepted = await client.put(
            "/api/config/secrets/SENTINEL_WORKSPACE_ID",
            headers=ADMIN,
            json={"value": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
        )
        assert accepted.status_code == 204
        assert runtime.settings.workspace_aliases == {
            "soc-principal": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        }
        by_id = {
            item["id"]: item
            for item in (await client.get("/api/config/sources", headers=ADMIN)).json()
        }
        assert by_id["entra"]["active"] is True and by_id["entra"]["requirement"] is None

    async def test_reserved_to_admin_role(self, config_context):
        client, _, _ = config_context
        for headers in (ANALYST, READER):
            response = await client.get("/api/config/sources", headers=headers)
            assert response.status_code == 403
        put = await client.put(
            "/api/config/secrets/OTX_API_KEY", headers=ANALYST, json={"value": "abcd"}
        )
        assert put.status_code == 403

    async def test_source_catalog_states(self, config_context):
        client, _, _ = config_context
        response = await client.get("/api/config/sources", headers=ADMIN)
        assert response.status_code == 200
        by_id = {item["id"]: item for item in response.json()}

        assert by_id["circl"]["active"] is True
        assert by_id["circl"]["secrets"] == []
        assert by_id["otx"]["active"] is False
        assert "Key missing" in by_id["otx"]["requirement"]
        assert by_id["gateway"]["active"] is False

    async def test_setting_a_key_activates_its_source(self, config_context):
        client, _, _ = config_context
        await client.put(
            "/api/config/secrets/OTX_API_KEY", headers=ADMIN, json={"value": "an-otx-key"}
        )
        by_id = {
            item["id"]: item
            for item in (await client.get("/api/config/sources", headers=ADMIN)).json()
        }
        assert by_id["otx"]["active"] is True
        assert by_id["otx"]["requirement"] is None

    async def test_anonymizer_key_is_savable_via_the_screen(self, config_context):
        client, _, _ = config_context
        put = await client.put(
            "/api/config/secrets/ANONYMIZER_API_KEY",
            headers=ADMIN,
            json={"value": "an-anon-test-key"},
        )
        assert put.status_code == 204

        by_id = {
            item["id"]: item
            for item in (await client.get("/api/config/sources", headers=ADMIN)).json()
        }
        assert "anonymizer" in by_id
        field = by_id["anonymizer"]["secrets"][0]
        assert field["name"] == "ANONYMIZER_API_KEY"
        assert field["configured"] is True
        assert field["origin"] == "configuration"

    async def test_sources_expose_their_server_side_endpoint_read_only(self, config_context):
        """The admin sees the wired endpoint and model without being able to change them
        here: an egress destination stays a server decision."""

        client, runtime, _ = config_context
        by_id = {
            item["id"]: item
            for item in (await client.get("/api/config/sources", headers=ADMIN)).json()
        }
        assert by_id["anonymizer"]["model"] == runtime.settings.anonymizer_model
        assert by_id["gateway"]["model"].startswith(runtime.settings.gateway_model_query)
        assert by_id["virustotal"]["endpoint"] is None and by_id["virustotal"]["model"] is None
        refused = await client.put(
            "/api/config/secrets/SHL_ANONYMIZER_BASE_URL", headers=ADMIN, json={"value": "x"}
        )
        assert refused.status_code in (400, 404, 422), "no generic store"

    def test_gateway_refusal_names_endpoint_model_and_settings(self):
        from api.runtime import _explain_gateway_refusal

        refused = _explain_gateway_refusal(
            ToolError(ErrorCode.UPSTREAM_REJECTED, "Call to the AI gateway refused."),
            endpoint="https://anonymizer.example/v1",
            model="local-model",
            url_setting="SHL_ANONYMIZER_BASE_URL",
            model_setting="SHL_ANONYMIZER_MODEL",
        )
        assert "https://anonymizer.example/v1" in refused.message
        assert "local-model" in refused.message
        assert "SHL_ANONYMIZER_BASE_URL" in (refused.hint or "")
        assert "the store takes precedence over .env" in (refused.hint or "")

        unreachable = _explain_gateway_refusal(
            ToolError(ErrorCode.UPSTREAM_UNAVAILABLE, "AI gateway unreachable."),
            endpoint="https://anonymizer.example/v1",
            model="m",
            url_setting="U",
            model_setting="M",
        )
        assert unreachable.message == "https://anonymizer.example/v1 unreachable."
        assert "firewall" in (unreachable.hint or "")

        untouched = ToolError(ErrorCode.RATE_LIMITED, "Quota.")
        assert (
            _explain_gateway_refusal(
                untouched, endpoint="e", model="m", url_setting="U", model_setting="M"
            )
            is untouched
        )

    async def test_secret_write_is_write_only(self, config_context):
        client, _, _ = config_context
        put = await client.put(
            "/api/config/secrets/OTX_API_KEY",
            headers=ADMIN,
            json={"value": "sk-really-secret-1234"},
        )
        assert put.status_code == 204

        listing = await client.get("/api/config/sources", headers=ADMIN)
        assert "sk-really-secret-1234" not in listing.text
        by_id = {item["id"]: item for item in listing.json()}
        field = by_id["otx"]["secrets"][0]
        assert field["configured"] is True
        assert field["origin"] == "configuration"
        assert field["updated_by"] == "a.admin"

    async def test_unknown_secret_name_is_rejected(self, config_context):
        client, _, _ = config_context
        response = await client.put(
            "/api/config/secrets/SOMETHING_ELSE", headers=ADMIN, json={"value": "abcd"}
        )
        assert response.status_code == 400

    async def test_delete_then_absent(self, config_context):
        client, _, _ = config_context
        await client.put(
            "/api/config/secrets/OTX_API_KEY", headers=ADMIN, json={"value": "abcd-efgh"}
        )
        first = await client.delete("/api/config/secrets/OTX_API_KEY", headers=ADMIN)
        assert first.status_code == 204
        second = await client.delete("/api/config/secrets/OTX_API_KEY", headers=ADMIN)
        assert second.status_code == 404

    async def test_updates_are_audited_without_the_value(self, config_context):
        client, _, repository = config_context
        await client.put(
            "/api/config/secrets/VIRUSTOTAL_API_KEY",
            headers=ADMIN,
            json={"value": "vt-secret-9876"},
        )
        trail = await repository.audit_trail("platform")
        assert any(entry["type"] == "config_secret_updated" for entry in trail)
        assert "vt-secret-9876" not in json.dumps(trail)

    async def test_hot_reload_activates_threat_intel(self, config_context):
        client, runtime, _ = config_context
        assert runtime.threat_intel_enabled is False

        await client.put(
            "/api/config/secrets/OTX_API_KEY", headers=ADMIN, json={"value": "abcd-efgh"}
        )
        assert runtime.threat_intel_enabled is True

    async def test_source_test_without_key_reports_missing_key_not_whitelist(self, config_context):
        client, _, _ = config_context
        response = await client.post("/api/config/sources/otx/test", headers=ADMIN)
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is False
        assert "Key missing" in body["detail"]
        assert "whitelist" not in body["detail"]


class TestLocalAccountAuth:
    async def _create_account(self, client, username="j.doe", roles=None):
        response = await client.post(
            "/api/config/accounts",
            headers=ADMIN,
            json={
                "username": username,
                "password": "a solid passphrase",
                "roles": roles or ["analyst", "admin"],
            },
        )
        assert response.status_code == 201

    async def test_login_sets_session_cookie_usable_without_dev_headers(self, config_context):
        client, _, _ = config_context
        await self._create_account(client)

        login = await client.post(
            "/api/auth/login",
            json={"username": "j.doe", "password": "a solid passphrase"},
        )
        assert login.status_code == 200
        assert "shl_session" in login.cookies

        me = await client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json() == {"name": "j.doe", "roles": ["admin", "analyst"]}

    async def test_wrong_password_is_refused_and_audited(self, config_context):
        client, _, repository = config_context
        await self._create_account(client)

        login = await client.post(
            "/api/auth/login",
            json={"username": "j.doe", "password": "a wrong password"},
        )
        assert login.status_code == 401
        assert "shl_session" not in login.cookies

        trail = await repository.audit_trail("platform")
        assert any(entry["type"] == "auth_login_failed" for entry in trail)

    async def test_logout_ends_the_session(self, config_context):
        client, _, _ = config_context
        await self._create_account(client)
        await client.post(
            "/api/auth/login",
            json={"username": "j.doe", "password": "a solid passphrase"},
        )

        await client.post("/api/auth/logout")
        me = await client.get("/api/auth/me")
        assert me.status_code == 401

    async def test_short_password_is_refused(self, config_context):
        client, _, _ = config_context
        response = await client.post(
            "/api/config/accounts",
            headers=ADMIN,
            json={"username": "x.y", "password": "short", "roles": ["analyst"]},
        )
        assert response.status_code == 422

    async def test_account_management_is_admin_only(self, config_context):
        client, _, _ = config_context
        assert (await client.get("/api/config/accounts", headers=ANALYST)).status_code == 403

    async def test_last_admin_cannot_be_deleted(self, config_context):
        client, _, _ = config_context
        await self._create_account(client, username="sole.admin")

        response = await client.delete("/api/config/accounts/sole.admin", headers=ADMIN)
        assert response.status_code == 400
        assert "last admin" in response.json()["detail"]

    async def test_account_listing_exposes_no_secret_material(self, config_context):
        client, _, _ = config_context
        await self._create_account(client)
        listing = await client.get("/api/config/accounts", headers=ADMIN)
        assert "a solid passphrase" not in listing.text
        assert "pbkdf2" not in listing.text


class TestHealth:
    async def test_health_reports_readiness(self, app_context):
        client, _, _ = app_context
        response = await client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["database"] == "ok"
        assert body["siem_sources"] == 1


class TestDeleteHunt:
    async def test_delete_removes_hunt_but_keeps_audit(self, app_context):
        client, runtime, repository = app_context
        created = await _create_hunt(client)
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        response = await client.delete(f"/api/hunts/{hunt_id}", headers=ANALYST)
        assert response.status_code == 204

        listing = await repository.list_hunts(limit=50)
        assert all(h["hunt_id"] != hunt_id for h in listing)
        assert await repository.load_report(hunt_id) is None

        trail = await repository.audit_trail(hunt_id)
        assert any(e["type"] == "hunt_deleted" for e in trail)
        assert any(e["type"] == "hunt_created" for e in trail)

    async def test_delete_is_reserved_to_analysts(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client)
        response = await client.delete(f"/api/hunts/{created['hunt_id']}", headers=READER)
        assert response.status_code == 403

    async def test_delete_unknown_hunt_is_404(self, app_context):
        client, _, _ = app_context
        response = await client.delete("/api/hunts/hunt_nonexistent", headers=ANALYST)
        assert response.status_code == 404

    async def test_running_hunt_cannot_be_deleted(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(client)
        hunt_id = created["hunt_id"]
        hunt = runtime.get(hunt_id)

        import asyncio

        async def _never():
            await asyncio.sleep(60)

        hunt.task = asyncio.create_task(_never())
        try:
            response = await client.delete(f"/api/hunts/{hunt_id}", headers=ANALYST)
            assert response.status_code == 400
        finally:
            hunt.task.cancel()


class TestPlaybookCheckpoint:
    async def test_start_without_plan_or_budgets_is_refused(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client, campaign=None, hypothesis="x" * 30)
        refused = await client.post(f"/api/hunts/{created['hunt_id']}/start", headers=ANALYST)
        assert refused.status_code == 400
        assert "playbook" in refused.json()["detail"]["message"].lower()

    async def test_plan_then_validated_budgets_drive_the_hunt(self, app_context):
        client, runtime, repository = app_context
        runtime._gateway = FakeGateway([PLAN_COMPLETION, *SCRIPT])
        created = await _create_hunt(client, campaign=None, hypothesis="x" * 30)
        hunt_id = created["hunt_id"]

        planned = await client.post(
            f"/api/hunts/{hunt_id}/plan", headers=ANALYST, json={"instruction": "keep it lean"}
        )
        assert planned.status_code == 200, planned.text
        playbook = planned.json()
        assert playbook["estimated_queries"] == 3
        assert playbook["estimated_iterations"] == 6
        assert playbook["instruction"] == "keep it lean"
        assert playbook["validated_by"] is None

        listed = (await client.get("/api/hunts", headers=ANALYST)).json()
        assert next(h for h in listed if h["hunt_id"] == hunt_id)["status"] == (
            "awaiting_plan_validation"
        )
        fetched = await client.get(f"/api/hunts/{hunt_id}/plan", headers=READER)
        assert fetched.json()["steps"][0]["technique"] == "T1078"

        started = await client.post(
            f"/api/hunts/{hunt_id}/start", headers=ANALYST, json={"max_siem_queries": 5}
        )
        assert started.status_code == 200, started.text
        hunt = runtime.get(hunt_id)
        assert hunt.budget.limits.max_siem_queries == 5
        assert hunt.budget.limits.max_iterations == 6
        assert hunt.dossier.playbook.validated_by == "j.doe"
        assert hunt.dossier.playbook.validated_queries == 5
        await hunt.task

        report = (await client.get(f"/api/hunts/{hunt_id}/report", headers=ANALYST)).json()
        assert report["playbook"]["validated_iterations"] == 6
        assert report["playbook"]["steps"][0]["siem"] == "sentinel"
        markdown = (
            await client.get(f"/api/hunts/{hunt_id}/report?format=markdown", headers=ANALYST)
        ).text
        assert "## Playbook" in markdown

        audit = (await client.get(f"/api/hunts/{hunt_id}/audit", headers=ANALYST)).json()
        types = [entry["type"] for entry in audit]
        assert "plan_proposed" in types and "plan_validated" in types
        validated = next(e for e in audit if e["type"] == "plan_validated")
        assert validated["detail"]["adjusted"] is True
        assert validated["detail"]["max_siem_queries"] == 5

    async def test_plan_waits_for_ioc_validation(self, app_context):
        client, runtime, _ = app_context
        runtime._gateway = FakeGateway([PLAN_COMPLETION])
        created = await _create_hunt(client)
        assert created["requires_ioc_validation"] is True
        response = await client.post(f"/api/hunts/{created['hunt_id']}/plan", headers=ANALYST)
        assert response.status_code == 400
        assert "indicators" in response.json()["detail"]["message"].lower()

    async def test_plan_survives_a_restart(self, app_context):
        client, runtime, _ = app_context
        runtime._gateway = FakeGateway([PLAN_COMPLETION])
        created = await _create_hunt(client, campaign=None, hypothesis="x" * 30)
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/plan", headers=ANALYST)

        runtime._hunts.pop(hunt_id)
        restored = await runtime.resolve(hunt_id)
        assert restored.dossier.status.value == "awaiting_plan_validation"
        assert restored.dossier.playbook is not None
        assert restored.dossier.playbook.estimated_queries == 3


class TestResume:
    async def _finished_parent(self, client, runtime):
        runtime._gateway = FakeGateway([PLAN_COMPLETION, *SCRIPT])
        created = await _create_hunt(
            client,
            campaign=None,
            hypothesis="x" * 30,
            manual_iocs=[{"value": "evil.example", "type": "domain"}],
        )
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/plan", headers=ANALYST)
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task
        return hunt_id

    async def test_resume_inherits_iocs_and_carries_the_trace(self, app_context):
        client, runtime, _ = app_context
        parent_id = await self._finished_parent(client, runtime)

        response = await client.post(
            f"/api/hunts/{parent_id}/resume",
            headers=ANALYST,
            json={"instruction": "Dig into the service accounts."},
        )
        assert response.status_code == 201, response.text
        child_id = response.json()["hunt_id"]
        assert response.json()["parent_hunt_id"] == parent_id
        assert child_id != parent_id

        child = runtime.get(child_id)
        assert child.dossier.status.value == "draft"
        assert child.dossier.parent_hunt_id == parent_id
        assert [ioc.value for ioc in child.dossier.iocs] == ["evil.example"]
        assert all(ioc.status.value == "validated" for ioc in child.dossier.iocs)

        briefing = child.orchestrator.briefing()
        assert "## Resuming a previous hunt" in briefing
        assert parent_id in briefing
        assert "Dig into the service accounts." in briefing
        assert "Queries already executed" in briefing

        parent_audit = (await client.get(f"/api/hunts/{parent_id}/audit", headers=ANALYST)).json()
        resumed = [entry for entry in parent_audit if entry["type"] == "hunt_resumed"]
        assert resumed and resumed[0]["detail"]["child"] == child_id

    async def test_resume_from_a_step_truncates_the_trace(self, app_context):
        client, runtime, _ = app_context
        parent_id = await self._finished_parent(client, runtime)
        report = (await client.get(f"/api/hunts/{parent_id}/report", headers=ANALYST)).json()
        first_query = report["executed_queries"][0]["query_id"]

        response = await client.post(
            f"/api/hunts/{parent_id}/resume",
            headers=ANALYST,
            json={"from_query_id": first_query},
        )
        assert response.status_code == 201, response.text
        briefing = runtime.get(response.json()["hunt_id"]).orchestrator.briefing()
        assert f"The resumption starts after the query {first_query}" in briefing
        assert "Conclusion of the initial hunt" not in briefing

        unknown = await client.post(
            f"/api/hunts/{parent_id}/resume",
            headers=ANALYST,
            json={"from_query_id": "q_0000000000"},
        )
        assert unknown.status_code == 400

    async def test_only_finished_hunts_can_be_resumed(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client, campaign=None, hypothesis="x" * 30)
        response = await client.post(f"/api/hunts/{created['hunt_id']}/resume", headers=ANALYST)
        assert response.status_code == 400
        assert "completed or interrupted" in response.json()["detail"]["message"]

    async def test_interrupted_hunt_without_report_uses_the_audit_trail(self, app_context):
        from api.runtime import build_resume_context

        client, runtime, repository = app_context
        parent_id = await self._finished_parent(client, runtime)
        row = await repository.get_hunt(parent_id)
        row = {**row, "status": "interrupted", "interruption_reason": "server restarted"}
        audit = await repository.audit_trail(parent_id)

        context = build_resume_context(
            parent_id=parent_id,
            row=row,
            report=None,
            audit=audit,
            from_query_id=None,
            instruction="Pick up from here.",
        )
        assert "interrupted: server restarted" in context
        assert "Queries already executed" in context
        assert "sentinel" in context
        assert "Pick up from here." in context


class TestContinueInPlace:
    async def test_interrupted_hunt_continues_where_it_stopped(self, app_context):
        client, runtime, repository = app_context
        runtime._settings.budget_pause_timeout_seconds = 0
        runtime._gateway = FakeGateway([PLAN_COMPLETION, *SCRIPT])
        created = await _create_hunt(client, campaign=None, hypothesis="x" * 30)
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/plan", headers=ANALYST)
        await client.post(
            f"/api/hunts/{hunt_id}/start",
            headers=ANALYST,
            json={"max_iterations": 1, "max_siem_queries": 15},
        )
        await runtime.get(hunt_id).task

        listed = (await client.get("/api/hunts", headers=ANALYST)).json()
        assert next(h for h in listed if h["hunt_id"] == hunt_id)["status"] == "interrupted"
        options = (await client.get(f"/api/hunts/{hunt_id}/resume-options", headers=ANALYST)).json()
        assert options["continuable"] is True
        state = await repository.load_hunt_state(hunt_id)
        assert state and state["messages"]
        assert state["budget"]["iterations"] == 1
        assert state["records"], "executed queries are part of the state"

        resumed = await client.post(
            f"/api/hunts/{hunt_id}/continue",
            headers=ANALYST,
            json={"max_iterations": 20},
        )
        assert resumed.status_code == 200, resumed.text
        hunt = runtime.get(hunt_id)
        assert hunt.budget.iterations >= 1, "consumed counters are preserved"
        await hunt.task

        report = (await client.get(f"/api/hunts/{hunt_id}/report", headers=ANALYST)).json()
        assert report["proposed_verdict"] == "suspicious"
        assert report["partial"] is False
        assert (
            len(report["executed_queries"]) == 1
        ), "the query from before the interruption is present"

        audit = (await client.get(f"/api/hunts/{hunt_id}/audit", headers=ANALYST)).json()
        assert any(entry["type"] == "hunt_continued" for entry in audit)
        assert await repository.load_hunt_state(hunt_id) is None, "state purged after conclusion"
        options = (await client.get(f"/api/hunts/{hunt_id}/resume-options", headers=ANALYST)).json()
        assert options["continuable"] is False

    async def test_continue_requires_a_saved_state(self, app_context):
        client, runtime, repository = app_context
        runtime._gateway = FakeGateway([PLAN_COMPLETION, *SCRIPT])
        created = await _create_hunt(client, campaign=None, hypothesis="x" * 30)
        hunt_id = created["hunt_id"]
        await client.post(f"/api/hunts/{hunt_id}/plan", headers=ANALYST)
        await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        await runtime.get(hunt_id).task

        response = await client.post(f"/api/hunts/{hunt_id}/continue", headers=ANALYST)
        assert response.status_code == 400


class TestManualIocFeedback:
    async def test_duplicate_is_reported_not_silently_dropped(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(
            client,
            campaign=None,
            hypothesis="x" * 30,
            manual_iocs=[{"value": "evil.example", "type": "domain"}],
        )
        response = await client.post(
            f"/api/hunts/{created['hunt_id']}/iocs",
            json={"iocs": [{"value": "evil[.]example", "type": "domain"}]},
            headers=ANALYST,
        )
        outcome = response.json()
        assert outcome["added"] == 0
        assert outcome["duplicates"] == ["evil[.]example"]
        assert len(outcome["iocs"]) == 1


class TestStaleEnrichment:
    async def test_validation_during_a_search_discards_its_late_results(self, app_context):
        from middleware.guardrails.ioc import Ioc, IocStatus, IocType

        client, runtime, _ = app_context
        created = await _create_hunt(
            client,
            campaign=None,
            hypothesis="x" * 30,
            manual_iocs=[{"value": "evil.example", "type": "domain"}],
        )
        hunt_id = created["hunt_id"]
        hunt = await runtime.resolve(hunt_id)

        async def slow_search(name, arguments):
            await runtime.validate_iocs(
                hunt_id, validated=["evil.example"], rejected=[], analyst="jdoe"
            )
            hunt.dossier.iocs.append(
                Ioc(
                    value="late-result.example",
                    type=IocType.DOMAIN,
                    source_name="publisher",
                    source_url="https://publisher.example/report",
                    status=IocStatus.PENDING_VALIDATION,
                )
            )
            return {"iocs": 1}

        hunt.enrichment.dispatch = slow_search  # type: ignore[method-assign]
        iocs = await runtime.enrich(
            hunt_id, campaign_name="Test campaign", ioc_types=None, max_results=10
        )

        values = {ioc.value: ioc.status.value for ioc in iocs}
        assert "late-result.example" not in values, "the late result is discarded"
        assert values["evil.example"] == "validated"
        assert hunt.dossier.status.value == "draft", "the checkpoint stays cleared"

        audit = (await client.get(f"/api/hunts/{hunt_id}/audit", headers=ANALYST)).json()
        stale = [
            entry
            for entry in audit
            if entry["type"] == "ioc_search" and entry["detail"].get("stale_discarded")
        ]
        assert stale and stale[0]["detail"]["stale_discarded"] == 1

        started = await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json=BUDGETS)
        assert started.status_code == 200, started.text


class TestOwnPassword:
    async def _login(self, client, username, password):
        return await client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )

    async def test_any_user_can_change_their_own_password(self, config_context):
        client, _, _ = config_context
        await client.put(
            "/api/config/secrets/OTX_API_KEY", headers=ADMIN, json={"value": "seed"}
        )  # no purpose, just to materialize the context

        created = await client.post(
            "/api/config/accounts",
            headers=ADMIN,
            json={
                "username": "l.reader",
                "password": "Password-Initial-1",
                "roles": ["reader"],
            },
        )
        assert created.status_code == 201, created.text
        login = await self._login(client, "l.reader", "Password-Initial-1")
        assert login.status_code == 200
        cookie = login.cookies

        refused = await client.post(
            "/api/auth/password",
            cookies=cookie,
            json={"current_password": "wrong", "new_password": "Password-New-1"},
        )
        assert refused.status_code == 400
        assert "Current password" in refused.json()["detail"]

        short = await client.post(
            "/api/auth/password",
            cookies=cookie,
            json={"current_password": "Password-Initial-1", "new_password": "short"},
        )
        assert short.status_code == 400

        changed = await client.post(
            "/api/auth/password",
            cookies=cookie,
            json={
                "current_password": "Password-Initial-1",
                "new_password": "Password-New-1",
            },
        )
        assert changed.status_code == 204, changed.text

        assert (await self._login(client, "l.reader", "Password-Initial-1")).status_code == 401
        assert (await self._login(client, "l.reader", "Password-New-1")).status_code == 200

        audit = (await client.get("/api/hunts/platform/audit", headers=ADMIN)).json()
        assert any(entry["type"] == "account_password_changed" for entry in audit)


class TestIocFileImport:
    async def test_imported_indicators_await_validation(self, app_context):
        client, runtime, _ = app_context
        created = await _create_hunt(
            client,
            campaign=None,
            hypothesis="x" * 30,
            manual_iocs=[{"value": "evil.example", "type": "domain"}],
        )
        hunt_id = created["hunt_id"]

        body = "evil[.]example\nnew.example\n185.220.101.42\nreport.pdf\n"
        response = await client.post(
            f"/api/hunts/{hunt_id}/iocs/import?filename=list.txt",
            headers=ANALYST,
            content=body.encode(),
        )
        assert response.status_code == 200, response.text
        outcome = response.json()
        assert outcome["added"] == 2
        assert outcome["duplicates"] == 1, "evil.example already present (defang normalized)"
        assert outcome["by_type"] == {"domain": 1, "ip": 1}

        statuses = {item["value"]: item["status"] for item in outcome["iocs"]}
        assert statuses["new.example"] == "pending_validation"
        assert statuses["185.220.101.42"] == "pending_validation"
        assert statuses["evil.example"] == "validated", "the existing one is not modified"

        listed = (await client.get("/api/hunts", headers=ANALYST)).json()
        assert next(h for h in listed if h["hunt_id"] == hunt_id)["status"] == (
            "awaiting_ioc_validation"
        ), "the checkpoint applies to imported ones"

        audit = (await client.get(f"/api/hunts/{hunt_id}/audit", headers=ANALYST)).json()
        entry = next(e for e in audit if e["type"] == "ioc_import")
        assert entry["detail"]["filename"] == "list.txt"
        assert entry["detail"]["added"] == 2

    async def test_import_is_reserved_to_analysts(self, app_context):
        client, _, _ = app_context
        created = await _create_hunt(client, campaign=None, hypothesis="x" * 30)
        response = await client.post(
            f"/api/hunts/{created['hunt_id']}/iocs/import",
            headers=READER,
            content=b"evil.example",
        )
        assert response.status_code == 403
