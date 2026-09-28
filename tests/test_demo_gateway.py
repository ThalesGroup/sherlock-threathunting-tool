"""The scripted gateway drives a complete hunt through the real platform: playbook,
loop, executor, anonymization, findings and report, without any model."""

import httpx
import pytest

from api.app import create_app
from api.runtime import HuntRuntime, SiemClients
from middleware.clients.simulated import SimulatedSiemClient
from middleware.config import Settings
from orchestrator.demo_gateway import ScriptedGateway
from storage.repository import Database, HuntRepository, SqlAuditSink

ANALYST = {"X-Dev-User": "j.doe", "X-Dev-Roles": "analyst"}


@pytest.fixture
async def demo_context(tmp_path):
    database = Database(f"sqlite+aiosqlite:///{tmp_path}/demo.db")
    await database.create_all()
    repository = HuntRepository(database)
    settings = Settings(
        _env_file=None,
        workspace_aliases={"soc-principal": "guid-demo"},
        semantic_anonymization=False,
    )
    runtime = HuntRuntime(
        settings=settings,
        repository=repository,
        audit_sink=SqlAuditSink(database),
        gateway=ScriptedGateway(delay_seconds=0),
        clients=SiemClients(
            sentinel=SimulatedSiemClient(siem="sentinel"),
            defender=SimulatedSiemClient(siem="defender"),
        ),
    )
    app = create_app(settings=settings, runtime=runtime, repository=repository, database=database)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, runtime, repository
    await database.dispose()


async def test_scripted_hunt_runs_end_to_end(demo_context):
    client, runtime, repository = demo_context
    created = await client.post(
        "/api/hunts",
        json={"hypothesis": "Living-off-the-land lateral movement towards the domain controllers."},
        headers=ANALYST,
    )
    assert created.status_code == 201, created.text
    hunt_id = created["hunt_id"] if isinstance(created, dict) else created.json()["hunt_id"]

    planned = await client.post(f"/api/hunts/{hunt_id}/plan", headers=ANALYST, json={})
    assert planned.status_code == 200, planned.text
    assert [step["technique"] for step in planned.json()["steps"]][:2] == ["T1047", "T1090.001"]

    started = await client.post(f"/api/hunts/{hunt_id}/start", headers=ANALYST, json={})
    assert started.status_code == 200, started.text
    await runtime.get(hunt_id).task

    report = await repository.load_report(hunt_id)
    assert report is not None
    assert report.proposed_verdict.value == "escalate"
    assert report.status.value == "awaiting_review"
    assert len(report.executed_queries) == 4
    assert {finding.severity.value for finding in report.findings} == {"critical", "high", "medium"}
    assert all(finding.evidence_query_ids for finding in report.findings)
    # The reasoning was written with pseudonyms; the analyst reads real identifiers.
    assert any(
        "PAR-FS-03" in query.interpretation
        for query in report.executed_queries
        if query.interpretation
    )
    entities = {entity.value for finding in report.findings for entity in finding.entities}
    assert any("PAR-DC-01" in value for value in entities), entities
    assert report.attack_overview is not None and len(report.attack_overview.techniques) == 4
    assert len(report.timeline) == 5


def test_scripted_gateway_is_refused_outside_dev(tmp_path):
    settings = Settings(
        _env_file=None,
        environment="prod",
        demo_gateway=True,
        database_url=f"sqlite+aiosqlite:///{tmp_path}/x.db",
    )
    with pytest.raises(RuntimeError, match="SHL_DEMO_GATEWAY"):
        create_app(settings=settings)
