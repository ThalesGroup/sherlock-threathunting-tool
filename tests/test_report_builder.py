"""Report building: attack presentation and scope computed by the code."""

from middleware.budgets import Budgets, HuntBudget
from reporting.dossier import Dossier
from reporting.models import AttackTechnique, Verdict
from reporting.report import (
    build_report,
    describe_anonymization,
    describe_scope,
    format_window,
    to_markdown,
)


def _dossier() -> Dossier:
    return Dossier(hunt_id="hunt_1", hypothesis="Lateral movement via WMI", analyst="jdoe")


class TestAnonymizationDescription:
    def test_counts_and_semantic_state_are_spelled_out(self):
        text = describe_anonymization(
            {
                "semantic": "degraded",
                "tokenization": True,
                "masked_fields": 2,
                "tokens": {"HOST": 3, "USER": 0, "IP-INT": 1, "DATA": 4},
            }
        )
        assert text == (
            "3 host(s), 1 internal IP(s), 4 free-text fragment(s) pseudonymized ; "
            "semantic pass degraded, 2 field(s) masked for safety"
        )

    def test_untraced_query_is_said_so(self):
        assert describe_anonymization({}) == "anonymization not traced"


class TestAttackOverview:
    def test_conclusion_fields_flow_into_the_report(self):
        dossier = _dossier()
        dossier.conclude(
            verdict=Verdict.BENIGN,
            summary="No signal over the analyzed period.",
            limitations="Defender not covered.",
            attack_description="An attacker already present repurposes WMI to move.",
            techniques=[
                AttackTechnique(id="T1047", name="Execution via WMI", description="wmic /node.")
            ],
            recommendation="No action, monitoring maintained.",
        )
        report = build_report(
            dossier,
            HuntBudget(limits=Budgets()),
            sources=["sentinel"],
            investigation_window="2026-06-01T00:00:00+00:00 -> 2026-06-08T00:00:00+00:00",
        )

        assert report.attack_overview is not None
        assert report.attack_overview.description.startswith("An attacker")
        assert [t.id for t in report.attack_overview.techniques] == ["T1047"]
        assert "01/06/2026 -> 08/06/2026" in report.attack_overview.scope
        assert "Sentinel" in report.attack_overview.scope
        assert report.recommendation == "No action, monitoring maintained."
        assert report.sources == ["sentinel"]

    def test_interrupted_hunt_falls_back_to_the_hypothesis(self):
        report = build_report(
            _dossier(),
            HuntBudget(limits=Budgets()),
            partial=True,
            interruption_reason="budget exhausted",
            sources=[],
        )
        assert report.attack_overview is not None
        assert report.attack_overview.description == "Lateral movement via WMI"
        assert report.attack_overview.techniques == []
        assert "no accessible SIEM source" in report.attack_overview.scope
        assert report.recommendation is None

    def test_scope_is_computed_by_the_platform(self):
        scope = describe_scope(
            HuntBudget(limits=Budgets(max_siem_queries=15, max_iterations=20)),
            sources=["defender", "secops"],
            investigation_window=None,
            executed=3,
            campaign="Volt Typhoon",
        )
        assert "Defender, SecOps" in scope
        assert "Volt Typhoon" in scope
        assert "3 query(ies) executed out of a budget of 15" in scope

    def test_format_window_tolerates_unexpected_input(self):
        assert format_window("anything") == "anything"
        assert format_window("2026-06-01T00:00:00+00:00 -> not-a-date") == (
            "01/06/2026 -> not-a-date"
        )

    def test_markdown_carries_the_agents_reading(self):
        from reporting.models import ExecutedQuery

        dossier = _dossier()
        dossier.conclude(
            verdict=Verdict.BENIGN,
            summary="No signal over the analyzed period.",
            limitations="Nothing.",
        )
        report = build_report(dossier, HuntBudget(limits=Budgets()), sources=[])
        report.executed_queries.append(
            ExecutedQuery(
                query_id="q_1",
                siem="sentinel",
                query="SigninLogs",
                executed_at="2026-07-01T10:00:00Z",
                returned_rows=2,
                source_rows=2,
                truncated=False,
                duration_ms=5,
                interpretation="Both hosts are known administration servers.",
            )
        )
        markdown = to_markdown(report)
        assert (
            "Agent's reading: Both hosts are known administration servers."
            in markdown
        )

    def test_markdown_carries_the_attack_section(self):
        dossier = _dossier()
        dossier.conclude(
            verdict=Verdict.SUSPICIOUS,
            summary="An unusual service account.",
            limitations="Nothing.",
            attack_description="Description of the attack under investigation.",
            techniques=[AttackTechnique(id="T1047", name="WMI", description="wmic /node.")],
            recommendation="Review the scripts.",
        )
        markdown = to_markdown(build_report(dossier, HuntBudget(limits=Budgets()), sources=[]))
        assert "## The attack under investigation" in markdown
        assert "**T1047** WMI" in markdown
        assert "**Recommendation**: Review the scripts." in markdown
