"""Knowledge base: bounded loading and injection into the briefing.

Two properties locked down: only files known to the repository reach the
briefing, and each sheet is injected only for the sources retained by the hunt.
"""

from orchestrator.knowledge import load_knowledge
from orchestrator.prompts import hunt_briefing


def _briefing(knowledge, sources=("sentinel",)):
    return hunt_briefing(
        hypothesis="Living off the land activity on the backup servers",
        campaign=None,
        iocs_summary=[],
        available_sources=list(sources),
        budgets={"max_iterations": 20, "max_siem_queries": 15, "max_duration_seconds": 900},
        knowledge=knowledge,
    )


class TestLoadKnowledge:
    def test_only_known_files_are_loaded(self, tmp_path):
        (tmp_path / "sentinel.md").write_text("Useful tables: SigninLogs.")
        (tmp_path / "other.md").write_text("never loaded")

        knowledge = load_knowledge(tmp_path)

        assert set(knowledge) == {"sentinel"}

    def test_missing_directory_yields_empty_knowledge(self, tmp_path):
        assert load_knowledge(tmp_path / "nonexistent") == {}

    def test_content_is_capped(self, tmp_path):
        (tmp_path / "defender.md").write_text("x" * 20_000)
        knowledge = load_knowledge(tmp_path)
        assert len(knowledge["defender"]) == 9_000

    def test_template_made_of_comments_is_not_loaded(self, tmp_path):
        (tmp_path / "environment.md").write_text("<!--\n## to fill in\n-->\n")
        assert load_knowledge(tmp_path) == {}

    def test_repository_template_is_inert_until_filled(self):
        knowledge = load_knowledge("knowledge")
        assert "environment" not in knowledge
        assert {"sentinel", "defender", "secops"} <= set(knowledge)


class TestBriefingInjection:
    def test_only_selected_sources_get_their_sheet(self):
        knowledge = {"sentinel": "Table SigninLogs.", "defender": "Table DeviceProcessEvents."}
        briefing = _briefing(knowledge, sources=("sentinel",))

        assert "## sentinel reference" in briefing
        assert "SigninLogs" in briefing
        assert "DeviceProcessEvents" not in briefing

    def test_environment_sheet_is_always_injected_when_filled(self):
        knowledge = {"environment": "Backup servers are SRV-BKP-*."}
        briefing = _briefing(knowledge, sources=("defender",))

        assert "## Environment specifics" in briefing
        assert "SRV-BKP-" in briefing

    def test_without_knowledge_the_briefing_is_unchanged(self):
        briefing = _briefing({}, sources=("sentinel",))
        assert "## Reference" not in briefing
        assert "## Environment specifics" not in briefing
