"""PDF export: generated locally, complete, with no external dependency.

Expected structure: cover page, presentation of the attack under investigation, report
(proposed verdict, findings, entities, execution log, decision), query appendix.
"""

from io import BytesIO

from pypdf import PdfReader

from reporting import pdf as pdf_module
from reporting.models import (
    AttackOverview,
    AttackTechnique,
    Confidence,
    Entity,
    ExecutedQuery,
    Finding,
    HumanDecision,
    HuntReport,
    HuntStatus,
    Playbook,
    PlaybookStep,
    Severity,
    TimelineEvent,
    Verdict,
)
from reporting.pdf import to_pdf


def _report(**overrides):
    base = dict(
        hunt_id="hunt_pdf_test",
        hypothesis="Suspected compromise of a service account via living off the land.",
        campaign="Volt Typhoon",
        analyst="j.doe",
        status=HuntStatus.AWAITING_REVIEW,
        proposed_verdict=Verdict.SUSPICIOUS,
        summary="Repeated nighttime connections from an unusual workstation.",
        limitations="Defender not queried: retention window exceeded.",
        iocs=[{"value": "45.155.12.7", "type": "ip", "source": "CIRCL OSINT (MISP)"}],
        findings=[
            Finding(
                id="f_1",
                title="Off-hours connections",
                description="The svc-backup account opens sessions at 03:00 AM.",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                entities=[Entity(type="account", value="svc-backup")],
                evidence_query_ids=["q_1"],
            )
        ],
        timeline=[
            TimelineEvent(
                timestamp="2026-07-01T03:12:00Z",
                event="First abnormal connection",
                source="sentinel",
            )
        ],
        executed_queries=[
            ExecutedQuery(
                query_id="q_1",
                siem="sentinel",
                query="SigninLogs | where TimeGenerated > ago(7d)",
                executed_at="2026-07-01T10:00:00Z",
                returned_rows=42,
                source_rows=42,
                truncated=False,
                duration_ms=1200,
                intent="Off-hours connections for the service account",
                columns=["Account", "Hour"],
                sample=[{"Account": "svc-backup", "Hour": 3}],
                model_sample=[{"Account": "USER-001", "Hour": 3}],
                anonymization={
                    "semantic": "active",
                    "tokenization": True,
                    "masked_fields": 0,
                    "tokens": {"HOST": 0, "USER": 1, "IP-INT": 0, "DATA": 0},
                },
                interpretation=(
                    "Only two nighttime connections, both from the on-call "
                    "workstation: profile consistent with a planned intervention."
                ),
            )
        ],
        budgets={"iterations": {"used": 5, "limit": 20}},
        sources=["sentinel", "defender"],
        investigation_window="2026-06-24T00:00:00+00:00 -> 2026-07-01T10:00:00+00:00",
        recommendation="Have the AD team review the svc-backup account's scripts.",
        playbook=Playbook(
            summary="Look for nighttime connections then correlate with the hosts.",
            steps=[
                PlaybookStep(
                    order=1,
                    siem="sentinel",
                    objective="Spot nighttime session logons",
                    technique="T1078",
                    expected_queries=3,
                )
            ],
            not_covered="Defender absent from this installation.",
            estimated_queries=3,
            estimated_iterations=6,
            generated_at="2026-07-01T09:00:00Z",
            validated_by="j.doe",
            validated_at="2026-07-01T09:05:00Z",
            validated_queries=5,
            validated_iterations=6,
        ),
        attack_overview=AttackOverview(
            description=(
                "An attacker already present repurposes native admin tools "
                "to move without dropping a binary."
            ),
            techniques=[
                AttackTechnique(
                    id="T1059.001",
                    name="Obfuscated PowerShell",
                    description="Encoded commands and hidden windows to conceal code.",
                ),
                AttackTechnique(
                    id="T1047",
                    name="Execution via WMI",
                    description="wmic process call create to a remote host.",
                ),
            ],
            scope="Investigation period 24/06/2026 -> 01/07/2026 on Sentinel, Defender.",
        ),
    )
    base.update(overrides)
    return HuntReport(**base)


def _pages(document: bytes) -> list[str]:
    return [page.extract_text() for page in PdfReader(BytesIO(document)).pages]


class TestPdfExport:
    def test_produces_a_valid_pdf(self):
        document = to_pdf(_report())
        assert document.startswith(b"%PDF")
        assert len(document) > 1500

    def test_cover_page_then_attack_presentation(self):
        pages = _pages(to_pdf(_report(), organisation="SOC FR-PAR-01"))
        cover, attack = pages[0], pages[1]

        assert "SOC FR-PAR-01" in cover
        assert "INVESTIGATION REPORT" in cover
        assert "hunt_pdf_test" in cover
        assert "SUSPICIOUS" in cover
        assert "24/06/2026" in cover and "01/07/2026" in cover
        assert "Sentinel, Defender" in cover

        assert "The attack under investigation" in attack
        assert "T1059.001" in attack and "T1047" in attack
        assert "Obfuscated PowerShell" in attack
        assert "HUNT SCOPE" in attack
        everything = "\n".join(pages)
        assert "Playbook" in everything and "T1078" in everything
        assert "NOT COVERED BY THE PLAN" in everything

    def test_body_content_is_present(self):
        text = "\n".join(_pages(to_pdf(_report())))
        assert "Off-hours connections" in text
        assert "svc-backup" in text
        assert "SigninLogs" in text
        assert "RECOMMENDATION" in text
        assert "INVESTIGATION LIMITATIONS" in text
        assert "AWAITING VALIDATION" in text
        assert "EVIDENCE" in text and "q_1" in text
        assert "Off-hours connections" in text
        assert "SAMPLE" in text and "Account: svc-backup" in text
        assert "TRANSMITTED TO THE MODEL" in text and "Account: USER-001" in text
        assert "1 ACCOUNT(S) PSEUDONYMIZED" in text.upper()
        assert "AGENT'S READING" in text
        assert "workstation" in text and "on-call" in text
        assert "semantic 1/1" in text
        assert "RESTRICTED DISTRIBUTION" in text

    def test_human_decision_and_partial_are_rendered(self):
        report = _report(
            partial=True,
            interruption_reason="budget exhausted",
            human_decision=HumanDecision(
                verdict=Verdict.ESCALATE,
                decided_by="a.senior",
                decided_at="2026-07-02T09:00:00Z",
                comment="To escalate to the CERT.",
            ),
        )
        text = "\n".join(_pages(to_pdf(report)))
        assert "a.senior" in text
        assert "budget exhausted" in text
        assert "PARTIAL REPORT" in text
        assert "corrects the proposal" in text

    def test_report_without_overview_still_renders(self):
        report = _report(attack_overview=None, recommendation=None, sources=[], findings=[])
        pages = _pages(to_pdf(report))
        assert "No MITRE ATT&CK technique" in pages[1]
        assert "No findings recorded" in "\n".join(pages)

    def test_unicode_outside_latin1_does_not_crash(self):
        report = _report(summary="Summary with emoji \U0001f512 and letter ł.")
        assert to_pdf(report).startswith(b"%PDF")

    def test_falls_back_to_core_fonts_without_dejavu(self, monkeypatch, tmp_path):
        monkeypatch.setattr(pdf_module, "_FONT_DIR", tmp_path)
        document = to_pdf(_report(summary="Accented summary \U0001f512"))
        assert document.startswith(b"%PDF")
        assert "hunt_pdf_test" in "\n".join(_pages(document))
