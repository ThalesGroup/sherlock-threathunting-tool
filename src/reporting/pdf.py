"""PDF export of the investigation report.

Generated locally (fpdf2, pure Python): no data leaves the platform to produce the
document. Document structure: cover page, overview of the attack under investigation,
then the report (proposed verdict, findings, entities, execution log, analyst decision).
The agent's verdict remains a proposal; the human decision is displayed when it exists.

Fonts: DejaVu (Sans and Sans Mono) when installed, to cover accents; otherwise the PDF
base fonts with a latin-1 fallback.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from reporting.models import Finding, HuntReport, Verdict
from reporting.report import describe_anonymization, summarize_anonymization

_FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
_FONT_FILES = {
    ("sans", ""): "DejaVuSans.ttf",
    ("sans", "B"): "DejaVuSans-Bold.ttf",
    ("mono", ""): "DejaVuSansMono.ttf",
    ("mono", "B"): "DejaVuSansMono-Bold.ttf",
}

_MARGIN = 18
_RESTRICTED = "RESTRICTED DISTRIBUTION"
_PDF_SAMPLE_ROWS = 5
_FOOTER_NOTICE = "RESTRICTED DISTRIBUTION · DO NOT SHARE OUTSIDE THE SOC SCOPE"

_INK = (0x12, 0x21, 0x2F)
_NAVY = (0x0D, 0x1E, 0x33)
_SLATE = (0x5B, 0x6B, 0x7C)
_META = (0x84, 0x94, 0xA3)
_TEXT = (0x24, 0x35, 0x44)
_TEXT_SOFT = (0x3D, 0x4D, 0x5C)
_ACCENT = (0x2B, 0x8F, 0xD6)
_RULE = (0xD3, 0xDA, 0xE1)
_RULE_SOFT = (0xEE, 0xF1, 0xF4)
_BG_SOFT = (0xF6, 0xF8, 0xFA)
_WHITE = (0xFF, 0xFF, 0xFF)
_AMBER = (0xA8, 0x56, 0x0B)
_AMBER_BG = (0xF7, 0xEC, 0xDF)

_VERDICTS: dict[str, tuple[str, tuple[int, int, int], tuple[int, int, int]]] = {
    "benign": ("BENIGN", (0x14, 0x6B, 0x48), (0xE6, 0xF2, 0xEC)),
    "suspicious": ("SUSPICIOUS", _AMBER, _AMBER_BG),
    "escalate": ("ESCALATE", (0x8F, 0x1D, 0x1D), (0xF6, 0xE3, 0xE3)),
    "inconclusive": ("INCONCLUSIVE", _SLATE, _RULE_SOFT),
}
_SEVERITIES: dict[str, tuple[str, tuple[int, int, int], tuple[int, int, int]]] = {
    "critical": ("CRITICAL", (0x8F, 0x1D, 0x1D), (0xF6, 0xE3, 0xE3)),
    "high": ("HIGH", _AMBER, _AMBER_BG),
    "medium": ("MEDIUM", (0xA8, 0x71, 0x0B), (0xF8, 0xEF, 0xDC)),
    "low": ("LOW", (0x1F, 0x6F, 0x5C), (0xE3, 0xF0, 0xEC)),
    "info": ("INFO", _SLATE, _RULE_SOFT),
}
_CONFIDENCES = {
    "low": "LOW CONFIDENCE",
    "medium": "MEDIUM CONFIDENCE",
    "high": "HIGH CONFIDENCE",
}
_SOURCES = {"sentinel": "Sentinel", "defender": "Defender", "secops": "SecOps"}


def to_pdf(report: HuntReport, *, organisation: str = "SOC") -> bytes:
    document = _Document(report, organisation=organisation)
    document.render()
    return bytes(document.output())


class _Document(FPDF):
    def __init__(self, report: HuntReport, *, organisation: str) -> None:
        super().__init__(format="A4")
        self._report = report
        self._organisation = organisation.strip() or "SOC"
        self._cover = True
        self._frame_page = 0
        self._table: tuple[list[str], list[float]] = ([], [])
        self._unicode = self._load_fonts()
        self.set_margins(_MARGIN, _MARGIN + 6, _MARGIN)
        self.set_auto_page_break(auto=True, margin=_MARGIN + 6)
        self.set_title(f"Investigation report {report.hunt_id}")

    # ------------------------------------------------------------------ fonts

    def _load_fonts(self) -> bool:
        paths = {key: _FONT_DIR / name for key, name in _FONT_FILES.items()}
        if not all(path.is_file() for path in paths.values()):
            return False
        for (family, style), path in paths.items():
            self.add_font(family, style=style, fname=str(path))
        return True

    def _font(self, family: str, size: float, *, bold: bool = False) -> None:
        style = "B" if bold else ""
        if self._unicode:
            self.set_font(family, style=style, size=size)
        else:
            self.set_font("helvetica" if family == "sans" else "courier", style=style, size=size)

    def _t(self, text: str) -> str:
        if self._unicode:
            return text
        return text.encode("latin-1", "replace").decode("latin-1")

    # ------------------------------------------------------------ header / footer

    def header(self) -> None:
        if self._cover:
            return
        y = 11
        self.set_fill_color(*_ACCENT)
        self.rect(_MARGIN, y - 1.2, 2.6, 2.6, style="F", round_corners=True, corner_radius=0.6)
        self._font("mono", 7, bold=True)
        self.set_text_color(*_SLATE)
        self.set_xy(_MARGIN + 5, y - 2.5)
        self.cell(0, 5, self._t(f"THREAT HUNTING · {self._organisation.upper()}"))
        self.set_text_color(*_META)
        self.set_xy(_MARGIN, y - 2.5)
        self.cell(0, 5, self._report.hunt_id, align="R")
        self.set_draw_color(*_RULE)
        self.line(_MARGIN, y + 4.5, self.w - _MARGIN, y + 4.5)
        self.set_y(_MARGIN + 6)

    def footer(self) -> None:
        if self._cover:
            return
        y = self.h - 12
        self.set_draw_color(*_RULE)
        self.line(_MARGIN, y - 2.5, self.w - _MARGIN, y - 2.5)
        self._font("mono", 6.5)
        self.set_text_color(*_META)
        self.set_xy(_MARGIN, y)
        self.cell(0, 4, self._t(_FOOTER_NOTICE))
        self.set_xy(_MARGIN, y)
        generated = _format_datetime(self._report.generated_at)
        self.cell(
            0,
            4,
            self._t(
                f"GENERATED ON {generated} · {self._report.analyst.upper()} · P. {self.page_no()}"
            ),
            align="R",
        )

    # ---------------------------------------------------------------- rendering

    def render(self) -> None:
        self._cover_page()
        self._cover = False
        self._attack_page()
        self._body()

    @property
    def _content_width(self) -> float:
        return self.w - 2 * _MARGIN

    def _cover_page(self) -> None:
        report = self._report
        self.add_page()

        self.set_fill_color(*_ACCENT)
        self.rect(_MARGIN, 24, 4, 4, style="F", round_corners=True, corner_radius=1)
        self._font("mono", 9, bold=True)
        self.set_text_color(*_INK)
        self.set_xy(_MARGIN + 7, 22.5)
        self.cell(0, 7, self._t(self._organisation.upper()))
        self._chip(_RESTRICTED, fg=_SLATE, bg=_WHITE, border=_RULE, right=True, y=22.5)

        self.set_xy(_MARGIN, 92)
        self._font("mono", 8.5)
        self.set_text_color(*_SLATE)
        self.cell(
            0,
            6,
            self._t("INVESTIGATION REPORT · THREAT HUNTING"),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(4)
        title_size, title_height = _title_metrics(report.hypothesis)
        self._font("sans", title_size, bold=True)
        self.set_text_color(*_NAVY)
        self.multi_cell(
            self._content_width * 0.85,
            title_height,
            self._t(report.hypothesis),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(6)
        self._font("mono", 10.5)
        self.set_text_color(*_SLATE)
        self.cell(self.get_string_width(report.hunt_id) + 2, 8, report.hunt_id)
        label, fg, bg = _VERDICTS[report.proposed_verdict.value]
        self._chip(f"PROPOSED VERDICT · {label}", fg=fg, bg=bg, y=self.get_y() + 1.2)
        if report.partial:
            self._chip(
                "PARTIAL REPORT",
                fg=_AMBER,
                bg=_AMBER_BG,
                y=self.get_y() + 1.2,
                x=self.get_x() + 3,
            )

        y = self.h - 52
        self.set_draw_color(*_NAVY)
        self.set_line_width(0.4)
        self.line(_MARGIN, y, self.w - _MARGIN, y)
        self.set_line_width(0.2)
        cells = [
            ("ANALYST", report.analyst),
            ("PERIOD COVERED", _window_label(report)),
            ("SOURCES", _sources_label(report)),
            ("GENERATED ON", _format_datetime(report.generated_at)),
        ]
        self._meta_row(cells, y + 5, width=self._content_width / 4)

    def _attack_page(self) -> None:
        overview = self._report.attack_overview
        self.add_page()
        self._section_title("The attack under investigation", "HUNT HYPOTHESIS · MITRE ATT&CK")

        description = overview.description if overview else self._report.hypothesis
        self._font("sans", 10.5)
        self.set_text_color(*_TEXT)
        self.multi_cell(
            self._content_width, 6.2, self._t(description), new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.ln(5)

        techniques = overview.techniques if overview else []
        if techniques:
            gap = 4
            width = (self._content_width - gap) / 2
            index = 0
            while index < len(techniques):
                pair = techniques[index : index + 2]
                heights = [self._technique_height(t.name, t.description, width) for t in pair]
                row_height = max(heights)
                if self.get_y() + row_height > self.page_break_trigger:
                    self.add_page()
                top = self.get_y()
                for column, technique in enumerate(pair):
                    x = _MARGIN + column * (width + gap)
                    self._technique_card(
                        technique.id,
                        technique.name,
                        technique.description,
                        x,
                        top,
                        width,
                        row_height,
                    )
                self.set_y(top + row_height + gap)
                index += 2
            self.ln(2)
        else:
            self._font("sans", 9)
            self.set_text_color(*_META)
            self.multi_cell(
                self._content_width,
                5,
                self._t("No MITRE ATT&CK technique was attached to this hunt by the agent."),
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            self.ln(4)

        scope = overview.scope if overview else ""
        if scope:
            self._callout("HUNT SCOPE", scope, bar=_NAVY)
        self._playbook_section()

    def _playbook_section(self) -> None:
        playbook = self._report.playbook
        if playbook is None:
            return
        caption = (
            f"PROPOSED BY THE AGENT · VALIDATED BY {playbook.validated_by.upper()}"
            if playbook.validated_by
            else "PROPOSED BY THE AGENT · NOT VALIDATED"
        )
        self._section_title("Playbook", caption)
        self._font("sans", 10)
        self.set_text_color(*_TEXT)
        self.multi_cell(
            self._content_width,
            5.6,
            self._t(playbook.summary),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(3)
        widths = [10, 22, 98, 22, 22]
        self._table_head(["#", "SIEM", "OBJECTIVE", "TECHNIQUE", "PLANNED"], widths)
        for step in playbook.steps:
            self._table_row(
                [
                    (str(step.order), "mono", _META),
                    (_SOURCES.get(step.siem, step.siem), "sans", _SLATE),
                    (step.objective, "sans", _TEXT_SOFT),
                    (step.technique or "", "mono", _SLATE),
                    (str(step.expected_queries), "mono", _INK),
                ],
                widths,
                align_last="R",
            )
        executed = self._report.executed_by_siem()
        executed_label = ", ".join(
            f"{_SOURCES.get(siem, siem)} {count}" for siem, count in sorted(executed.items())
        )
        validated = (
            f"validated: {playbook.validated_queries} queries / "
            f"{playbook.validated_iterations} iterations"
            if playbook.validated_by
            else "not validated"
        )
        self.ln(1.5)
        self._font("mono", 7)
        self.set_text_color(*_SLATE)
        self.multi_cell(
            self._content_width,
            4.2,
            self._t(
                f"Estimate: {playbook.estimated_queries} queries / "
                f"{playbook.estimated_iterations} iterations · {validated} · executed: "
                f"{sum(executed.values())} query(ies)"
                + (f" ({executed_label})" if executed_label else "")
            ),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(4)
        self._callout("NOT COVERED BY THE PLAN", playbook.not_covered, bar=_SLATE)

    def _body(self) -> None:
        report = self._report
        self.add_page()

        top = self.get_y()
        self.set_fill_color(*_NAVY)
        self.rect(_MARGIN, top, 1.4, 16, style="F")
        self.set_xy(_MARGIN + 5, top)
        self._font("mono", 7.5)
        self.set_text_color(*_SLATE)
        self.cell(
            0, 5, self._t("INVESTIGATION REPORT"), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.set_x(_MARGIN + 5)
        self._font("sans", 16, bold=True)
        self.set_text_color(*_INK)
        self.multi_cell(
            self._content_width - 5,
            7.5,
            self._t(report.hypothesis),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(6)

        budgets = report.budgets
        iterations = budgets.get("iterations") or {}
        siem = budgets.get("siem_queries") or {}
        total_rows = sum(query.source_rows for query in report.executed_queries)
        width = self._content_width / 4
        y = self.get_y()
        self.set_draw_color(*_RULE_SOFT)
        self.line(_MARGIN, y, self.w - _MARGIN, y)
        self._meta_row(
            [
                ("REFERENCE", report.hunt_id),
                ("ANALYST", report.analyst),
                ("PERIOD COVERED", _window_label(report)),
                ("SOURCES", _sources_label(report)),
            ],
            y + 3,
            width=width,
        )
        y = self.get_y() + 1
        self.line(_MARGIN, y, self.w - _MARGIN, y)
        self._meta_row(
            [
                ("ITERATIONS", _ratio(iterations)),
                ("SIEM QUERIES", _ratio(siem)),
                ("EVENTS READ", str(total_rows)),
                ("ANONYMIZATION", summarize_anonymization(report)),
            ],
            y + 3,
            width=width,
        )
        y = self.get_y() + 1
        self.line(_MARGIN, y, self.w - _MARGIN, y)
        self.ln(8)

        if report.partial:
            self._callout(
                "PARTIAL REPORT",
                "The hunt was interrupted "
                f"({report.interruption_reason or 'reason unspecified'}). "
                "The unexplored leads are not documented.",
                bar=_AMBER,
                fill=_AMBER_BG,
            )

        self._verdict_block()
        self._findings()
        self._entities()
        self._timeline()
        self._iocs()
        self._journal()
        self._decision()
        self._queries_annex()

    # ------------------------------------------------------------- sections

    def _verdict_block(self) -> None:
        report = self._report
        label, fg, bg = _VERDICTS[report.proposed_verdict.value]
        decision = report.human_decision
        status = (
            f"VALIDATED BY {decision.decided_by.upper()} ON {_format_datetime(decision.decided_at)}"
            if decision
            else "AGENT PROPOSAL · AWAITING VALIDATION"
        )
        top = self.get_y()
        self._frame_start()
        self.set_xy(_MARGIN + 6, top + 5)
        self._font("sans", 11, bold=True)
        self.set_text_color(*_INK)
        self.cell(
            self.get_string_width(self._t("Proposed verdict")) + 4, 6, self._t("Proposed verdict")
        )
        self._chip(label, fg=fg, bg=bg, y=self.get_y() + 0.8, x=self.get_x())
        self._font("mono", 7)
        self.set_text_color(*_META)
        self.set_xy(self.get_x() + 3, self.get_y())
        self.cell(0, 6, self._t(status))
        self.set_xy(_MARGIN + 6, top + 14)
        self._font("sans", 10)
        self.set_text_color(*_TEXT)
        self.multi_cell(
            self._content_width - 12,
            5.8,
            self._t(report.summary),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        if report.recommendation:
            self.ln(3)
            self._inner_box("RECOMMENDATION", report.recommendation)
        self.ln(3)
        self._inner_box("INVESTIGATION LIMITATIONS", report.limitations)
        self._frame_end(
            top, bar=(0x1F, 0x8A, 0x5F) if report.proposed_verdict is Verdict.BENIGN else fg
        )
        self.ln(8)

    def _findings(self) -> None:
        findings = self._report.findings_by_severity()
        self._section_title("Findings", f"{len(findings)} FINDING(S) · SORTED BY SEVERITY")
        if not findings:
            self._font("sans", 9.5)
            self.set_text_color(*_META)
            self.multi_cell(
                self._content_width,
                5,
                self._t(
                    "No findings recorded: no evidence tied to an executed query."
                ),
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            self.ln(6)
            return
        for finding in findings:
            self._finding_card(finding)
        self.ln(4)

    def _finding_card(self, finding: Finding) -> None:
        label, fg, bg = _SEVERITIES[finding.severity.value]
        needed = 22 + self._text_height(finding.description, self._content_width - 12, 10, 5.6)
        if self.get_y() + min(needed, 120) > self.page_break_trigger:
            self.add_page()
        top = self.get_y()
        self._frame_start()
        self.set_xy(_MARGIN + 6, top + 5)
        self._chip(label, fg=fg, bg=bg, y=top + 5, x=_MARGIN + 6)
        title_x = self.get_x() + 3
        self._font("mono", 7)
        self.set_text_color(*_META)
        confidence = self._t(
            _CONFIDENCES.get(finding.confidence.value, finding.confidence.value.upper())
        )
        confidence_width = self.get_string_width(confidence) + 2
        self.set_xy(self.w - _MARGIN - 6 - confidence_width, top + 5)
        self.cell(confidence_width, 6, confidence, align="R")
        self.set_xy(title_x, top + 5)
        self._font("sans", 10.5, bold=True)
        self.set_text_color(*_INK)
        self.multi_cell(
            self.w - _MARGIN - 6 - confidence_width - title_x - 2,
            6,
            self._t(finding.title),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(1.5)
        self.set_x(_MARGIN + 6)
        self._font("sans", 10)
        self.set_text_color(*_TEXT_SOFT)
        self.multi_cell(
            self._content_width - 12,
            5.6,
            self._t(finding.description),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        if finding.entities:
            self.ln(2.5)
            x = _MARGIN + 6
            y = self.get_y()
            for entity in finding.entities:
                text = f"{entity.type.upper()}  {entity.value}"
                self._font("mono", 7.5)
                width = self.get_string_width(self._t(text)) + 6
                if x + width > self.w - _MARGIN - 6:
                    x = _MARGIN + 6
                    y += 7.5
                    if y + 8 > self.page_break_trigger:
                        self.add_page()
                        y = self.get_y()
                self._chip(
                    text, fg=_INK, bg=_BG_SOFT, border=_RULE_SOFT, x=x, y=y, mono_size=7.5
                )
                x += width + 2
            self.set_y(y + 7.5)
        self.ln(2)
        self.set_draw_color(*_RULE_SOFT)
        self.line(_MARGIN + 6, self.get_y(), self.w - _MARGIN - 6, self.get_y())
        self.set_xy(_MARGIN + 6, self.get_y() + 1.5)
        self._font("mono", 7)
        self.set_text_color(*_META)
        self.multi_cell(
            self._content_width - 12,
            4.5,
            self._t("EVIDENCE · " + " · ".join(finding.evidence_query_ids)),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self._frame_end(top, bar=fg)
        self.ln(4)

    def _entities(self) -> None:
        entities = self._report.observed_entities()
        if not entities:
            return
        self._section_title(
            "Observed entities", f"{len(entities)} ENTITY(IES) · CITED BY THE FINDINGS"
        )
        widths = [22, 78, 60, 14]
        self._table_head(["TYPE", "VALUE", "CONTEXT", "OCC."], widths)
        for entity, findings in entities:
            self._table_row(
                [
                    (entity.type.upper(), "mono", _META),
                    (entity.value, "mono", _INK),
                    (findings[0].title, "sans", _SLATE),
                    (str(len(findings)), "mono", _INK),
                ],
                widths,
                align_last="R",
            )
        self.ln(8)

    def _timeline(self) -> None:
        timeline = self._report.timeline
        if not timeline:
            return
        self._section_title("Timeline", f"{len(timeline)} EVENT(S)")
        for event in timeline:
            if self.get_y() + 12 > self.page_break_trigger:
                self.add_page()
            self.set_fill_color(*_ACCENT)
            self.rect(
                _MARGIN + 1,
                self.get_y() + 1.8,
                2,
                2,
                style="F",
                round_corners=True,
                corner_radius=1,
            )
            self.set_x(_MARGIN + 6)
            self._font("mono", 7.5)
            self.set_text_color(*_SLATE)
            self.cell(
                0,
                5,
                self._t(f"{event.timestamp}   {event.source.upper()}"),
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            self.set_x(_MARGIN + 6)
            self._font("sans", 9.5)
            self.set_text_color(*_INK)
            self.multi_cell(
                self._content_width - 6,
                5,
                self._t(event.event),
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            self.ln(2)
        self.ln(6)

    def _iocs(self) -> None:
        iocs = self._report.iocs
        if not iocs:
            return
        self._section_title("Validated indicators", f"{len(iocs)} INDICATOR(S) · SOURCE CITED")
        widths = [88, 22, 64]
        self._table_head(["VALUE", "TYPE", "SOURCE"], widths)
        for ioc in iocs:
            source = ioc.get("source") or ioc.get("source_name") or ""
            self._table_row(
                [
                    (str(ioc.get("value", "")), "mono", _INK),
                    (str(ioc.get("type", "")).upper(), "mono", _META),
                    (str(source), "sans", _SLATE),
                ],
                widths,
            )
        self.ln(8)

    def _journal(self) -> None:
        queries = self._report.executed_queries
        duration = (self._report.budgets.get("duration_seconds") or {}).get("used")
        self._section_title(
            "Execution log", f"{len(queries)} QUERY(IES) · DURATION {_duration(duration)}"
        )
        if not queries:
            self._font("sans", 9.5)
            self.set_text_color(*_META)
            self.cell(
                0, 5, self._t("No queries executed."), new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )
            self.ln(6)
            return
        widths = [18, 26, 20, 94, 16]
        self._table_head(["TIME", "REFERENCE", "SIEM", "OBJECTIVE", "ROWS"], widths)
        for query in queries:
            first_line = query.intent or next(
                (line.strip() for line in query.query.splitlines() if line.strip()), ""
            )
            rows = f"{query.returned_rows}{' ⚠' if query.truncated else ''}"
            self._table_row(
                [
                    (_format_time(query.executed_at), "mono", _SLATE),
                    (query.query_id, "mono", _INK),
                    (_SOURCES.get(query.siem, query.siem), "sans", _SLATE),
                    (first_line, "mono", _TEXT_SOFT),
                    (rows, "mono", _INK),
                ],
                widths,
                align_last="R",
            )
        self._font("mono", 6.5)
        self.set_text_color(*_META)
        self.ln(1)
        self.cell(
            0,
            4,
            self._t(
                "⚠ result truncated by the row cap · "
                "full query text in the appendix"
            ),
            align="L",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.ln(6)

    def _queries_annex(self) -> None:
        queries = self._report.executed_queries
        if not queries:
            return
        self.add_page()
        self._section_title(
            "Appendix · executed queries", "FULL TEXT · REPRODUCIBLE BY THE ANALYST"
        )
        for query in queries:
            if self.get_y() + 18 > self.page_break_trigger:
                self.add_page()
            self._font("mono", 8, bold=True)
            self.set_text_color(*_INK)
            flags = f" · {query.returned_rows} row(s)" + (" · truncated" if query.truncated else "")
            self.cell(
                0,
                5,
                self._t(
                    f"{query.query_id} · {_SOURCES.get(query.siem, query.siem)} · "
                    f"{_format_datetime(query.executed_at)}{flags}"
                ),
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            if query.intent:
                self._font("sans", 9)
                self.set_text_color(*_SLATE)
                self.multi_cell(
                    self._content_width,
                    4.8,
                    self._t(f"Objective: {query.intent}"),
                    align="L",
                    new_x=XPos.LMARGIN,
                    new_y=YPos.NEXT,
                )
            self._font("mono", 7.5)
            self.set_text_color(*_TEXT_SOFT)
            self.set_fill_color(*_BG_SOFT)
            self.multi_cell(
                self._content_width,
                4.2,
                self._t(query.query),
                fill=True,
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            if query.interpretation:
                self.ln(1.5)
                self._font("mono", 6.8, bold=True)
                self.set_text_color(*_SLATE)
                self.cell(0, 4, self._t("AGENT'S READING"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self._font("sans", 9)
                self.set_text_color(*_TEXT_SOFT)
                self.multi_cell(
                    self._content_width,
                    4.8,
                    self._t(query.interpretation),
                    align="L",
                    new_x=XPos.LMARGIN,
                    new_y=YPos.NEXT,
                )
            if query.anonymization:
                self.ln(1.5)
                self._font("mono", 6.8, bold=True)
                self.set_text_color(*_SLATE)
                self.cell(
                    0,
                    4,
                    self._t(
                        "ANONYMIZATION · " + describe_anonymization(query.anonymization).upper()
                    ),
                    new_x=XPos.LMARGIN,
                    new_y=YPos.NEXT,
                )
            self._sample_lines(
                f"SAMPLE · ANALYST VIEW · {len(query.sample)} ROW(S) OUT OF "
                f"{query.source_rows}",
                query.columns,
                query.sample,
            )
            self._sample_lines(
                "TRANSMITTED TO THE MODEL · PSEUDONYMS IN PLACE", query.columns, query.model_sample
            )
            self.ln(4)

    def _sample_lines(self, label: str, columns: list[str], rows: list[dict[str, Any]]) -> None:
        if not rows or not columns:
            return
        self.ln(1.5)
        self._font("mono", 6.8, bold=True)
        self.set_text_color(*_META)
        self.cell(0, 4, self._t(label), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self._font("mono", 6.8)
        self.set_text_color(*_TEXT_SOFT)
        for row in rows[:_PDF_SAMPLE_ROWS]:
            if self.get_y() + 5 > self.page_break_trigger:
                self.add_page()
            line = " · ".join(
                f"{column}: {row.get(column, '')}"
                for column in columns
                if row.get(column) not in (None, "")
            )
            self.cell(
                0,
                4,
                self._t(_truncate_to_width(self, line, self._content_width)),
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )

    def _decision(self) -> None:
        decision = self._report.human_decision
        if self.get_y() + 36 > self.page_break_trigger:
            self.add_page()
        else:
            self.ln(4)
        top = self.get_y()
        gap = 4
        right_width = 56
        left_width = self._content_width - right_width - gap
        height = 30
        self.set_draw_color(*_RULE)
        self.rect(_MARGIN, top, left_width, height, style="D", round_corners=True, corner_radius=3)
        self.rect(
            _MARGIN + left_width + gap,
            top,
            right_width,
            height,
            style="D",
            round_corners=True,
            corner_radius=3,
        )

        self.set_xy(_MARGIN + 5, top + 4)
        self._font("mono", 7)
        self.set_text_color(*_SLATE)
        self.cell(
            0, 4, self._t("ANALYST DECISION"), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.set_x(_MARGIN + 5)
        self._font("sans", 10.5, bold=True)
        self.set_text_color(*_INK)
        if decision:
            label = _VERDICTS[decision.verdict.value][0].capitalize()
            headline = f"Verdict {label.lower()}" + (
                " confirmed"
                if decision.verdict is self._report.proposed_verdict
                else " (corrects the proposal)"
            )
            detail = decision.comment or "No comment."
        else:
            headline = "Awaiting validation"
            detail = (
                "The agent's verdict is a proposal: it does not have the force of a decision "
                "until an analyst has confirmed it."
            )
        self.cell(
            left_width - 10, 6, self._t(headline), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.set_x(_MARGIN + 5)
        self._font("sans", 9)
        self.set_text_color(*_SLATE)
        self.multi_cell(
            left_width - 10, 4.6, self._t(detail), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )

        x = _MARGIN + left_width + gap + 5
        self.set_xy(x, top + 4)
        self._font("mono", 7)
        self.set_text_color(*_SLATE)
        self.cell(0, 4, "VALIDATION", align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(x)
        self._font("mono", 8.5)
        if decision:
            self.set_text_color(*_INK)
            self.cell(
                0, 5, self._t(decision.decided_by), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )
            self.set_x(x)
            self.set_text_color(*_META)
            self.cell(
                0,
                5,
                self._t(_format_datetime(decision.decided_at)),
                align="L",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
        else:
            self.set_text_color(*_META)
            self.cell(
                0, 5, self._t("not validated"), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )
        self.set_y(top + height)

    # ------------------------------------------------------------ primitives

    def _section_title(self, title: str, caption: str) -> None:
        if self.get_y() + 30 > self.page_break_trigger:
            self.add_page()
        y = self.get_y()
        self._font("sans", 13, bold=True)
        self.set_text_color(*_INK)
        self.set_xy(_MARGIN, y)
        self.cell(self._content_width * 0.55, 7, self._t(title))
        self._font("mono", 7)
        self.set_text_color(*_META)
        self.cell(self._content_width * 0.45, 7, self._t(caption), align="R")
        y += 8.5
        self.set_draw_color(*_NAVY)
        self.set_line_width(0.35)
        self.line(_MARGIN, y, self.w - _MARGIN, y)
        self.set_line_width(0.2)
        self.set_y(y + 5)

    def _chip(
        self,
        text: str,
        *,
        fg: tuple[int, int, int],
        bg: tuple[int, int, int],
        border: tuple[int, int, int] | None = None,
        x: float | None = None,
        y: float | None = None,
        right: bool = False,
        mono_size: float = 7,
    ) -> None:
        self._font("mono", mono_size, bold=True)
        label = self._t(text)
        width = self.get_string_width(label) + 6
        height = 6
        if y is None:
            y = self.get_y()
        if right:
            x = self.w - _MARGIN - width
        elif x is None:
            x = self.get_x()
        self.set_fill_color(*bg)
        if border:
            self.set_draw_color(*border)
            self.rect(x, y, width, height, style="DF", round_corners=True, corner_radius=1.5)
        else:
            self.rect(x, y, width, height, style="F", round_corners=True, corner_radius=1.5)
        self.set_text_color(*fg)
        self.set_xy(x, y)
        self.cell(width, height, label, align="C")
        self.set_xy(x + width, y)

    def _meta_row(self, cells: list[tuple[str, str]], y: float, *, width: float) -> None:
        bottom = y
        for index, (label, value) in enumerate(cells):
            x = _MARGIN + index * width
            self.set_xy(x, y)
            self._font("mono", 6.5)
            self.set_text_color(*_META)
            self.cell(width - 3, 4, self._t(label), align="L", new_x=XPos.LEFT, new_y=YPos.NEXT)
            self.set_x(x)
            self._font("mono", 8.5)
            self.set_text_color(*_INK)
            self.multi_cell(
                width - 3, 4.6, self._t(value), align="L", new_x=XPos.LEFT, new_y=YPos.NEXT
            )
            bottom = max(bottom, self.get_y())
        self.set_y(bottom + 2)

    def _callout(
        self,
        label: str,
        text: str,
        *,
        bar: tuple[int, int, int],
        fill: tuple[int, int, int] | None = None,
    ) -> None:
        height = 15 + self._text_height(text, self._content_width - 12, 9.5, 5.4)
        if self.get_y() + height > self.page_break_trigger:
            self.add_page()
        top = self.get_y()
        self.set_draw_color(*_RULE)
        if fill:
            self.set_fill_color(*fill)
            self.rect(
                _MARGIN,
                top,
                self._content_width,
                height,
                style="DF",
                round_corners=True,
                corner_radius=3,
            )
        else:
            self.rect(
                _MARGIN,
                top,
                self._content_width,
                height,
                style="D",
                round_corners=True,
                corner_radius=3,
            )
        self.set_fill_color(*bar)
        self.rect(_MARGIN, top + 1, 1.4, height - 2, style="F")
        self.set_xy(_MARGIN + 6, top + 4.5)
        self._font("mono", 7, bold=True)
        self.set_text_color(*_SLATE)
        self.cell(0, 4, self._t(label), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(_MARGIN + 6, self.get_y() + 1.5)
        self._font("sans", 9.5)
        self.set_text_color(*_TEXT_SOFT)
        self.multi_cell(
            self._content_width - 12, 5.4, self._t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.set_y(top + height)
        self.ln(8)

    def _inner_box(self, label: str, text: str) -> None:
        width = self._content_width - 12
        needed = 12 + self._text_height(text, width - 8, 9.5, 5.2)
        if self.get_y() + needed > self.page_break_trigger:
            self.add_page()
        top = self.get_y()
        self.set_fill_color(*_BG_SOFT)
        self.set_draw_color(*_RULE_SOFT)
        self.rect(
            _MARGIN + 6, top, width, needed, style="DF", round_corners=True, corner_radius=2.5
        )
        self.set_xy(_MARGIN + 10, top + 3.5)
        self._font("mono", 7, bold=True)
        self.set_text_color(*_SLATE)
        self.cell(0, 4, self._t(label), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(_MARGIN + 10, self.get_y() + 1)
        self._font("sans", 9.5)
        self.set_text_color(*_TEXT_SOFT)
        self.multi_cell(
            width - 8, 5.2, self._t(text), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.set_y(top + needed)

    def _frame_start(self) -> None:
        self._frame_page = self.page

    def _frame_end(self, top: float, *, bar: tuple[int, int, int]) -> None:
        """Draw a card's frame once its content is written. If the content changed page,
        only the left rule is drawn on the current page: no frame straddling pages."""

        bottom = self.get_y() + 4
        if self.page != self._frame_page:
            self.set_fill_color(*bar)
            self.rect(_MARGIN, self.t_margin, 1.4, bottom - self.t_margin, style="F")
            self.set_y(bottom)
            return
        height = bottom - top
        self.set_draw_color(*_RULE)
        self.rect(
            _MARGIN,
            top,
            self._content_width,
            height,
            style="D",
            round_corners=True,
            corner_radius=3,
        )
        self.set_fill_color(*bar)
        self.rect(_MARGIN, top + 1, 1.4, height - 2, style="F")
        self.set_y(bottom)

    def _technique_height(self, name: str, description: str, width: float) -> float:
        header = self._name_lines(name, width) * 5
        return 6 + header + 2 + self._text_height(description, width - 10, 9, 4.8) + 4

    def _name_lines(self, name: str, width: float) -> int:
        self._font("sans", 10, bold=True)
        return len(self.multi_cell(width - 30, 5, self._t(name), dry_run=True, output="LINES"))

    def _technique_card(
        self,
        code: str,
        name: str,
        description: str,
        x: float,
        y: float,
        width: float,
        height: float,
    ) -> None:
        self.set_draw_color(*_RULE)
        self.rect(x, y, width, height, style="D", round_corners=True, corner_radius=3)
        self._chip(code, fg=_SLATE, bg=_RULE_SOFT, x=x + 5, y=y + 4.5)
        name_x = self.get_x() + 2.5
        self.set_xy(name_x, y + 4.5)
        self._font("sans", 10, bold=True)
        self.set_text_color(*_INK)
        self.multi_cell(
            x + width - 4 - name_x, 5, self._t(name), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
        self.set_xy(x + 5, self.get_y() + 2.5)
        self._font("sans", 9)
        self.set_text_color(*_TEXT_SOFT)
        self.multi_cell(
            width - 10, 4.8, self._t(description), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )

    def _table_head(self, labels: list[str], widths: list[float]) -> None:
        self._table = (labels, widths)
        y = self.get_y()
        self.set_fill_color(*_BG_SOFT)
        self.rect(_MARGIN, y, self._content_width, 7, style="F")
        self._font("mono", 6.5)
        self.set_text_color(*_SLATE)
        x = _MARGIN
        for index, (label, width) in enumerate(zip(labels, widths, strict=True)):
            self.set_xy(x + 2, y)
            self.cell(
                width - 4,
                7,
                self._t(label),
                align="R" if index == len(labels) - 1 and len(labels) > 3 else "L",
            )
            x += width
        self.set_draw_color(*_RULE)
        self.line(_MARGIN, y + 7, self.w - _MARGIN, y + 7)
        self.set_y(y + 7)

    def _table_row(
        self,
        cells: list[tuple[str, str, tuple[int, int, int]]],
        widths: list[float],
        *,
        align_last: str = "L",
    ) -> None:
        if self.get_y() + 7 > self.page_break_trigger:
            self.add_page()
            self._table_head(*self._table)
        y = self.get_y()
        x = _MARGIN
        for index, ((text, family, color), width) in enumerate(zip(cells, widths, strict=True)):
            self._font(family, 7.5)
            self.set_text_color(*color)
            self.set_xy(x + 2, y)
            align = align_last if index == len(cells) - 1 else "L"
            self.cell(
                width - 4, 6.5, self._t(_truncate_to_width(self, text, width - 4)), align=align
            )
            x += width
        self.set_draw_color(*_RULE_SOFT)
        self.line(_MARGIN, y + 6.5, self.w - _MARGIN, y + 6.5)
        self.set_y(y + 6.5)

    def _text_height(self, text: str, width: float, size: float, line_height: float) -> float:
        self._font("sans", size)
        lines = self.multi_cell(width, line_height, self._t(text), dry_run=True, output="LINES")
        return len(lines) * line_height


def _title_metrics(title: str) -> tuple[float, float]:
    """Font size and line height of the cover title, decreasing with length."""

    length = len(title)
    if length <= 70:
        return 24, 11
    if length <= 140:
        return 19, 9
    return 15, 7.5


def _truncate_to_width(pdf: _Document, text: str, width: float) -> str:
    text = " ".join(pdf._t(text).split())
    if pdf.get_string_width(text) <= width:
        return text
    ellipsis = "…" if pdf._unicode else "..."
    while text and pdf.get_string_width(text + ellipsis) > width:
        text = text[:-1]
    return text + ellipsis


def _format_datetime(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return value[:16].replace("T", " ")


def _format_time(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%H:%M:%S")
    except ValueError:
        return value[11:19]


def _window_label(report: HuntReport) -> str:
    if report.investigation_window:
        from reporting.report import format_window

        return format_window(report.investigation_window).replace("->", "→")
    return "default window"


def _sources_label(report: HuntReport) -> str:
    if report.sources:
        return ", ".join(_SOURCES.get(source, source) for source in report.sources)
    return "no source"


def _ratio(counter: dict[str, object]) -> str:
    used, limit = counter.get("used"), counter.get("limit")
    if used is None:
        return "-"
    return f"{used} / {limit}" if limit is not None else str(used)


def _duration(seconds: object) -> str:
    if not isinstance(seconds, (int, float)):
        return "-"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes} min {rest:02d} s" if minutes else f"{rest} s"
