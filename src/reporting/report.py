"""Investigation report generation.

The report is produced in every case, including when the hunt stops on budget or on
analyst interruption: a stop never produces a blank screen, it produces a partial
report that states what was not covered.
"""

from __future__ import annotations

from typing import Any

from middleware.budgets import HuntBudget
from middleware.guardrails.ioc import summarize_for_model
from reporting.dossier import Dossier
from reporting.models import AttackOverview, HuntReport, Verdict

_SOURCE_LABELS = {"sentinel": "Sentinel", "defender": "Defender", "secops": "SecOps"}


def build_report(
    dossier: Dossier,
    budget: HuntBudget,
    *,
    partial: bool = False,
    interruption_reason: str | None = None,
    sources: list[str] | None = None,
    investigation_window: str | None = None,
) -> HuntReport:
    conclusion = dossier.conclusion
    executed = dossier.executed_queries()
    sources = list(sources or [])

    if conclusion is not None:
        verdict = conclusion.verdict
        summary = conclusion.summary
        limitations = conclusion.limitations
        timeline = conclusion.timeline
        attack_description = conclusion.attack_description
        techniques = conclusion.techniques
        recommendation = conclusion.recommendation
    else:
        verdict = Verdict.INCONCLUSIVE
        summary = _interrupted_summary(dossier, interruption_reason)
        limitations = _interrupted_limitations(dossier, interruption_reason)
        timeline = []
        attack_description = None
        techniques = []
        recommendation = None

    overview = AttackOverview(
        description=attack_description or dossier.hypothesis,
        techniques=list(techniques),
        scope=describe_scope(
            budget,
            sources=sources,
            investigation_window=investigation_window,
            executed=len(executed),
            campaign=dossier.campaign,
        ),
    )

    if partial:
        limitations = _append_limitation(limitations, _truncation_notice(executed))

    return HuntReport(
        hunt_id=dossier.hunt_id,
        hypothesis=dossier.hypothesis,
        campaign=dossier.campaign,
        analyst=dossier.analyst,
        status=dossier.status,
        proposed_verdict=verdict,
        summary=summary,
        limitations=limitations,
        iocs=summarize_for_model(dossier.iocs),
        findings=list(dossier.findings),
        timeline=timeline,
        executed_queries=executed,
        budgets=budget.snapshot(),
        partial=partial,
        interruption_reason=interruption_reason,
        attack_overview=overview,
        playbook=dossier.playbook,
        parent_hunt_id=dossier.parent_hunt_id,
        recommendation=recommendation,
        sources=sources,
        investigation_window=investigation_window,
    )


_TOKEN_LABELS = (
    ("HOST", "host(s)"),
    ("USER", "account(s)"),
    ("IP-INT", "internal IP(s)"),
    ("DATA", "free-text fragment(s)"),
)
_SEMANTIC_LABELS = {
    "active": "semantic pass active",
    "degraded": "semantic pass degraded",
    "disabled": "semantic pass disabled",
}


def describe_anonymization(info: dict[str, Any]) -> str:
    """A readable line: what the model received for this query."""

    if not info:
        return "anonymization not traced"
    tokens = info.get("tokens") or {}
    parts = [f"{tokens[family]} {label}" for family, label in _TOKEN_LABELS if tokens.get(family)]
    head = (
        ", ".join(parts) + " pseudonymized"
        if parts
        else "no internal identifier in the result"
    )
    tail = _SEMANTIC_LABELS.get(str(info.get("semantic")), "semantic pass unknown")
    masked = info.get("masked_fields") or 0
    if masked:
        tail += f", {masked} field(s) masked for safety"
    if not info.get("tokenization", True):
        tail += ", tokenization disabled"
    return f"{head} ; {tail}"


def summarize_anonymization(report: HuntReport) -> str:
    """Anonymization status across the whole hunt, for the report cover."""

    traced = [query.anonymization for query in report.executed_queries if query.anonymization]
    if not traced:
        return "not traced"
    if not all(info.get("tokenization", True) for info in traced):
        return "tokenization disabled"
    degraded = sum(1 for info in traced if info.get("semantic") == "degraded")
    disabled = sum(1 for info in traced if info.get("semantic") == "disabled")
    if degraded:
        return f"semantic degraded {degraded}/{len(traced)}"
    if disabled == len(traced):
        return "deterministic only"
    return f"semantic {len(traced) - disabled}/{len(traced)}"


def describe_scope(
    budget: HuntBudget,
    *,
    sources: list[str],
    investigation_window: str | None,
    executed: int,
    campaign: str | None,
) -> str:
    """The hunt's real scope, computed from the platform's parameters."""

    labels = [_SOURCE_LABELS.get(source, source) for source in sources]
    parts: list[str] = []
    if investigation_window:
        parts.append(f"Investigation window {format_window(investigation_window)}")
    else:
        parts.append("Default investigation window of each source")
    if labels:
        parts[-1] += f" on {', '.join(labels)}."
    else:
        parts[-1] += ", with no accessible SIEM source."
    if campaign:
        parts.append(f"Hunt guided by the validated indicators of the \"{campaign}\" campaign.")
    limits = budget.limits
    parts.append(
        f"{executed} query(ies) executed out of a budget of {limits.max_siem_queries}, "
        f"{limits.max_iterations} iterations at most, each result minimized and "
        "pseudonymized before analysis."
    )
    return " ".join(parts)


def format_window(window: str) -> str:
    """"2026-06-01T06:00:00+00:00 -> 2026-08-31T08:54:04+00:00" becomes
    "01/06/2026 -> 31/08/2026"."""

    from datetime import datetime

    ends = [part.strip() for part in window.split("->")]
    if len(ends) != 2:
        return window
    rendered = []
    for value in ends:
        try:
            rendered.append(datetime.fromisoformat(value).strftime("%d/%m/%Y"))
        except ValueError:
            rendered.append(value)
    return f"{rendered[0]} -> {rendered[1]}"


def _interrupted_summary(dossier: Dossier, reason: str | None) -> str:
    parts = [
        f"The hunt stopped before the agent concluded ({reason or 'reason unspecified'}).",
        f"{len(dossier.executed_queries())} query(ies) executed, "
        f"{len(dossier.findings)} finding(s) recorded.",
    ]
    if not dossier.findings:
        parts.append("No substantiated finding could be produced before the stop.")
    return " ".join(parts)


def _interrupted_limitations(dossier: Dossier, reason: str | None) -> str:
    return (
        f"Investigation interrupted: {reason or 'reason unspecified'}. "
        "The unexplored leads are not documented and the absence of a finding does not "
        "amount to the absence of a signal. Relaunch the hunt with a larger budget to "
        "cover the remaining angles."
    )


def _truncation_notice(executed: list[Any]) -> str | None:
    truncated = [query.query_id for query in executed if query.truncated]
    if not truncated:
        return None
    return (
        f"{len(truncated)} query(ies) returned a result truncated by the row cap "
        f"({', '.join(truncated)}): the corresponding view is not exhaustive."
    )


def _append_limitation(limitations: str, extra: str | None) -> str:
    if not extra:
        return limitations
    return f"{limitations}\n\n{extra}"


def to_markdown(report: HuntReport) -> str:
    """Markdown export of the report. The verdict stays presented as a proposal."""

    lines = [
        f"# Investigation report — {report.hunt_id}",
        "",
        f"**Hypothesis**: {report.hypothesis}",
    ]
    if report.campaign:
        lines.append(f"**Campaign**: {report.campaign}")
    if report.parent_hunt_id:
        lines.append(f"**Resumed from hunt**: {report.parent_hunt_id}")
    lines.extend(
        [
            f"**Analyst**: {report.analyst}",
            f"**Generated on**: {report.generated_at}",
            "",
            f"## Proposed verdict: {report.proposed_verdict.value}",
            "",
            "This verdict is a proposal from the agent. It does not have the force of a "
            "decision until an analyst has confirmed it.",
            "",
            "## Summary",
            "",
            report.summary,
        ]
    )
    if report.recommendation:
        lines.extend(["", "**Recommendation**: " + report.recommendation])
    lines.extend(["", f"**Anonymization before analysis**: {summarize_anonymization(report)}"])

    if report.attack_overview:
        lines.extend(
            ["", "## The attack under investigation", "", report.attack_overview.description]
        )
        for technique in report.attack_overview.techniques:
            lines.append(f"- **{technique.id}** {technique.name} — {technique.description}")
        lines.extend(["", f"Hunt scope: {report.attack_overview.scope}"])

    if report.playbook:
        playbook = report.playbook
        lines.extend(["", "## Playbook", "", playbook.summary, ""])
        executed = report.executed_by_siem()
        lines.append("| # | SIEM | Objective | Technique | Planned queries |")
        lines.append("|---|---|---|---|---|")
        for step in playbook.steps:
            lines.append(
                f"| {step.order} | {step.siem} | {step.objective} | {step.technique or ''} | "
                f"{step.expected_queries} |"
            )
        lines.append("")
        lines.append(
            f"Estimate: {playbook.estimated_queries} query(ies), "
            f"{playbook.estimated_iterations} iteration(s). "
            + (
                f"Validated by {playbook.validated_by} on {playbook.validated_at}: "
                f"{playbook.validated_queries} query(ies), {playbook.validated_iterations} "
                "iteration(s). "
                if playbook.validated_by
                else "Not validated. "
            )
            + f"Executed: {sum(executed.values())} query(ies)."
        )
        lines.extend(["", f"Not covered by the plan: {playbook.not_covered}"])

    if report.partial:
        lines.extend(
            [
                "",
                "> Partial report: the hunt was interrupted "
                f"({report.interruption_reason or 'reason unspecified'}).",
            ]
        )

    lines.extend(["", "## Indicators", ""])
    if report.iocs:
        lines.append("| Value | Type | Source | Status |")
        lines.append("|---|---|---|---|")
        for ioc in report.iocs:
            lines.append(
                f"| `{ioc.get('value')}` | {ioc.get('type')} | "
                f"[{ioc.get('source')}]({ioc.get('source_url')}) | {ioc.get('status')} |"
            )
    else:
        lines.append("No indicators: behavioral hunt.")

    lines.extend(["", "## Findings", ""])
    if report.findings:
        for finding in report.findings_by_severity():
            lines.extend(
                [
                    f"### [{finding.severity.value}] {finding.title}",
                    "",
                    f"Confidence: {finding.confidence.value}",
                    "",
                    finding.description,
                    "",
                    f"Evidence: {', '.join(f'`{qid}`' for qid in finding.evidence_query_ids)}",
                    "",
                ]
            )
    else:
        lines.append("No findings recorded.")

    entities = report.observed_entities()
    if entities:
        lines.extend(
            ["", "## Observed entities", "", "| Type | Value | Findings |", "|---|---|---|"]
        )
        for entity, findings in entities:
            lines.append(f"| {entity.type} | `{entity.value}` | {len(findings)} |")

    if report.timeline:
        lines.extend(["", "## Timeline", ""])
        for event in report.timeline:
            lines.append(f"- `{event.timestamp}` — {event.event} _({event.source})_")

    lines.extend(["", "## Executed queries", ""])
    if report.executed_queries:
        for query in report.executed_queries:
            flag = " — truncated result" if query.truncated else ""
            lines.extend(
                [
                    f"**`{query.query_id}`** ({query.siem}, {query.returned_rows} rows{flag})",
                    "",
                ]
            )
            if query.intent:
                lines.extend([f"Objective: {query.intent}", ""])
            lines.extend(["```", query.query, "```", ""])
            if query.interpretation:
                lines.extend([f"Agent's reading: {query.interpretation}", ""])
            if query.anonymization:
                lines.extend([f"Anonymization: {describe_anonymization(query.anonymization)}", ""])
            if query.sample and query.columns:
                lines.append(
                    f"Sample ({len(query.sample)} row(s) out of {query.source_rows}):"
                )
                lines.append("")
                lines.append("| " + " | ".join(query.columns) + " |")
                lines.append("|" + "---|" * len(query.columns))
                for row in query.sample:
                    cells = [
                        str(row.get(column, "")).replace("|", "\\|").replace("\n", " ")
                        for column in query.columns
                    ]
                    lines.append("| " + " | ".join(cells) + " |")
                lines.append("")
            if query.model_sample and query.columns:
                lines.extend(["Transmitted to the model (pseudonyms in place):", ""])
                lines.append("| " + " | ".join(query.columns) + " |")
                lines.append("|" + "---|" * len(query.columns))
                for row in query.model_sample:
                    cells = [
                        str(row.get(column, "")).replace("|", "\\|").replace("\n", " ")
                        for column in query.columns
                    ]
                    lines.append("| " + " | ".join(cells) + " |")
                lines.append("")
    else:
        lines.append("No queries executed.")

    lines.extend(["", "## Investigation limitations", "", report.limitations, ""])
    return "\n".join(lines)
