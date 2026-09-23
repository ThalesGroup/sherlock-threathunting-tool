/**
 * Screen 4 - Report.
 *
 * Reading rule: each finding shows the queries that support it, linked to the
 * corresponding query. A finding that cannot be tied to a query does not exist, and the
 * middleware refuses it upstream.
 *
 * The agent's verdict is presented as a proposal. The validation area is separate, and the
 * decision is timestamped and attributed.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  ConfidenceLabel,
  EmptyState,
  ErrorNotice,
  Mono,
  QueryBlock,
  SEVERITY_COLORS,
  SeverityBadge,
  TruncationNotice,
  VerdictBadge,
} from "@/components/primitives";
import { AnonymizationLine, ResultSample } from "@/components/ResultSample";
import {
  api,
  ApiError,
  type AnonymizationInfo,
  type ExecutedQuery,
  type Finding,
  type Verdict,
} from "@/lib/api";

const VERDICTS: { value: Verdict; label: string }[] = [
  { value: "benign", label: "Benign" },
  { value: "suspicious", label: "Suspicious" },
  { value: "escalate", label: "To escalate" },
  { value: "inconclusive", label: "Inconclusive" },
];

const VERDICT_ACCENTS: Record<Verdict, string> = {
  benign: "#1f8a5f",
  suspicious: "#a8560b",
  escalate: "#8f1d1d",
  inconclusive: "#5b6b7c",
};

export function ReportScreen() {
  const { huntId = "" } = useParams();
  const queryClient = useQueryClient();
  const report = useQuery({
    queryKey: ["report", huntId],
    queryFn: () => api.report(huntId),
  });

  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [resumeFrom, setResumeFrom] = useState<string | null>(null);
  const [comment, setComment] = useState("");

  const decide = useMutation({
    mutationFn: () => api.decide(huntId, verdict!, comment.trim() || null),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["report", huntId] }),
  });

  const exportMarkdown = useMutation({
    mutationFn: () => api.reportMarkdown(huntId),
    onSuccess: (markdown) => downloadText(`${huntId}.md`, markdown),
  });

  const exportPdf = useMutation({
    mutationFn: () => api.reportPdf(huntId),
    onSuccess: (blob) => downloadBlob(`${huntId}.pdf`, blob),
  });

  if (report.isLoading) return <p className="meta-text">Loading the report…</p>;

  if (report.error) {
    return (
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_300px]">
        <EmptyState title="Report unavailable">
          This hunt did not produce a report: it may still be running, or it was
          interrupted before its conclusion (for example by a server restart).
          If it is finished or interrupted, you can resume it: the new
          investigation will receive its progress rebuilt from the audit log.
        </EmptyState>
        <ResumeCard huntId={huntId} queries={[]} />
      </div>
    );
  }

  const data = report.data!;
  const iterations = data.budgets.iterations;
  const siemQueries = data.budgets.siem_queries;
  const duration = data.budgets.duration_seconds;
  const totalRows = data.executed_queries.reduce(
    (sum, q) => sum + q.source_rows,
    0,
  );
  const coverCells: [string, string][] = [
    ["Analyst", data.analyst],
    ["Period covered", formatWindow(data.investigation_window)],
    [
      "Sources",
      data.sources.length > 0
        ? data.sources.map(sourceLabel).join(", ")
        : "none",
    ],
    ["Generated on", formatDate(data.generated_at)],
  ];
  const entities = observedEntities(data.findings);
  const runStats: [string, string][] = [
    [
      "iterations",
      iterations ? `${iterations.used} / ${iterations.limit}` : "-",
    ],
    [
      "SIEM queries",
      siemQueries ? `${siemQueries.used} / ${siemQueries.limit}` : "-",
    ],
    ["events read", String(totalRows)],
    ["findings", String(data.findings.length)],
    ["duration", duration ? formatDuration(duration.used) : "-"],
    ["anonymization", anonymizationSummary(data.executed_queries)],
  ];

  return (
    <article className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_290px]">
      <div className="min-w-0">
        <header className="card mb-4 p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="meta-mono uppercase tracking-[0.22em]">
                Investigation report · Threat hunting
              </p>
              <h1 className="mt-2 text-[21px] font-semibold leading-snug tracking-tight text-navy">
                {data.hypothesis}
              </h1>
              <div className="mt-3 flex flex-wrap items-center gap-2.5">
                <Mono className="text-[12px] font-medium text-slate">
                  {data.hunt_id}
                </Mono>
                <VerdictBadge verdict={data.proposed_verdict} />
                {data.parent_hunt_id ? (
                  <Link
                    to={`/hunts/${data.parent_hunt_id}/report`}
                    className="badge bg-[#e2eef7] text-[#0a5f9e] hover:underline"
                  >
                    resumed from {data.parent_hunt_id}
                  </Link>
                ) : null}
                {data.partial ? (
                  <span className="badge bg-[#faeddc] text-[#a8560b]">
                    partial
                  </span>
                ) : null}
              </div>
            </div>
            <div className="flex flex-none gap-2 print:hidden">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => exportMarkdown.mutate()}
              >
                Export Markdown
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => exportPdf.mutate()}
                disabled={exportPdf.isPending}
              >
                {exportPdf.isPending ? "Exporting…" : "Export PDF"}
              </button>
            </div>
          </div>
          <dl className="mt-5 grid grid-cols-2 gap-4 border-t border-navy pt-4 md:grid-cols-4">
            {coverCells.map(([label, value]) => (
              <div key={label}>
                <dt className="meta-mono uppercase">{label}</dt>
                <dd className="mt-1 font-mono text-[12px] font-medium text-ink">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
        </header>

        {data.attack_overview ? (
          <section className="card mb-4 p-5">
            <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2 border-b border-navy pb-2">
              <h2 className="text-[15px] font-semibold text-ink">
                The attack under investigation
              </h2>
              <span className="meta-mono uppercase">
                Hunt hypothesis · MITRE ATT&amp;CK
              </span>
            </div>
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-[#243544]">
              {data.attack_overview.description}
            </p>
            {data.attack_overview.techniques.length > 0 ? (
              <ul className="mt-4 grid gap-3 md:grid-cols-2">
                {data.attack_overview.techniques.map((technique) => (
                  <li
                    key={technique.id}
                    className="flex h-full flex-col rounded-[12px] border border-rule px-4 py-3.5"
                  >
                    <div className="flex items-center gap-2.5">
                      <Mono className="rounded-[5px] bg-rule-soft px-2 py-1 text-[9px] font-semibold tracking-[0.1em] text-slate">
                        {technique.id}
                      </Mono>
                      <h3 className="text-[13px] font-semibold leading-snug text-ink">
                        {technique.name}
                      </h3>
                    </div>
                    <p className="mt-2 text-[12.5px] leading-relaxed text-[#3d4d5c]">
                      {technique.description}
                    </p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="meta-text mt-3">
                No MITRE ATT&amp;CK technique was tied to this hunt by the
                agent.
              </p>
            )}
            <div className="mt-4 rounded-[12px] border border-rule border-l-4 border-l-navy px-4 py-3.5">
              <span className="label mb-1.5 block">Hunt scope</span>
              <p className="text-[13px] leading-relaxed text-[#3d4d5c]">
                {data.attack_overview.scope}
              </p>
            </div>
          </section>
        ) : null}

        {data.playbook ? (
          <section className="card mb-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule px-5 py-3">
              <h2 className="text-[13px] font-semibold text-ink">Playbook</h2>
              <span className="meta-mono uppercase">
                {data.playbook.validated_by
                  ? `validated by ${data.playbook.validated_by} · ${data.playbook.validated_queries} queries / ${data.playbook.validated_iterations} iterations`
                  : "not validated"}
              </span>
            </div>
            <p className="px-5 pt-4 text-sm leading-relaxed text-[#243544]">
              {data.playbook.summary}
            </p>
            <div className="overflow-x-auto px-5 pb-2 pt-3">
              <table className="w-full text-left">
                <thead className="bg-soft-bg">
                  <tr>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      #
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      SIEM
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      Objective
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      Technique
                    </th>
                    <th className="meta-mono px-3 py-2 text-right font-medium uppercase">
                      Planned
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.playbook.steps.map((step) => (
                    <tr
                      key={step.order}
                      className="border-t border-rule-soft align-top"
                    >
                      <td className="px-3 py-2">
                        <Mono className="text-[11px] text-meta">
                          {step.order}
                        </Mono>
                      </td>
                      <td className="px-3 py-2 text-xs text-slate">
                        {sourceLabel(step.siem)}
                      </td>
                      <td className="px-3 py-2 text-[13px] text-ink">
                        {step.objective}
                      </td>
                      <td className="px-3 py-2">
                        <Mono className="text-[11px] text-slate">
                          {step.technique ?? ""}
                        </Mono>
                      </td>
                      <td className="px-3 py-2 text-right">
                        <Mono className="text-xs font-medium">
                          {step.expected_queries}
                        </Mono>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="meta-mono px-5 pb-2 uppercase">
              Estimate {data.playbook.estimated_queries} queries /{" "}
              {data.playbook.estimated_iterations} iterations · executed{" "}
              {data.executed_queries.length} query(ies)
            </p>
            <div className="mx-5 mb-5 rounded-[10px] border border-[#e3e8ed] bg-soft-bg px-4 py-3.5">
              <span className="label mb-1.5 block">
                Not covered by the plan
              </span>
              <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-[#3d4d5c]">
                {data.playbook.not_covered}
              </p>
            </div>
          </section>
        ) : null}

        {data.partial ? (
          <div className="mb-4">
            <TruncationNotice>
              Partial report: the hunt was interrupted (
              {data.interruption_reason ?? "reason not specified"}).
            </TruncationNotice>
          </div>
        ) : null}

        <section
          className="card mb-4 p-5"
          style={{
            borderLeft: `4px solid ${VERDICT_ACCENTS[data.proposed_verdict]}`,
          }}
        >
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-[13px] font-semibold text-ink">
              Proposed verdict
            </h2>
            <VerdictBadge verdict={data.proposed_verdict} />
            <span className="meta-mono uppercase">
              {data.human_decision ? "validated" : "not validated"}
            </span>
          </div>
          <p className="mt-3.5 whitespace-pre-wrap text-sm leading-relaxed text-[#243544]">
            {data.summary}
          </p>

          {data.recommendation ? (
            <div className="mt-4 rounded-[10px] border border-[#e3e8ed] bg-soft-bg px-4 py-3.5">
              <span className="label mb-1.5 block">Recommendation</span>
              <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-[#3d4d5c]">
                {data.recommendation}
              </p>
            </div>
          ) : null}

          <div className="mt-4 rounded-[10px] border border-[#e3e8ed] bg-soft-bg px-4 py-3.5">
            <span className="label mb-1.5 block">
              Investigation limitations
            </span>
            <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-[#3d4d5c]">
              {data.limitations}
            </p>
          </div>

          <div className="mt-4 border-t border-rule-soft pt-4 print:hidden">
            {data.human_decision ? (
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-3">
                  <VerdictBadge verdict={data.human_decision.verdict} />
                  <span className="meta-mono uppercase">
                    Verdict validated by {data.human_decision.decided_by} ·{" "}
                    {formatDate(data.human_decision.decided_at)}
                  </span>
                </div>
                {data.human_decision.comment ? (
                  <p className="whitespace-pre-wrap text-sm text-ink">
                    {data.human_decision.comment}
                  </p>
                ) : null}
              </div>
            ) : (
              <>
                <fieldset>
                  <legend className="meta-text mb-2.5">
                    You confirm, correct or overturn the agent&apos;s proposal.
                    Your decision is timestamped and attributed to you.
                  </legend>
                  <div className="flex flex-wrap gap-2">
                    {VERDICTS.map((option) => (
                      <label
                        key={option.value}
                        className={`cursor-pointer rounded-btn border px-3.5 py-2 text-xs
                        font-medium transition-colors ${
                          verdict === option.value
                            ? "border-navy bg-navy text-white"
                            : "border-field-border text-slate hover:bg-soft-bg"
                        }`}
                      >
                        <input
                          type="radio"
                          name="verdict"
                          value={option.value}
                          checked={verdict === option.value}
                          onChange={() => setVerdict(option.value)}
                          className="sr-only"
                        />
                        {option.label}
                      </label>
                    ))}
                  </div>
                </fieldset>
                <textarea
                  value={comment}
                  onChange={(event) => setComment(event.target.value)}
                  rows={2}
                  className="field mt-3 text-sm"
                  placeholder="Comment (optional)"
                  aria-label="Decision comment"
                />
                {decide.error ? (
                  <div className="mt-3">
                    <ErrorNotice
                      message={
                        decide.error instanceof ApiError
                          ? decide.error.message
                          : "The decision could not be recorded."
                      }
                    />
                  </div>
                ) : null}
                <div className="mt-3.5 flex items-center gap-3">
                  <button
                    type="button"
                    className="btn-primary"
                    disabled={!verdict || decide.isPending}
                    onClick={() => decide.mutate()}
                  >
                    Confirm the verdict
                  </button>
                  <span className="meta-mono">
                    No decision is recorded before validation.
                  </span>
                </div>
              </>
            )}
          </div>
        </section>

        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-[15px] font-semibold text-ink">
            Findings{" "}
            <span className="meta-mono font-normal">
              {data.findings.length}
            </span>
          </h2>
          {data.findings.length > 1 ? (
            <span className="meta-mono uppercase">Sorted by severity</span>
          ) : null}
        </div>

        {data.findings.length === 0 ? (
          <p className="meta-text mb-4">No finding recorded.</p>
        ) : (
          data.findings.map((finding) => (
            <section
              key={finding.id}
              id={finding.id}
              className="card mb-3 scroll-mt-20 px-5 py-4"
              style={{
                borderLeft: `4px solid ${SEVERITY_COLORS[finding.severity]}`,
              }}
            >
              <div className="flex flex-wrap items-center gap-3">
                <SeverityBadge severity={finding.severity} />
                <h3 className="flex-1 text-sm font-semibold leading-snug text-ink">
                  {finding.title}
                </h3>
                <span className="meta-mono uppercase">
                  <ConfidenceLabel confidence={finding.confidence} />
                </span>
              </div>
              <p className="mt-2.5 whitespace-pre-wrap text-[13px] leading-relaxed text-[#3d4d5c]">
                {finding.description}
              </p>
              {finding.entities.length > 0 ? (
                <ul className="mt-3.5 flex flex-wrap gap-1.5">
                  {finding.entities.map((entity) => (
                    <li
                      key={`${entity.type}:${entity.value}`}
                      className="flex items-center gap-1.5 rounded-[7px] border border-[#e3e8ed] bg-soft-bg px-2.5 py-1.5"
                    >
                      <span className="font-mono text-[9px] font-medium uppercase tracking-[0.1em] text-meta">
                        {entity.type}
                      </span>
                      <Mono className="text-[11px] font-medium">
                        {entity.value}
                      </Mono>
                    </li>
                  ))}
                </ul>
              ) : null}
              <p className="meta-mono mt-3 border-t border-rule-soft pt-2.5 uppercase">
                Evidence ·{" "}
                {finding.evidence_query_ids.map((id, index) => (
                  <span key={id}>
                    {index > 0 ? " · " : ""}
                    <a href={`#${id}`} className="text-indigo hover:underline">
                      {id}
                    </a>
                  </span>
                ))}
              </p>
            </section>
          ))
        )}

        {entities.length > 0 ? (
          <section className="card mb-4 mt-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule px-5 py-3">
              <h2 className="text-[13px] font-semibold text-ink">
                Observed entities
              </h2>
              <span className="meta-mono uppercase">
                {entities.length} entity(ies) · cited by the findings
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-soft-bg">
                  <tr>
                    <th className="meta-mono px-5 py-2 font-medium uppercase">
                      Type
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      Value
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      Context
                    </th>
                    <th className="meta-mono px-5 py-2 text-right font-medium uppercase">
                      Occ.
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {entities.map((entry) => (
                    <tr key={entry.key} className="border-t border-rule-soft">
                      <td className="meta-mono px-5 py-2 uppercase">
                        {entry.type}
                      </td>
                      <td className="px-3 py-2">
                        <Mono className="text-xs font-medium text-ink">
                          {entry.value}
                        </Mono>
                      </td>
                      <td className="px-3 py-2 text-xs text-slate">
                        <a
                          href={`#${entry.findings[0].id}`}
                          className="hover:underline"
                        >
                          {entry.findings[0].title}
                        </a>
                      </td>
                      <td className="px-5 py-2 text-right">
                        <Mono className="text-xs font-medium">
                          {entry.findings.length}
                        </Mono>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ) : null}

        {data.executed_queries.length > 0 ? (
          <section className="card mb-4 mt-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-rule px-5 py-3">
              <h2 className="text-[13px] font-semibold text-ink">
                Execution log
              </h2>
              <span className="meta-mono uppercase">
                {data.executed_queries.length} query(ies)
                {duration ? ` · duration ${formatDuration(duration.used)}` : ""}
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-soft-bg">
                  <tr>
                    <th className="meta-mono px-5 py-2 font-medium uppercase">
                      Time
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      Reference
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      SIEM
                    </th>
                    <th className="meta-mono px-3 py-2 font-medium uppercase">
                      Objective
                    </th>
                    <th className="meta-mono px-5 py-2 text-right font-medium uppercase">
                      Rows
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.executed_queries.map((query) => (
                    <tr
                      key={query.query_id}
                      className="border-t border-rule-soft"
                    >
                      <td className="px-5 py-2">
                        <Mono className="text-[11px] text-slate">
                          {formatTime(query.executed_at)}
                        </Mono>
                      </td>
                      <td className="px-3 py-2">
                        <a
                          href={`#${query.query_id}`}
                          className="font-mono text-[11px] font-medium text-indigo hover:underline"
                        >
                          {query.query_id}
                        </a>
                      </td>
                      <td className="meta-mono px-3 py-2 uppercase">
                        {query.siem}
                      </td>
                      <td className="max-w-[28rem] px-3 py-2">
                        {query.intent ? (
                          <span className="text-xs text-[#3d4d5c]">
                            {query.intent}
                          </span>
                        ) : (
                          <Mono className="block truncate text-[11px] text-[#3d4d5c]">
                            {firstLine(query.query)}
                          </Mono>
                        )}
                      </td>
                      <td className="px-5 py-2 text-right">
                        <Mono className="text-[11px] font-medium">
                          {query.returned_rows}
                          {query.truncated ? " ⚠" : ""}
                        </Mono>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ) : null}

        {data.timeline.length > 0 ? (
          <section className="card mb-4 mt-4 p-5">
            <h2 className="mb-4 text-[13px] font-semibold text-ink">
              Timeline
            </h2>
            <ol className="space-y-3 border-l border-rule pl-5">
              {data.timeline.map((event, index) => (
                <li key={`${event.timestamp}-${index}`} className="relative">
                  <span
                    className="absolute -left-[1.4rem] top-1.5 h-2 w-2 rounded-full bg-accent"
                    aria-hidden="true"
                  />
                  <Mono className="text-[11px] text-slate">
                    {event.timestamp}
                  </Mono>
                  <p className="text-[13px] text-ink">{event.event}</p>
                  <p className="meta-mono uppercase">{event.source}</p>
                </li>
              ))}
            </ol>
          </section>
        ) : null}

        {data.iocs.length > 0 ? (
          <section className="card mb-4 mt-4">
            <h2 className="card-header">Indicators</h2>
            <ul className="px-5 py-2">
              {data.iocs.map((ioc) => (
                <li
                  key={`${ioc.type}:${ioc.value}`}
                  className="flex flex-wrap items-baseline gap-3 border-b border-rule-soft py-2 last:border-b-0"
                >
                  <Mono className="text-xs font-medium text-ink">
                    {ioc.value}
                  </Mono>
                  <span className="meta-mono uppercase">{ioc.type}</span>
                  <span className="meta-mono uppercase">{ioc.status}</span>
                  {ioc.source_url.startsWith("internal://") ? (
                    <span className="meta-text">{ioc.source}</span>
                  ) : (
                    <a
                      href={ioc.source_url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-xs text-indigo hover:underline"
                    >
                      {ioc.source}
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <section className="card mt-4">
          <h2 className="card-header">
            Appendix · executed queries (full text)
          </h2>
          <div className="space-y-4 p-5">
            {data.executed_queries.map((query) => (
              <div
                key={query.query_id}
                id={query.query_id}
                className="scroll-mt-20 space-y-2"
              >
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                  <Mono className="text-xs font-medium text-indigo">
                    {query.query_id}
                  </Mono>
                  <span className="meta-mono uppercase">{query.siem}</span>
                  <span className="meta-mono">
                    {query.returned_rows} row(s)
                  </span>
                  <span className="meta-mono">
                    {formatDate(query.executed_at)}
                  </span>
                </div>
                {query.intent ? (
                  <p className="text-sm text-ink">{query.intent}</p>
                ) : null}
                <QueryBlock query={query.query} />
                <AnonymizationLine info={query.anonymization} />
                <ResultSample
                  columns={query.columns}
                  rows={query.sample}
                  modelRows={query.model_sample}
                  sourceRows={query.source_rows}
                />
                {query.truncated ? (
                  <TruncationNotice>
                    {query.source_rows} rows returned by the source, cap
                    reached: the result is not exhaustive. The model received{" "}
                    {query.returned_rows}
                    {query.source_rows > query.returned_rows
                      ? " (with aggregates)"
                      : ""}
                    .
                  </TruncationNotice>
                ) : null}
                <button
                  type="button"
                  className="text-xs text-indigo hover:underline print:hidden"
                  onClick={() => {
                    setResumeFrom(query.query_id);
                    document
                      .getElementById("card-resume")
                      ?.scrollIntoView({ behavior: "smooth", block: "center" });
                  }}
                >
                  Resume the investigation from here →
                </button>
              </div>
            ))}
          </div>
        </section>
      </div>

      <aside className="sticky top-[72px] hidden flex-col gap-4 xl:flex print:hidden">
        {data.findings.length > 0 ? (
          <nav className="card" aria-label="Findings summary">
            <div className="label border-b border-rule px-3.5 py-3">
              Contents
            </div>
            {data.findings.map((finding) => (
              <a
                key={finding.id}
                href={`#${finding.id}`}
                className="flex gap-2.5 border-b border-rule-soft px-3.5 py-2.5 text-ink last:border-b-0 hover:bg-soft-bg"
              >
                <span
                  className="mt-1.5 h-[7px] w-[7px] flex-none rounded-full"
                  style={{ background: SEVERITY_COLORS[finding.severity] }}
                  aria-hidden="true"
                />
                <span className="text-xs leading-snug">{finding.title}</span>
              </a>
            ))}
          </nav>
        ) : null}

        <ResumeCard
          huntId={data.hunt_id}
          queries={data.executed_queries}
          prefillFromQuery={resumeFrom}
        />

        <div className="card p-3.5">
          <div className="label mb-3">Execution</div>
          {runStats.map(([k, v]) => (
            <div
              key={k}
              className="flex justify-between border-b border-rule-soft py-1.5 font-mono text-[11px] last:border-b-0"
            >
              <span className="text-slate">{k}</span>
              <span className="font-medium">{v}</span>
            </div>
          ))}
        </div>
      </aside>
    </article>
  );
}

function ResumeCard({
  huntId,
  queries,
  prefillFromQuery = null,
}: {
  huntId: string;
  queries: ExecutedQuery[];
  prefillFromQuery?: string | null;
}) {
  const navigate = useNavigate();
  const [instruction, setInstruction] = useState("");
  const [fromQuery, setFromQuery] = useState("");

  useEffect(() => {
    if (prefillFromQuery) setFromQuery(prefillFromQuery);
  }, [prefillFromQuery]);
  const options = useQuery({
    queryKey: ["resume-options", huntId],
    queryFn: () => api.resumeOptions(huntId),
  });

  const continueInPlace = useMutation({
    mutationFn: () =>
      api.continueHunt(
        huntId,
        instruction.trim() ? { instruction: instruction.trim() } : {},
      ),
    onSuccess: () => navigate(`/hunts/${huntId}/feed`),
  });

  const resume = useMutation({
    mutationFn: () =>
      api.resumeHunt(huntId, {
        ...(instruction.trim() ? { instruction: instruction.trim() } : {}),
        ...(fromQuery ? { from_query_id: fromQuery } : {}),
      }),
    onSuccess: (created) => navigate(`/hunts/${created.hunt_id}/playbook`),
  });

  return (
    <div className="card p-3.5" id="card-resume">
      <div className="label mb-2">Resume this hunt</div>
      <textarea
        value={instruction}
        onChange={(event) => setInstruction(event.target.value)}
        rows={2}
        className="field mb-3 text-sm"
        placeholder="Question or instruction for what follows (optional)"
        aria-label="Instruction for the resume"
      />
      {options.data?.continuable ? (
        <div className="mb-4 border-b border-rule-soft pb-4">
          <p className="meta-text mb-2.5">
            {options.data?.status === "awaiting_review"
              ? "Same investigation: the agent starts again from its memory, its queries and its findings, with your instruction, and will conclude again. This report will be replaced; the previous one stays in the audit trail. Once the verdict is validated, the hunt is frozen."
              : "Same investigation: the agent starts again from its memory, its queries and its findings, with your instruction and its remaining budgets. If they are exhausted, it will ask you for an extension in the feed."}
          </p>
          <button
            type="button"
            className="btn-primary w-full justify-center"
            onClick={() => continueInPlace.mutate()}
            disabled={continueInPlace.isPending}
          >
            {continueInPlace.isPending
              ? "Resuming…"
              : "Continue the same investigation"}
          </button>
          {continueInPlace.error ? (
            <p className="mt-2 text-sm text-garnet">
              {continueInPlace.error instanceof ApiError
                ? continueInPlace.error.message
                : "Cannot resume."}
            </p>
          ) : null}
        </div>
      ) : null}
      <p className="meta-text mb-3">
        {options.data?.continuable ? "Or start over in a n" : "N"}ew linked
        investigation, with a new hunt and a new report: it inherits the
        validated indicators and this hunt&apos;s progress, and goes through the
        playbook again. This report stays unchanged.
      </p>
      <label className="mb-3 block text-xs text-slate">
        Resume after
        <select
          value={fromQuery}
          onChange={(event) => setFromQuery(event.target.value)}
          className="field mt-1 font-mono text-xs"
        >
          <option value="">the end of the hunt</option>
          {queries.map((query) => (
            <option key={query.query_id} value={query.query_id}>
              {query.query_id} · {query.siem}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        className="btn-secondary w-full justify-center"
        onClick={() => resume.mutate()}
        disabled={resume.isPending}
      >
        {resume.isPending
          ? "Creating…"
          : "New linked investigation (playbook to validate)"}
      </button>
      {resume.error ? (
        <p className="mt-2 text-sm text-garnet">
          {resume.error instanceof ApiError
            ? resume.error.message
            : "Cannot resume."}
        </p>
      ) : null}
    </div>
  );
}

function formatDate(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function formatWindow(window: string | null): string {
  if (!window) return "default window";
  const ends = window.split("->").map((part) => part.trim());
  if (ends.length !== 2) return window;
  const render = (value: string) => {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime())
      ? value
      : parsed.toLocaleDateString("en-GB");
  };
  return `${render(ends[0])} → ${render(ends[1])}`;
}

const SOURCE_LABELS: Record<string, string> = {
  sentinel: "Sentinel",
  defender: "Defender",
  secops: "SecOps",
};

function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source;
}

function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleTimeString("en-GB");
}

function firstLine(query: string): string {
  return (
    query
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line.length > 0) ?? ""
  );
}

interface ObservedEntity {
  key: string;
  type: string;
  value: string;
  findings: Finding[];
}

function observedEntities(findings: Finding[]): ObservedEntity[] {
  const seen = new Map<string, ObservedEntity>();
  for (const finding of findings) {
    for (const entity of finding.entities) {
      const key = `${entity.type.toLowerCase()}:${entity.value}`;
      const entry = seen.get(key);
      if (entry) {
        entry.findings.push(finding);
      } else {
        seen.set(key, {
          key,
          type: entity.type,
          value: entity.value,
          findings: [finding],
        });
      }
    }
  }
  return [...seen.values()].sort(
    (a, b) => b.findings.length - a.findings.length,
  );
}

function anonymizationSummary(queries: ExecutedQuery[]): string {
  const traced = queries
    .map((query) => query.anonymization)
    .filter(
      (info): info is AnonymizationInfo => info !== null && "tokens" in info,
    );
  if (traced.length === 0) return "not traced";
  if (traced.some((info) => !info.tokenization)) return "tokenization disabled";
  const degraded = traced.filter((info) => info.semantic === "degraded").length;
  const disabled = traced.filter((info) => info.semantic === "disabled").length;
  if (degraded > 0) return `semantic degraded ${degraded}/${traced.length}`;
  if (disabled === traced.length) return "deterministic only";
  return `semantic active ${traced.length - disabled}/${traced.length}`;
}

function formatDuration(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return minutes > 0 ? `${minutes} min ${rest} s` : `${rest} s`;
}

function downloadText(filename: string, content: string): void {
  downloadBlob(
    filename,
    new Blob([content], { type: "text/markdown;charset=utf-8" }),
  );
}

function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
