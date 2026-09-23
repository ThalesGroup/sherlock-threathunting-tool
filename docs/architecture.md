# Threat hunting agent platform

Architecture note.

## 1. Objective

Provide SOC analysts with an autonomous investigation platform. The analyst submits a hypothesis or the name of an attack campaign; an LLM-powered agent (through the AI gateway) enriches the hypothesis into IOCs, generates and runs queries against Google SecOps, Microsoft Sentinel and Microsoft Defender, analyzes the results in a loop, then delivers an investigation report with a timeline and a consolidated findings dashboard.

v1 scope: read-only, ad hoc hunts triggered by an analyst, no automated response (no host isolation, no account disabling, no automatic case opening).

## 2. Guiding principles

1. **Read-only by construction.** No write tool is exposed to the agent. Read-only is not an instruction given to the model: it is material (minimal API permissions, tools that do not exist).
2. **Investigation results stay internal.** SIEM data, logs, findings and reports move only within the internal perimeter and through the AI gateway. The only outbound flow leaving the perimeter is IOC lookup against external threat intelligence sources.
3. **No IOC from the model's memory.** Every IOC comes from a real lookup against an authorized source, with a citation. IOCs are validated by the analyst before any SIEM querying.
4. **Systematic minimization.** The middleware sorts, masks, aggregates and caps results before returning them to the model. The model never receives a raw dump.
5. **Autonomy of exploration, human verdict.** The agent runs the hunt end to end, but three human checkpoints frame it: IOC validation, playbook and budget validation before any query, and report validation before any decision (escalation, case opening).

## 3. Architecture

### 3.1 Components

| Component | Role | Zone |
|---|---|---|
| Analyst interface | Hypothesis entry, IOC validation, report and dashboard consultation | Internal |
| Hunt orchestrator | Agentic loop: drives the AI gateway calls, sequences the steps, applies the iteration budget | Internal |
| AI gateway | Single access point to the gateway's models, function calling, OpenAI-compatible interface | Internal (AI platform team) |
| Tools / middleware layer | Holds the SIEM credentials, runs the queries, applies the guardrails, minimizes the results | Internal |
| External TI connector | IOC lookup against whitelisted sources, returns sourced and cited indicators | Sole outbound flow |
| SIEM sources | Google SecOps (UDM / YARA-L), Sentinel (KQL), Defender (Advanced Hunting KQL), read-only | Internal |
| Deliverable storage | Reports, timelines, findings, hunt audit log | Internal |

### 3.2 Hunt flow

Upstream phase:

1. The analyst enters a hypothesis, a campaign name or free-form IOCs.
2. The agent looks up associated IOCs against the authorized TI sources. Each IOC is returned with its source. Only the campaign name or the IOC is sent outward, never any internal context.
3. The analyst sorts and validates the IOCs (mandatory human checkpoint). On rejection, return to step 1.
4. The model produces a playbook: leads ordered by SIEM with an objective and an ATT&CK technique, an estimate of the number of queries and iterations, and uncovered angles. It has no query tool at this stage (forced function call). The analyst validates, adjusts the budgets or reformulates with an instruction (mandatory human checkpoint): the retained budgets become the limits applied by the middleware, and the plan is injected into the agent's briefing.

Investigation loop (autonomous, bounded by an iteration budget):

5. The model generates a query suited to the target SIEM (UDM / YARA-L or KQL).
6. The middleware runs it read-only and applies the caps (volume, time window, rate limit).
7. The middleware minimizes the results (field selection, masking, aggregation, token cap) and returns them to the model.
8. The model analyzes and decides: pivot to a new entity, dig deeper, or conclude. Return to step 5 as long as the budget allows.

Delivery:

9. The agent produces the report (summary, timeline, findings, executed queries, proposed verdict) and feeds the dashboard.
10. Analyst review: final human verdict.
11. Continuation (optional): an interrupted hunt (budget, analyst stop, restart) keeps its execution state - tokenized transcript, pseudonym table, consumed budgets, query registry, findings - saved to the internal database at each iteration and kept until the analyst validates the report. "Continue the same investigation" reloads that state and resumes the loop exactly where it stopped, with caps possibly raised by the analyst and an optional instruction for what follows (logged). A concluded but unvalidated hunt continues the same way, to complete a conclusion judged insufficient: the report is rebuilt, the previous verdict and summary stay in the audit trail. A validated report freezes the hunt: only a new linked investigation remains possible.
12. Resumption (optional): from a finished or interrupted hunt, the analyst creates a new linked investigation - free-form question or instruction, resumption point chosen among the executed queries. It inherits the validated IOCs, receives the parent's persisted progress in its briefing (report, or failing that the audit log), and goes back through the playbook checkpoint. The original hunt is never modified.

## 4. Prerequisites

### 4.1 AI gateway / AI platform team side

- Access to the AI gateway with function calling enabled: a capable model for analysis and decision, a fast model for query generation (exact identifiers per the gateway's catalog).
- Written confirmation from the platform team on the guarantees of the gateway -> model provider path: non-retention, non-training on the data, data residency. This point defines what "staying internal" means contractually.
- Quotas and token budget dedicated to the use case (long hunts consume a lot; plan for prompt caching if available).
- A service account / gateway key dedicated to the platform, distinct from individual usage, for attribution and audit.

### 4.2 SIEM side (strict read-only access)

This section serves as an access-request sheet. For each SIEM: the technical identity to create, the API permission and the exact role to request.

**Google SecOps (Chronicle)**

- Identity: a dedicated GCP service account for the platform (not shared with any other usage). This is the standard pattern for programmatic access to SecOps.
- Role: **Chronicle API Viewer** (predefined role, read-only access to the SecOps application and API). A more restrictive variant is possible: **Chronicle API Limited Viewer**, which excludes detection-engine rules and retrohunts.
- Authentication: if the middleware runs on GCP, prefer Workload Identity (identity attached to the workload) over an exported JSON key. Off GCP, the JSON key goes to the vault with scheduled rotation. A JSON key grants the full access of the account: handle it with the highest level of care.
- Do not request: any write access to rules or feeds.

**Microsoft Sentinel**

- Identity: a dedicated Entra ID app registration (service principal), preferably with a certificate (or a client secret).
- API permission: **Log Analytics Data.Read** (application permission authorizing calls to the query API).
- Azure RBAC role: **Log Analytics Reader**, preferably assigned at the level of each Log Analytics workspace hosting Sentinel (least privilege), rather than at the subscription level. This role alone grants the right to read data by query, without execution or writing.
- Optional: **Microsoft Sentinel Reader** if you also want to read Sentinel incidents, not just the logs.
- Data lake case: if Sentinel has been switched to the data lake (unified Defender portal), service-principal access still goes through the Azure RBAC roles on the workspace (Log Analytics Reader). Entra ID roles or unified XDR RBAC are not supported for this scenario.
- To verify: role assignments are cumulative; make sure no broader role (Contributor, Owner) lingers on this service principal via a group.

**Microsoft Defender**

- Identity: Entra ID app registration (the same one as Sentinel can be shared, or a second dedicated one depending on the separation policy).
- API permission: **ThreatHunting.Read.All** of type Application (the agent runs with no signed-in user), to call the Graph endpoint `POST /security/runHuntingQuery`. Requires tenant admin consent.
- Preferred path: the Microsoft Graph security API (ThreatHunting.Read.All). The older Defender XDR API (`api.security.microsoft.com`, permission `AdvancedHunting.Read.All`) is an older version with limited capabilities: do not request it.
- Structural API limits (to carry over into the middleware caps): queries limited to the last 30 days, 100,000 rows max per response, call quotas (45/minute, 1,500/hour) and execution-time quotas. The max window on the Defender side is therefore effectively 30 days; beyond that, rely on Sentinel if the Defender tables are ingested there.
- Do not request: any remediation permission.

**Common to all three**

- Secrets (SA key, Entra secrets/certificates) stored in an enterprise secrets vault (Azure Key Vault, HashiCorp Vault or equivalent). Azure Key Vault is the most coherent choice if the platform runs on Azure: native integration with Entra ID and possible access via managed identity, with no secret stored in the clear. In all cases: scheduled rotation, secrets never exposed to the model nor present in prompts, and priority given to an identity managed by the hosting platform (managed identity on Azure, Workload Identity on GCP) over an exported key.
- Retention windows known per SIEM (this conditions the maximum time windows of hunts).

### 4.3 External threat intelligence side

- Whitelist of sources approved by security (examples to arbitrate: VirusTotal, public Mandiant / MISP feeds, CISA / ANSSI advisories, vendor reports).
- API keys for the sources that require them, same vault rules.
- Network egress authorized from the TI connector only, toward these domains only.
- Anti-leak rule implemented in the connector: outbound requests contain only the campaign name or the IOC, never a hunt result nor an internal identifier.

### 4.4 Platform side

- Internal hosting environment (containers or VMs) for the orchestrator, the middleware and the interface, in a network zone that has access to the AI gateway, the SIEM APIs and the TI connector, and nothing else.
- OpenAI-compatible orchestration framework (LangChain, LlamaIndex, or a home-grown orchestrator) wired to the AI gateway.
- Internal database for the hunts, findings, reports and the audit log (each executed query is logged with the hunt identity, the target SIEM, the query and the returned volume).
- Definition of the middleware's default caps: max number of rows returned per query, max time window, max iteration budget per hunt, max token budget per hunt.
- Sensitive-field masking policy (to be defined with the CISO: personal data, secrets, sensitive business fields).

### 4.5 Organization side

- CISO / DPO validation of the outbound TI flow and of the transit of minimized results through the AI gateway.
- At least one referent analyst for the pilot phase and the definition of test hypotheses.
- Report-review procedure: who validates, within what deadline, and what triggers an escalation.

## 5. Technical guardrails (implemented in the middleware)

| Guardrail | Implementation |
|---|---|
| Read-only | Minimal API permissions + no write tool exposed to the agent |
| Volume cap | `take 500` injected into each query - it is both the analysis threshold and the overflow detector: result under the cap, the model receives everything and analyzes row by row; cap reached, it receives only aggregates and must refine (or aggregate within the SIEM). Also bounds what enters the platform (network, anonymization, API quotas) |
| Time cap | Max window per query (Defender: 30 days max imposed by the API; Sentinel / SecOps: per retention), extensible on analyst validation |
| Defender row cap | Graph response capped at 100,000 rows; also respect the call quotas (45/min, 1,500/h) |
| Minimization | Selection of useful fields, masking of sensitive fields, aggregation when possible |
| Tokenization of internal identifiers | Hosts, accounts and private IPs replaced by stable per-hunt pseudonyms (`HOST-001`) before any send to the model; queries detokenized at the SIEM boundary, report rehydrated locally. Internal identifiers do not leave the platform, independently of the gateway's pseudonymization (defense in depth, flow-classification argument) |
| Iteration budget | Max number of steps per hunt (e.g. 20), clean stop with a partial report |
| Cost budget | Token cap per hunt, alert at 80% |
| IOC anti-hallucination | IOCs accepted only if they carry a cited source and an analyst validation |
| Egress anti-leak | Filtering of outbound TI requests: campaign name or IOC only |
| Prompt injection | SIEM and TI results are treated as untrusted data: wrapped in tags, never interpreted as instructions |
| Audit | Full log: queries, volumes, agent decisions, timestamp |

Specific point of attention: SIEM logs and TI pages can contain hostile text (an attacker can place instructions in a log field). The agent's system prompt must make explicit that the content of results is never an instruction, and the middleware must wrap these contents in clear delimiters.

## 6. Hunt output deliverables

- **Investigation report**: starting hypothesis, validated IOCs and their sources, executed queries per SIEM, timeline of relevant events, findings with a confidence level, proposed verdict (benign / suspicious / to escalate), investigation limitations.
- **Consolidated dashboard**: view of past and ongoing hunts, findings by severity, most affected entities, coverage by SIEM.

## 7. Open questions

- Definitive TI whitelist and access modalities (keys, quotas).
- Field masking policy: which fields, which SIEMs.
- Retention of reports and hunt contexts (duration, who accesses them).
- Prompt caching available on the AI gateway to reduce the cost of long hunts?
