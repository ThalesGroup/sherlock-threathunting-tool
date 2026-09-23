# Web interface

Front-end specification. Covers the screens, the visual direction, the stack and the browser-specific security constraints.

## Role of the front end

The front end is the analyst's workspace. It never talks to the SIEMs or to the AI gateway: it only talks to the platform's internal API. No secret, no credential, no SIEM endpoint passes through the browser.

It carries two responsibilities the engine cannot assume on its own: making the agent's reasoning legible, and materializing the three human checkpoints (IOC validation, playbook and budget validation, report validation).

## Screens

### 1. New hunt

Entry point. A free-text field for the hypothesis or the campaign name, plus an advanced mode to supply known IOCs directly - entered one by one, or imported from a file (txt, csv, xlsx) parsed at hunt creation, whose extracted indicators arrive pending validation.

Below the field: the hunt parameters (target SIEMs, time window, iteration budget), pre-filled with the default values and editable. The window displays the real limits per source (Defender caps at 30 days) rather than letting the analyst ask for the impossible.

Empty state: the list of recent hunts, to pick up a thread rather than start from scratch.

### 2. CTI analysis

The other entry point, for when the starting material is a threat intelligence report rather than a hypothesis. The analyst imports a CTI report (PDF: daily digest, vendor analysis, CERT bulletin); the document is treated as untrusted content and does not leave the internal perimeter. The agent breaks it down into distinct attacks, each with a summary and the IOCs published in the document, then probes the threat intelligence sources to check whether IOCs exist online for each threat. Each attack card carries the resulting recommendation - hunt by indicators (which goes through IOC validation) or by behavioral hypothesis (which goes straight to the playbook) - and a button to seed the corresponding hunt. Past analyses are kept in a side panel and can be reopened; the analysis survives navigating away.

### 3. IOC validation

Blocking screen. Until the analyst has decided, no query goes to a SIEM.

A table of the IOCs surfaced by the threat intelligence lookup, one row per indicator: value in monospace, type, clickable source, first-seen date, confidence level. Selection by checkbox, with global selection and bulk rejection.

The important element is the source column: it is always filled, it is always a link. This is the visual translation of the rule "no IOC from the model's memory". An indicator without a source does not make it this far, but if the case occurs, it appears struck through and non-selectable.

The analyst can also add their own indicators: one by one (value + type, duplicate flagged), or by file import (txt, csv, xlsx) - pattern extraction on the server side, normalized defang, deduplication; imported indicators arrive pending validation and therefore go back through the checkpoint.

Two actions: launch the hunt with the selection, or reformulate the hypothesis and re-run the lookup.

### 4. Playbook

Blocking screen, between the indicators (or creation, for a hypothesis hunt) and the hunt. The agent proposes its plan: approach, ordered leads (SIEM, objective, ATT&CK technique, planned queries), what the plan will not cover, and its estimate of queries and iterations. The analyst has two fields pre-filled with the estimate - SIEM queries, iterations - that they can adjust, an instruction area to reformulate the plan ("ignore Sentinel", "focus on persistence"), and the "Launch with this plan" button. Until they launch, no query goes out. Each generation and the validation (author, retained budgets, gap with the estimate) are logged. The New hunt form no longer carries budgets: they are decided here, in view of the plan.

### 5. Hunt in progress

The central screen, where trust in the agent is played out.

The investigation feed occupies the main column: each iteration is added at the bottom, live. One card per step, containing the objective the agent gave to the query, the generated query (in monospace, on a distinct background, collapsible), the queried SIEM, the number of returned rows, a sample of the rows behind an expand arrow (ten at most, the real total recalled in the label) with two views - a rehydrated "analyst view" and "transmitted to the model" with the pseudonyms in place - and an anonymization-proof line (pseudonyms placed by family, state of the semantic pass, masked fields), the truncation note where applicable, and the agent's reasoning that follows ("I pivot to this host", "no signal, I change angle").

In the side column: the state of the budgets (iterations consumed, SIEM queries, tokens, elapsed time), the entities encountered, and the findings already recorded. Whenever a budget runs out, whichever it is (iterations, queries, tokens, duration), the feed shows the budget checkpoint: continue with a supplement (iterations, queries, tokens; granted minutes count from the time already elapsed) or stop with a partial report. A stop button lets the analyst interrupt the hunt at any time; the interruption produces a partial report, never a blank screen.

### 6. Report

The deliverable. It opens like a case file: a cover header (reference, proposed verdict, analyst, period covered, sources, date), then the presentation of the searched-for attack - description for a reader who did not follow the hunt, MITRE ATT&CK techniques as cards, hunt scope computed by the platform - and the validated playbook (leads, planned versus executed queries, uncovered angles). Then come the summary, the proposed verdict, the agent's recommendation, the investigation limitations, the findings classified by severity, the observed entities, the execution log (one line per query) and, in appendix, the full text of the executed queries - each with the announced objective, the reading the agent made of the result (its real comment at the time of the investigation, never regenerated), the sample of rows and a "Resume the investigation from here" button that pre-fills the resumption card.

The PDF export follows the same structure with a real cover page, a running header and footer (a "restricted distribution" note, the hunt reference, pagination). The issuing entity shown on the cover is set on the server side (`SHL_REPORT_ORGANISATION`).

Reading rule: each finding displays the queries that support it, with a direct link to the corresponding step of the investigation feed. A finding not attachable to a query does not exist.

The verdict is presented as a proposal. The analyst has their own validation area: they confirm, correct or refute it, and their decision is timestamped and attributed. Export as PDF and Markdown.

The screen also carries resumption, in a "Resume this hunt" card whose "Question or instruction for what follows" area serves both actions. For an interrupted hunt, or a concluded one whose verdict has not been validated yet, "Continue the same investigation" relaunches the same hunt with its transcript, its pseudonyms, its remaining budgets (if exhausted, the budget checkpoint asks again in the feed) and the instruction, pseudonymised then injected into the transcript; after a conclusion the report is rebuilt and the previous verdict stays in the audit trail. Otherwise - or in addition - "New linked investigation" (instruction, choice of the query after which to restart) creates a new linked investigation, which inherits the validated indicators and receives the progress of the original hunt in its briefing - the original report stays unchanged, and the resumption goes back through the playbook checkpoint. A report resulting from a resumption displays a link to its parent hunt.

### 7. Dashboard

Consolidated view: recent hunts and their status, findings by severity, most frequently affected entities, coverage by SIEM over the period. Each element is an entry point to the corresponding hunt.

### 8. History and audit

The complete list of hunts with filters (period, analyst, verdict, SIEM). For each hunt, access to the full log: executed queries, volumes, agent decisions, human validations with their author and timestamp. This screen is what is shown during a compliance audit.

### 9. Configuration

Reserved for the admin role. Each installation wires in the keys of its ecosystem here: the AI gateway, Entra ID app registration (Sentinel / Defender), threat intelligence sources. The Sentinel workspace is declared here by Subscription ID, resource group and name: the platform finds the Workspace ID itself (Azure Resource Manager read with the same app registration) and memorizes it; the real workspace name never leaves toward the model, which only sees the alias `soc-principal`.

The principle is write-only: a key is entered, tested and deleted, but never read back. The API returns only states (configured, provided by the environment, absent), the author and the last-modified date. A "Test the connection" button triggers a minimal real call on the server side and displays the result.

Two intentional limits: the outbound authorized domains (TI whitelist, approved publishers) are not editable from this screen - they remain a server decision validated by security - and each key modification is logged in the audit (author, key concerned, timestamp, never the value).

The screen also carries the management of local accounts: creation (identifier, password, roles) and deletion, without self-registration. The last admin account is not deletable, and the first account is bootstrapped by a server-side script.

## Visual direction

The subject is an investigation: traces, evidence, a chain of reasoning to verify. The interface borrows from the case file rather than from the supervision console. We avoid the black background with a fluorescent accent, which has become the reflex of the field and a poor companion for long reading sessions.

Palette:

| Name | Hex | Usage |
|---|---|---|
| Ink | `#12212f` | Main text, headings |
| Paper | `#e9edf1` | Background of reading areas |
| Slate | `#5b6b7c` | Secondary text, rules |
| Meta | `#8494a3` | Metadata, timestamps, muted labels |
| Indigo | `#0a5f9e` | Interactive elements, links, selection |
| Navy | `#0d1e33` | Sidebar, primary buttons |
| Accent | `#2b8fd6` | Signature accents |
| Amber | `#a8560b` | Pending validation, truncated result, budget started |
| Garnet | `#8f1d1d` | Critical severity, escalation |
| Mint | `#1f6f5c` | Low severity, success states |

Amber and garnet only serve to signal, never to decorate. A healthy screen is in ink, paper and slate.

Typography:

- Titles and body text: a geometric sans stack - Century Gothic, with URW Gothic, Jost and Questrial as fallbacks, then the system sans.
- Data: IBM Plex Mono, for queries, hashes, IP addresses, domains and identifiers.

Monospace is not a stylistic effect: it is the language of the subject. A hash or a KQL query reads in fixed width, and this typographic distinction visually separates what the machine produced from what a human wrote.

Signature element: the investigation feed. The stance is to show the agent's reasoning instead of hiding it behind a loading indicator. Trust in an autonomous agent is not decreed, it is verified; the interface therefore makes the execution trace its central object rather than a piece of debug information relegated to the side.

Level of demand: responsive down to mobile for report consultation, visible keyboard focus, `prefers-reduced-motion` respected, AA-compliant contrasts.

## Proposed stack

- React 18 and TypeScript, Vite build
- Tailwind CSS for the tokens and the layout
- TanStack Query for server state
- Server-Sent Events for the live hunt feed (unidirectional, simpler than a WebSocket here)
- Authentication: local accounts managed by the admin (login page, session in an
  httpOnly cookie, no self-registration - access is granted, it is not requested);
  an SSO path is left for adopters to wire in

Roles: `analyst` (launches hunts, validates IOCs and reports), `reader` (read-only consultation) and `admin` (Configuration screen: management of the source keys). Validation actions are reserved for the analyst role, configuration for the admin role, and all are logged.

## Front-end security constraints

1. Content from the SIEMs and from threat intelligence is rendered as inert text. Never `dangerouslySetInnerHTML`, never unsanitized Markdown rendering on those fields. A log field can contain hostile code placed there deliberately.
2. No secret on the browser side. The front end receives data already minimized by the middleware; it has no SIEM credential and cannot obtain one.
3. Internal technical identifiers (real workspace names, endpoints, service identities) are not exposed in the API responses.
4. Validation actions require an active authentication and are attributed by name.
5. No investigation data in persistent browser storage.

## Copy and tone

The labels name what the analyst controls, not the internal mechanics. We write "Launch the hunt", "Validate the indicators", "Confirm the verdict". An action keeps the same name from one end of the journey to the other.

Empty states are invitations to act, not messages of apology. Errors say what happened and what to do: "The requested window exceeds 30 days, the limit of the Defender API. Reduce the period or query Sentinel."

Point of vocabulary to hold: the agent proposes, the analyst decides. No label presents an agent output as an established conclusion.
