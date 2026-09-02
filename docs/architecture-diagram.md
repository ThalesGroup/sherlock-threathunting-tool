# Flow diagram

Overview of the components and data flows, as implemented in the code.
Reading rule: everything in the internal zone never leaves the perimeter. The logs
are anonymized in the middleware before any send to the reasoning model; the mapping
table never leaves the platform.

## Overview

```mermaid
flowchart TB
    ANALYST["Analyst<br/>(browser, no secret)"]

    subgraph SI["Internal information system (organization)"]
        subgraph PF["Threat hunting platform"]
            API["Internal API"]
            AGENT["Hunt agent<br/>(orchestrator + tools)"]
            MW["Middleware<br/>guardrails, anonymization, audit"]
            ANON["Anonymizer<br/>(local model)"]
            DB[("Internal database<br/>reports, audit")]
            VAULT[("Secrets<br/>encrypted store / Key Vault")]
        end
        SIEM["SIEM / EDR: Sentinel, Defender, SecOps<br/>(internal tools, read-only)"]
    end

    ENGINE["LLM via the AI gateway (AI platform team)<br/>contractual boundary"]
    TI["Threat intelligence — public internet<br/>(whitelist: VirusTotal, OTX,<br/>ThreatFox, CIRCL, publishers)"]

    ANALYST -->|"hypothesis / campaign"| API
    API -->|"orchestration"| AGENT
    AGENT -->|"tool calls"| MW
    MW -->|"read-only queries"| SIEM
    SIEM -->|"raw logs"| MW
    MW -->|"free text to anonymize"| ANON
    ANON -->|"detected fragments"| MW
    AGENT <-->|"pseudonyms only"| ENGINE
    MW -->|"campaign name only<br/>(upstream phase)"| TI
    MW -->|"reports, audit"| DB
    VAULT -.->|"credentials<br/>never seen by the model"| MW

    classDef internal fill:#e9edf1,stroke:#5b6b7c,color:#12212f
    classDef ia fill:#fff,stroke:#0a5f9e,color:#12212f
    classDef external fill:#fff,stroke:#8f1d1d,color:#12212f,stroke-dasharray: 5 5
    class API,AGENT,MW,DB,VAULT,SIEM internal
    class ANON ia
    class ENGINE ia
    class TI external
```

Three trust zones: the **platform** and the **SIEM/EDR** are two internal systems
of the organization (the logs stay at their host, the platform reads them read-only).
Only two boundaries leave this internal system: **the LLM via the AI gateway** (contractual
boundary with the AI platform team, pseudonyms only) and the **threat intelligence** (public internet, campaign
name only). The ANON anonymizer (local model) is **on-prem, inside the platform**: it has the
right to see the raw data, unlike the reasoning model which only receives pseudonyms.

## Flow of the protected data

This is the heart of the guarantee. A SIEM result crosses three nets before reaching the
reasoning model; the return path (queries, report) is detokenized locally.

```mermaid
flowchart TB
    RAW["Raw SIEM results<br/>hosts, accounts, IPs, emails, names"]
    MIN["1 · Minimization<br/>useful fields, secrets removed,<br/>aggregation, token cap"]
    DET["2 · Deterministic layer (2 passes)<br/>named fields + patterns<br/>HOST-001 · USER-001 · IP-INT-001<br/>same value replaced in bulk fields"]
    SEM["3 · Semantic pass (local model)<br/>residual in free text → DATA-001<br/>fail-closed: unreachable ⇒ field masked"]
    OUT["LLM via the AI gateway<br/>sees ONLY pseudonyms"]
    VAULT[("Mapping table<br/>stays in the platform")]
    BACK["Report & analyst feed<br/>rehydrated locally"]

    RAW --> MIN --> DET --> SEM --> OUT
    DET -.->|"records"| VAULT
    SEM -.->|"records"| VAULT
    VAULT -.->|"rehydration"| BACK
    OUT -.->|"pivot query on HOST-001,<br/>detokenized before the SIEM"| RAW

    classDef step fill:#e9edf1,stroke:#5b6b7c,color:#12212f
    classDef guard fill:#fff,stroke:#a8560b,color:#12212f
    classDef ia fill:#fff,stroke:#0a5f9e,color:#12212f
    classDef store fill:#fff,stroke:#5b6b7c,color:#12212f
    class RAW,BACK step
    class MIN,DET,SEM guard
    class OUT ia
    class VAULT store
```

Reading: the data descends while being anonymized (nets 1 to 3); only pseudonyms
reach the model. The mapping table (dotted arrows) serves only internally:
rehydrating the report for the analyst, and detokenizing a pivot query before the SIEM.
The model never sees a real value, and could not recover it.

## Course of a hunt

```mermaid
flowchart TB
    INPUT["Analyst: hypothesis OR campaign"]
    ENRICH["Threat intelligence enrichment<br/>(only outbound flow, campaign name only)<br/>TI databases + approved vendor reports"]
    CHK1{"Human checkpoint 1<br/>IOC validation"}
    PLAN["Agent proposes a playbook:<br/>leads, ATT&CK techniques,<br/>query and iteration estimates"]
    CHK2{"Human checkpoint 2<br/>playbook & budget validation"}
    LAUNCH["Hunt launch"]

    subgraph LOOP["Investigation loop (bounded by budgets)"]
        GEN["Query model: reasons<br/>and generates a query"]
        EXEC["Middleware runs it read-only,<br/>minimizes then anonymizes the result"]
        DECIDE{"Pivot or conclude?"}
    end

    FINAL["Analysis model: re-reads the file<br/>and settles the verdict"]
    REPORT["Report: proposed verdict,<br/>timeline, findings, limitations"]
    CHK3{"Human checkpoint 3<br/>analyst's final verdict"}

    INPUT --> ENRICH --> CHK1
    CHK1 -->|"IOCs rejected: reformulate"| INPUT
    CHK1 -->|"IOCs validated"| PLAN
    PLAN --> CHK2
    CHK2 -->|"reformulate the plan"| PLAN
    CHK2 -->|"plan validated, budgets set"| LAUNCH
    LAUNCH --> GEN --> EXEC --> DECIDE
    DECIDE -->|"pivot"| GEN
    DECIDE -->|"conclude or budget exhausted"| FINAL
    FINAL --> REPORT --> CHK3

    classDef human fill:#fff,stroke:#a8560b,color:#12212f
    classDef step fill:#e9edf1,stroke:#5b6b7c,color:#12212f
    classDef ia fill:#fff,stroke:#0a5f9e,color:#12212f
    class INPUT,CHK1,CHK2,CHK3 human
    class ENRICH,LAUNCH,EXEC,REPORT step
    class GEN,DECIDE,PLAN,FINAL ia
```

The amber diamonds are the moments where the human decides; the indigo frames are the
model calls; the rest is the platform. During the loop, no outbound tool
exists: enrichment is only possible before launch.

## Identities and secrets

| Target | Technical identity | Exact permission | Where the secret lives |
|---|---|---|---|
| Sentinel | Entra ID app registration | Log Analytics Data.Read + Log Analytics Reader role (per workspace) | Store / Key Vault (`ENTRA_*`) |
| Defender | Entra ID app registration | ThreatHunting.Read.All (application, admin consent) | Store / Key Vault (`ENTRA_*`) |
| SecOps | GCP service account | Chronicle API Viewer (Workload Identity preferred) | Store / Key Vault |
| AI gateway (reasoning) | Platform-dedicated service key | Gateway access, function calling | Store / Key Vault (`GATEWAY_API_KEY`) |
| ANON (anonymization) | Dedicated anonymization key | Local endpoint (OpenAI-compatible) | Store / Key Vault (`ANONYMIZER_API_KEY`) |
| Threat intelligence | Key per source | Search only | Store / Key Vault (`OTX_API_KEY`, etc.) |

The keys are entered in the Configuration screen (write-only, encrypted store
`.secrets.enc`), with a switch to Azure Key Vault in production (`SHL_KEY_VAULT_URL`). The
secrets are never in the clear, never logged, never in a prompt; the front end and the model
never see them.

## What guarantees that the data stays internal

1. **Model registry with no outbound tool**: during the loop, the agent materially has
   no tool whose flow leaves the perimeter. A string read from a
   log cannot become an external request, even on prompt injection.
2. **Enrichment confined to the upstream phase**: `/enrich` is reserved for the analyst and
   refused as soon as the hunt is launched. Only the campaign name leaves, after the anti-leak
   filter (private IPs, identifiers, paths, email addresses, internal DNS suffixes).
3. **Anonymization in depth before any return to the model**: minimization, then the
   deterministic layer (named fields + patterns, in two passes to cover the bulk fields),
   then the ANON semantic pass for the residual in free text. Fail-closed: if the anonymization model
   is unreachable, the free text is masked, never let through. The model never receives
   a real value, and the mapping table does not leave the platform.
4. **The AI gateway transit is the only contractual zone**: the anonymized data
   transits to the model through the platform team's gateway. The guarantee (non-retention,
   non-training, prompt caching included) is a commitment to be confirmed in writing,
   not a property of the code.
