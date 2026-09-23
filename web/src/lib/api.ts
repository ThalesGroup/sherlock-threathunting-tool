/**
 * Internal API client.
 *
 * The browser only talks to this API. It holds no SIEM credential, knows no source
 * endpoint, and only receives data already minimized by the middleware.
 */

export type IocStatus = "pending_validation" | "validated" | "rejected";
export type TimeRange = "month" | "3months" | "9months" | "year" | null;
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type Verdict = "benign" | "suspicious" | "escalate" | "inconclusive";
export type HuntStatus =
  | "draft"
  | "awaiting_ioc_validation"
  | "awaiting_plan_validation"
  | "running"
  | "awaiting_review"
  | "closed"
  | "interrupted";

export interface Ioc {
  value: string;
  type: string;
  source: string;
  source_url: string;
  corroborating_sources: string[];
  first_seen: string | null;
  confidence: string | null;
  status: IocStatus;
}

export interface SourceLimits {
  name: string;
  max_window_days: number;
  max_rows: number;
  configured: boolean;
  note: string | null;
}

export interface PlatformConfig {
  sources: SourceLimits[];
  budgets: {
    max_iterations: number;
    max_siem_queries: number;
    max_tokens: number;
    max_duration_seconds: number;
    token_alert_ratio: number;
  };
  threat_intel_enabled: boolean;
  workspaces: string[];
  demo_siem: boolean;
}

export interface HuntSummary {
  hunt_id: string;
  hypothesis: string;
  campaign: string | null;
  analyst: string;
  status: HuntStatus;
  created_at: string;
  interruption_reason: string | null;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  entities: { type: string; value: string }[];
  evidence_query_ids: string[];
  recorded_at: string;
}

export interface AnonymizationInfo {
  semantic: "active" | "degraded" | "disabled";
  tokenization: boolean;
  masked_fields: number;
  tokens: { HOST: number; USER: number; "IP-INT": number; DATA: number };
}

export interface ExecutedQuery {
  intent: string | null;
  columns: string[];
  sample: Record<string, unknown>[];
  model_sample: Record<string, unknown>[];
  anonymization: AnonymizationInfo | null;
  interpretation: string | null;
  query_id: string;
  siem: string;
  query: string;
  executed_at: string;
  returned_rows: number;
  source_rows: number;
  truncated: boolean;
  duration_ms: number;
}

export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
}

export interface AttackOverview {
  description: string;
  techniques: AttackTechnique[];
  scope: string;
}

export interface PlaybookStep {
  order: number;
  siem: string;
  objective: string;
  technique: string | null;
  expected_queries: number;
}

export interface Playbook {
  summary: string;
  steps: PlaybookStep[];
  not_covered: string;
  estimated_queries: number;
  estimated_iterations: number;
  instruction: string | null;
  generated_at: string;
  validated_by: string | null;
  validated_at: string | null;
  validated_queries: number | null;
  validated_iterations: number | null;
}

export interface HumanDecision {
  verdict: Verdict;
  decided_by: string;
  decided_at: string;
  comment: string | null;
}

export interface HuntReport {
  hunt_id: string;
  hypothesis: string;
  campaign: string | null;
  analyst: string;
  status: HuntStatus;
  proposed_verdict: Verdict;
  summary: string;
  limitations: string;
  iocs: Ioc[];
  findings: Finding[];
  timeline: { timestamp: string; event: string; source: string }[];
  executed_queries: ExecutedQuery[];
  budgets: Record<string, { used: number; limit: number }>;
  partial: boolean;
  interruption_reason: string | null;
  generated_at: string;
  human_decision: HumanDecision | null;
  attack_overview: AttackOverview | null;
  playbook: Playbook | null;
  parent_hunt_id: string | null;
  recommendation: string | null;
  sources: string[];
  investigation_window: string | null;
}

export interface AuditEntry {
  id: number;
  type: string;
  actor: string;
  timestamp: string;
  siem: string | null;
  query_id: string | null;
  query: string | null;
  rows_returned: number | null;
  truncated: boolean | null;
  duration_ms: number | null;
  error_code: string | null;
  detail: Record<string, unknown>;
}

export interface Dashboard {
  recent_hunts: HuntSummary[];
  findings_by_severity: Record<string, number>;
  top_entities: { entity: string; count: number }[];
  queries_by_siem: Record<string, number>;
}

export interface SessionUser {
  name: string;
  roles: string[];
}

export interface AccountView {
  username: string;
  roles: string[];
  created_by: string;
  created_at: string;
}

export interface SecretFieldView {
  name: string;
  configured: boolean;
  origin: "configuration" | "environment" | null;
  updated_at: string | null;
  updated_by: string | null;
}

export interface SourceConfigView {
  id: string;
  label: string;
  kind: "engine" | "siem" | "ti";
  active: boolean;
  secrets: SecretFieldView[];
  requirement: string | null;
  endpoint: string | null;
  model: string | null;
}

export interface SourceTestResult {
  source: string;
  ok: boolean;
  detail: string;
}

export interface CreateHuntPayload {
  hypothesis?: string | null;
  campaign?: string | null;
  manual_iocs?: { value: string; type: string; note?: string }[];
  sources?: string[];
  max_iterations?: number;
  max_siem_queries?: number;
  window_start?: string;
  window_end?: string;
}

export interface CtiIoc {
  value: string;
  type: string;
}

export interface CtiAttack {
  name: string;
  kind: string;
  summary: string;
  approach: "hypothesis" | "campaign";
  suggested_hypothesis: string;
  iocs: CtiIoc[];
}

export interface CtiAnalysis {
  analysis_id: string;
  attacks: CtiAttack[];
  pages: number;
  truncated: boolean;
}

export interface CtiStoredAttack extends CtiAttack {
  probe: CtiProbe | null;
}

export interface CtiStoredAnalysis {
  analysis_id: string;
  filename: string;
  analyzed_by: string;
  analyzed_at: string;
  pages: number;
  truncated: boolean;
  attacks: CtiStoredAttack[];
}

export interface CtiHistoryEntry {
  id: string;
  filename: string;
  analyzed_by: string;
  analyzed_at: string;
  attacks: number;
  iocs: number;
  pages: number;
}

export interface CtiProbe {
  found: number;
  sources: string[];
  sample: CtiIoc[];
}

/** Screen relevant to a hunt depending on its state: validation, live thread, or report. */
export function huntPath(hunt: {
  hunt_id: string;
  status: HuntStatus;
}): string {
  if (hunt.status === "awaiting_ioc_validation") {
    return `/hunts/${hunt.hunt_id}/indicators`;
  }
  if (hunt.status === "draft" || hunt.status === "awaiting_plan_validation") {
    return `/hunts/${hunt.hunt_id}/playbook`;
  }
  if (hunt.status === "running") {
    return `/hunts/${hunt.hunt_id}/feed`;
  }
  return `/hunts/${hunt.hunt_id}/report`;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | null,
    message: string,
    readonly hint: string | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * Authentication goes through an httpOnly cookie session, which the browser attaches by
 * itself to every request: nothing to add here. This function remains the insertion point
 * for the Entra ID token (code flow with PKCE) once SSO is wired in.
 */
export function authHeaders(): Record<string, string> {
  return {};
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(init.headers ?? {}),
    },
  });

  if (!response.ok) {
    throw await toApiError(response);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as T;
  }
  return (await response.text()) as unknown as T;
}

async function toApiError(response: Response): Promise<ApiError> {
  let code: string | null = null;
  let message = `The request failed (${response.status}).`;
  let hint: string | null = null;
  try {
    const body = await response.json();
    const detail = body?.detail;
    if (typeof detail === "string") {
      message = detail;
    } else if (detail && typeof detail === "object") {
      code = detail.error ?? null;
      message = detail.message ?? message;
      hint = detail.hint ?? null;
    }
  } catch {
    /* non-JSON body: keep the default message */
  }
  return new ApiError(response.status, code, message, hint);
}

export const api = {
  config: () => request<PlatformConfig>("/api/config"),

  listHunts: (
    params: { analyst?: string; status?: string; limit?: number } = {},
  ) => {
    const search = new URLSearchParams();
    if (params.analyst) search.set("analyst", params.analyst);
    if (params.status) search.set("status", params.status);
    if (params.limit) search.set("limit", String(params.limit));
    const suffix = search.toString() ? `?${search}` : "";
    return request<HuntSummary[]>(`/api/hunts${suffix}`);
  },

  createHunt: (payload: CreateHuntPayload) =>
    request<{
      hunt_id: string;
      status: HuntStatus;
      requires_ioc_validation: boolean;
    }>("/api/hunts", { method: "POST", body: JSON.stringify(payload) }),

  enrich: (
    huntId: string,
    campaignName: string,
    maxResults = 50,
    timeRange: TimeRange = null,
  ) =>
    request<Ioc[]>(`/api/hunts/${huntId}/enrich`, {
      method: "POST",
      body: JSON.stringify({
        campaign_name: campaignName,
        max_results: maxResults,
        time_range: timeRange,
      }),
    }),

  listIocs: (huntId: string) => request<Ioc[]>(`/api/hunts/${huntId}/iocs`),

  ctiHistory: () => request<CtiHistoryEntry[]>("/api/cti/history"),

  probeCti: (campaignName: string, analysisId?: string, attackIndex?: number) =>
    request<CtiProbe>("/api/cti/probe", {
      method: "POST",
      body: JSON.stringify({
        campaign_name: campaignName,
        ...(analysisId !== undefined ? { analysis_id: analysisId } : {}),
        ...(attackIndex !== undefined ? { attack_index: attackIndex } : {}),
      }),
    }),

  getCtiAnalysis: (analysisId: string) =>
    request<CtiStoredAnalysis>(
      `/api/cti/analyses/${encodeURIComponent(analysisId)}`,
    ),

  deleteCtiAnalysis: (analysisId: string) =>
    request<void>(`/api/cti/analyses/${encodeURIComponent(analysisId)}`, {
      method: "DELETE",
    }),

  /** Analysis of a CTI report (PDF). The file is sent as a raw body to the internal API. */
  analyzeCti: async (file: File): Promise<CtiAnalysis> => {
    const response = await fetch(
      `/api/cti/analyse?filename=${encodeURIComponent(file.name)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/pdf", ...authHeaders() },
        body: file,
      },
    );
    if (!response.ok) {
      throw await toApiError(response);
    }
    return (await response.json()) as CtiAnalysis;
  },

  importIocs: async (huntId: string, file: File) => {
    const response = await fetch(
      `/api/hunts/${huntId}/iocs/import?filename=${encodeURIComponent(file.name)}`,
      { method: "POST", headers: authHeaders(), body: file },
    );
    if (!response.ok) {
      throw await toApiError(response);
    }
    return (await response.json()) as {
      iocs: Ioc[];
      added: number;
      duplicates: number;
      extracted: number;
      by_type: Record<string, number>;
    };
  },

  addIocs: (
    huntId: string,
    iocs: { value: string; type: string; note?: string }[],
  ) =>
    request<{ iocs: Ioc[]; added: number; duplicates: string[] }>(
      `/api/hunts/${huntId}/iocs`,
      {
        method: "POST",
        body: JSON.stringify({ iocs }),
      },
    ),

  validateIocs: (huntId: string, validated: string[], rejected: string[]) =>
    request<Ioc[]>(`/api/hunts/${huntId}/iocs/validate`, {
      method: "POST",
      body: JSON.stringify({ validated, rejected }),
    }),

  startHunt: (
    huntId: string,
    budgets?: { max_iterations?: number; max_siem_queries?: number },
  ) =>
    request<{ hunt_id: string; status: HuntStatus; running: boolean }>(
      `/api/hunts/${huntId}/start`,
      { method: "POST", body: JSON.stringify(budgets ?? {}) },
    ),

  resumeOptions: (huntId: string) =>
    request<{ hunt_id: string; status: HuntStatus; continuable: boolean }>(
      `/api/hunts/${huntId}/resume-options`,
    ),

  continueHunt: (
    huntId: string,
    payload?: {
      max_iterations?: number;
      max_siem_queries?: number;
      instruction?: string;
    },
  ) =>
    request<{ hunt_id: string; status: HuntStatus; running: boolean }>(
      `/api/hunts/${huntId}/continue`,
      { method: "POST", body: JSON.stringify(payload ?? {}) },
    ),

  resumeHunt: (
    huntId: string,
    payload: { instruction?: string; from_query_id?: string },
  ) =>
    request<{ hunt_id: string; status: HuntStatus; parent_hunt_id: string }>(
      `/api/hunts/${huntId}/resume`,
      { method: "POST", body: JSON.stringify(payload) },
    ),

  planHunt: (huntId: string, instruction: string | null) =>
    request<Playbook>(`/api/hunts/${huntId}/plan`, {
      method: "POST",
      body: JSON.stringify({ instruction }),
    }),

  getPlan: (huntId: string) =>
    request<Playbook | null>(`/api/hunts/${huntId}/plan`),

  decideBudget: (
    huntId: string,
    payload: {
      action: "extend" | "stop";
      extra_iterations?: number;
      extra_siem_queries?: number;
      extra_minutes?: number;
      extra_tokens?: number;
    },
  ) =>
    request<{ hunt_id: string; extended: boolean }>(
      `/api/hunts/${huntId}/budget`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),

  stopHunt: (huntId: string) =>
    request<{ hunt_id: string; status: string }>(`/api/hunts/${huntId}/stop`, {
      method: "POST",
    }),

  report: (huntId: string) =>
    request<HuntReport>(`/api/hunts/${huntId}/report`),

  reportMarkdown: (huntId: string) =>
    request<string>(`/api/hunts/${huntId}/report?format=markdown`),

  reportPdf: async (huntId: string): Promise<Blob> => {
    const response = await fetch(`/api/hunts/${huntId}/report?format=pdf`, {
      headers: authHeaders(),
    });
    if (!response.ok) {
      throw await toApiError(response);
    }
    return response.blob();
  },

  decide: (huntId: string, verdict: Verdict, comment: string | null) =>
    request<{ hunt_id: string; verdict: Verdict; decided_by: string }>(
      `/api/hunts/${huntId}/decision`,
      { method: "POST", body: JSON.stringify({ verdict, comment }) },
    ),

  audit: (huntId: string) =>
    request<AuditEntry[]>(`/api/hunts/${huntId}/audit`),

  deleteHunt: (huntId: string) =>
    request<void>(`/api/hunts/${encodeURIComponent(huntId)}`, {
      method: "DELETE",
    }),

  dashboard: () => request<Dashboard>("/api/dashboard"),

  /** Local account session. Accounts are created by an admin, no self-registration. */
  me: () => request<SessionUser>("/api/auth/me"),

  login: (username: string, password: string) =>
    request<SessionUser>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  logout: () => request<void>("/api/auth/logout", { method: "POST" }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<void>("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    }),

  listAccounts: () => request<AccountView[]>("/api/config/accounts"),

  createAccount: (username: string, password: string, roles: string[]) =>
    request<{ username: string }>("/api/config/accounts", {
      method: "POST",
      body: JSON.stringify({ username, password, roles }),
    }),

  deleteAccount: (username: string) =>
    request<void>(`/api/config/accounts/${encodeURIComponent(username)}`, {
      method: "DELETE",
    }),

  /** Configuration screen (admin role). Keys are written, they are never read back. */
  sourceConfiguration: () => request<SourceConfigView[]>("/api/config/sources"),

  setSecret: (name: string, value: string) =>
    request<void>(`/api/config/secrets/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify({ value }),
    }),

  deleteSecret: (name: string) =>
    request<void>(`/api/config/secrets/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),

  testSource: (sourceId: string) =>
    request<SourceTestResult>(
      `/api/config/sources/${encodeURIComponent(sourceId)}/test`,
      {
        method: "POST",
      },
    ),
};
