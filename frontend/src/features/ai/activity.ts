import { apiRequest, ApiError } from "@/config/api";

export interface ActivityMetrics {
  attempts: number; answered: number; failed: number;
  dispatches: number | null; dispatchReports: number;
  usefulResults: number | null; usefulReports: number;
  unusable: number | null; waitingTimeouts: number | null; retries: number | null; fallbacks: number | null;
  inputTokens: number | null; inputReports: number;
  outputTokens: number | null; outputReports: number;
  cachedTokens: number | null; cacheReports: number;
  avgWaitMs: number | null; waitReports: number;
  avgRequestMs: number | null; requestReports: number;
  avgTotalMs: number | null; totalReports: number;
  avgProviderMs: number | null; providerReports: number;
}
export interface ActivityService {
  serviceId: string; serviceLabel: string; serviceKind: string; provider: string;
}
export interface ActivityGroup extends ActivityService, ActivityMetrics {
  feature: string; purpose: string; requested: string; reported: string; outcome: string; legacy: boolean;
}
export interface ActivityReport {
  asOf: string; start: string; end: string; timeZone: "UTC";
  firstMeasured: string | null; detailedSince: string | null; retentionDays: number;
  state: "ready" | "no_calls" | "no_matches" | "usage_disabled" | "unavailable";
  aiEnabled: boolean; usageEnabled: boolean; configuredServices: ActivityService[];
  totals: ActivityMetrics; services: (ActivityService & ActivityMetrics)[];
  purposes: ({ feature: string; label: string } & ActivityMetrics)[];
  trend: ({ day: string } & ActivityMetrics)[]; groups: ActivityGroup[];
  facets: { services: ActivityService[]; purposes: { id: string; label: string }[]; models: string[]; outcomes: { id: string; label: string }[] };
  work: { arrivals: number; completed: number; failed: number; cached: number; skipped: number; expired: number; retries: number; fallbacks: number };
  coverage: { legacyAttempts: number; detailedAttempts: number; recordingDegradedSince: string | null; missing: string[] };
}
export interface LiveActivity {
  asOf: string; windowStart: string; windowSeconds: number; windowComplete: boolean;
  state: string; label: string; message: string; nextCheck: string; rule: string;
  aiEnabled: boolean; usageEnabled: boolean;
  waiting: number; running: number; oldestWaitingSeconds: number | null;
  arrivals: number; usefulCompletions: number; failed: number; expired: number;
  rateLimited: number; timeouts: number; waitingTimeouts: number;
  inventory: { waiting: number; running: number; oldestWaitingSeconds: number | null; enabled: boolean };
  interactive: { waiting: number; running: number; oldestWaitingSeconds: number | null };
  patchInvestigations: { running: number; oldestRunningSeconds: number | null; coverage: "partial" };
  coverage: { detailedSince: string | null; recordingDegradedSince: string | null; missing: string[] };
}

export const activityPath = "/settings/ai/activity";
export const filterKeys = ["service", "provider", "purpose", "model", "outcome"] as const;
export function utcDay(offset = 0, now = new Date()) {
  const date = new Date(now); date.setUTCDate(date.getUTCDate() + offset);
  return date.toISOString().slice(0, 10);
}
export function activityQuery(params: URLSearchParams) {
  const query = new URLSearchParams({ start: params.get("start") ?? utcDay(-29), end: params.get("end") ?? utcDay() });
  for (const key of filterKeys) if (params.get(key)) query.set(key, params.get(key)!);
  return query;
}
export function rangeError(start: string, end: string): string | null {
  const valid = (day: string) => /^\d{4}-\d{2}-\d{2}$/.test(day) && Number.isFinite(Date.parse(day)) && new Date(day).toISOString().slice(0, 10) === day;
  if (!valid(start) || !valid(end)) return "Choose a valid start and end date (UTC).";
  const days = (Date.parse(end) - Date.parse(start)) / 86400000 + 1;
  if (days < 1 || days > 90) return "Choose an inclusive range of 1–90 days. The end must be on or after the start.";
  if (end > utcDay()) return "The end date cannot be in the future (UTC).";
  return null;
}
export function readFailure(error: unknown, live: boolean) {
  if (error instanceof ApiError && error.status === 403) return "You do not have permission to read AI Activity. Ask an administrator for system read access.";
  if (error instanceof ApiError && error.status === 422) return "AI Activity could not read these filters. Check the date range and selected values, then retry.";
  return `${live ? "Live workload" : "AI history"} could not be read. Check connectivity and retry; this does not mean there were no calls.`;
}
export const count = (value: number | null) => value === null ? "Unknown" : value.toLocaleString();
export const duration = (ms: number | null) => ms === null ? "Unknown" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toLocaleString(undefined, { maximumFractionDigits: 1 })} s`;
export const age = (seconds: number | null) => seconds === null ? "Unknown" : duration(seconds * 1000);
export const stamp = (value: string | null) => value ? new Date(value).toLocaleString() : "Not yet measured";
export function coverage(reports: number, attempts: number) { return `${count(reports)}/${count(attempts)} attempts measured`; }

const record = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const number = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0;
const nullableNumber = (value: unknown) => value === null || number(value);
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(item => typeof item === "string");
const timestamp = (value: unknown) => typeof value === "string" && Number.isFinite(Date.parse(value));
const nullableTimestamp = (value: unknown) => value === null || timestamp(value);
const numericMetrics = ["attempts", "answered", "failed", "dispatchReports", "usefulReports", "inputReports", "outputReports", "cacheReports", "waitReports", "requestReports", "totalReports", "providerReports"];
const optionalMetrics = ["dispatches", "usefulResults", "unusable", "waitingTimeouts", "retries", "fallbacks", "inputTokens", "outputTokens", "cachedTokens", "avgWaitMs", "avgRequestMs", "avgTotalMs", "avgProviderMs"];
const metrics = (value: unknown) => record(value) && numericMetrics.every(key => number(value[key])) && optionalMetrics.every(key => nullableNumber(value[key]));
const service = (value: unknown) => record(value) && ["serviceId", "serviceLabel", "serviceKind", "provider"].every(key => typeof value[key] === "string");
const choices = (value: unknown) => Array.isArray(value) && value.every(item => record(item) && typeof item.id === "string" && typeof item.label === "string");
const listOf = (value: unknown, valid: (value: unknown) => boolean) => Array.isArray(value) && value.every(valid);

/** A proxy returning JSON or an old server is an unreadable reading, never a zero. */
export function isActivityReport(value: unknown): value is ActivityReport {
  if (!record(value) || !record(value.facets) || !record(value.coverage) || !record(value.work)) return false;
  const work = value.work;
  return timestamp(value.asOf) && timestamp(value.start) && timestamp(value.end) && value.timeZone === "UTC"
    && nullableTimestamp(value.firstMeasured) && nullableTimestamp(value.detailedSince) && number(value.retentionDays)
    && ["ready", "no_calls", "no_matches", "usage_disabled", "unavailable"].includes(String(value.state))
    && typeof value.aiEnabled === "boolean" && typeof value.usageEnabled === "boolean" && metrics(value.totals)
    && listOf(value.configuredServices, service) && listOf(value.services, item => service(item) && metrics(item))
    && listOf(value.purposes, item => record(item) && typeof item.feature === "string" && typeof item.label === "string" && metrics(item))
    && listOf(value.trend, item => record(item) && timestamp(item.day) && metrics(item))
    && listOf(value.groups, item => record(item) && service(item) && metrics(item) && typeof item.legacy === "boolean"
      && ["feature", "purpose", "requested", "reported", "outcome"].every(key => typeof item[key] === "string"))
    && listOf(value.facets.services, service) && choices(value.facets.purposes) && choices(value.facets.outcomes) && strings(value.facets.models)
    && ["arrivals", "completed", "failed", "cached", "skipped", "expired", "retries", "fallbacks"].every(key => number(work[key]))
    && number(value.coverage.legacyAttempts) && number(value.coverage.detailedAttempts)
    && nullableTimestamp(value.coverage.recordingDegradedSince) && strings(value.coverage.missing);
}
export function isLiveActivity(value: unknown): value is LiveActivity {
  if (!record(value) || !record(value.coverage) || !record(value.inventory) || !record(value.interactive) || !record(value.patchInvestigations)) return false;
  return timestamp(value.asOf) && timestamp(value.windowStart) && number(value.windowSeconds) && typeof value.windowComplete === "boolean"
    && ["usage_disabled", "disabled", "not_running", "no_provider", "unavailable", "observing", "idle", "keeping_up", "backlog_growing", "waiting_too_long", "rate_limited", "stalled", "failures", "expired"].includes(String(value.state))
    && ["label", "message", "nextCheck", "rule"].every(key => typeof value[key] === "string")
    && typeof value.aiEnabled === "boolean" && typeof value.usageEnabled === "boolean"
    && ["waiting", "running", "arrivals", "usefulCompletions", "failed", "expired", "rateLimited", "timeouts", "waitingTimeouts"].every(key => number(value[key]))
    && nullableNumber(value.oldestWaitingSeconds)
    && [value.inventory, value.interactive].every(item => number(item.waiting) && number(item.running) && nullableNumber(item.oldestWaitingSeconds))
    && typeof value.inventory.enabled === "boolean" && number(value.patchInvestigations.running)
    && nullableNumber(value.patchInvestigations.oldestRunningSeconds) && value.patchInvestigations.coverage === "partial"
    && nullableTimestamp(value.coverage.detailedSince) && nullableTimestamp(value.coverage.recordingDegradedSince) && strings(value.coverage.missing);
}
export async function getActivity(query: string, signal: AbortSignal) {
  const body = await apiRequest<unknown>(`/system/ai/activity?${query}`, { signal });
  if (!isActivityReport(body)) throw new Error("Unreadable AI Activity response");
  return body;
}
export async function getLiveActivity(signal: AbortSignal) {
  const body = await apiRequest<unknown>("/system/ai/activity/live", { signal });
  if (!isLiveActivity(body)) throw new Error("Unreadable AI workload response");
  return body;
}
