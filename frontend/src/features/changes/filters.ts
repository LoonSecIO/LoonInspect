/** One URL vocabulary for the page, shared links and the feed request. */
import { CHANGE_KINDS } from "@/features/changes/render";
import { HIDDEN_KEYS, type ChangeFilters, type ChangeKind, type ChangeLevel } from "@/features/changes/types";

export const asChange = (value: string | null): ChangeKind | undefined => CHANGE_KINDS.find(kind => kind === value);
const asLevel = (value: string | null): ChangeLevel | undefined =>
  value === "high" || value === "normal" || value === "low" ? value : undefined;
const TEXT_KEYS = ["q", "artifact", "section", "field", "changedTo", "since", "until", "subjectId", "subjectKind", ...HIDDEN_KEYS] as const;

export function filtersFromParams(params: URLSearchParams): ChangeFilters {
  return {
    ...Object.fromEntries(TEXT_KEYS.map(key => [key, params.get(key) ?? undefined])),
    level: asLevel(params.get("level")), minLevel: asLevel(params.get("minLevel")), change: asChange(params.get("change")),
    connectionId: params.has("connectionId") ? Number(params.get("connectionId")) : undefined,
    page: params.has("page") ? Number(params.get("page")) : 1
  };
}

export function paramsFromFilters(filters: ChangeFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of [...TEXT_KEYS, "level", "minLevel", "change"] as const) {
    const value = filters[key];
    if (value !== undefined && (value !== "" || key === "changedTo")) params.set(key, value);
  }
  if (filters.connectionId !== undefined) params.set("connectionId", String(filters.connectionId));
  if (filters.page && filters.page !== 1) params.set("page", String(filters.page));
  return params;
}

/** Preserve milliseconds in shared bounds; inputs display the browser's local timezone. */
export function localTime(value: string | undefined): string {
  if (!value) return "";
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, -1) : "";
}

export function timeBound(draft: string, applied: string | undefined): string | undefined {
  // A repeated fall-back hour can name two instants. An unchanged input keeps the exact
  // shared instant, rather than choosing the browser's default occurrence again.
  if (applied && /(?:Z|[+-]\d\d:\d\d)$/i.test(applied) && localTime(applied) && draft === localTime(applied)) return applied;
  if (!draft) return undefined;
  const date = new Date(draft);
  if (!Number.isFinite(date.getTime()) || !/^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d{1,3})?)?$/.test(draft)) throw new Error("invalid time");
  const normalized = draft.length === 16 ? `${draft}:00.000` : draft.length === 19 ? `${draft}.000` : draft.padEnd(23, "0");
  if (localTime(date.toISOString()) !== normalized) throw new Error("nonexistent local time");
  return date.toISOString();
}
