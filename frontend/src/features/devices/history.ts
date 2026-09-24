import { apiRequest } from "@/config/api";

export interface HistoryPoint {
  kind?: "inventory" | "assessment";
  id: string;
  observedAt: string;
  collectedAt: string;
}
export interface HistoryPage {
  items: HistoryPoint[];
  hasMore: boolean;
  page: number;
}
export interface HistoryChoice {
  key: string;
  label: string;
  section: string;
  field: string;
  enabled: boolean;
  kind?: string;
  name?: string;
  identity?: Record<string, unknown>;
  preview?: Record<string, unknown>;
  sample?: HistoryValue;
}
export interface HistoryValue {
  state: string;
  value: unknown;
}
export interface HistoryDetail extends HistoryPoint {
  spanId: string;
  values: (HistoryChoice & HistoryValue & { before: HistoryValue | null })[];
  choices: HistoryChoice[];
  baseline: boolean;
  assessment: {
    total: number | null;
    critical: number | null;
    covered: number;
    outside: number;
    corpus: string[];
    vulnerabilityEvidence?: {
      releaseDigest: string;
      corpusAsOf: string;
      builds: {
        keyFull: string;
        name: string;
        version: string;
        assessment: "covered" | "unknown_app";
        counts: { total: number } | null;
        ids: string[] | null;
        idsTruncated: boolean | null;
        evaluatedAt: string | null;
      }[];
    };
  } | null;
  summary: {
    status: string;
    text: string | null;
    provider: string | null;
    reason: string | null;
  };
}
export const loadHistory = (device: number, page: number) =>
  apiRequest<HistoryPage>(`/devices/${device}/history?page=${page}`);
export const loadHistoryPoint = (device: number, point: string) =>
  apiRequest<HistoryDetail>(
    `/devices/${device}/history/point?${new URLSearchParams({ point })}`,
  );
export const saveHistorySlots = (
  device: number,
  point: string,
  slots: string[],
) =>
  apiRequest(`/devices/${device}/history/preferences`, {
    method: "PUT",
    json: { point, slots },
  });

/** The date under a timeline dot: when LoonInspect recorded the state, for every kind of point.
 *  The Mac's own report time (`observedAt`) stays in the dot's tooltip and the state's header.
 *  It does not move when Jamf's record changes without a new inventory report, so a line
 *  labelled by it repeats itself and runs backwards at an assessment point (#645). */
export function dotLabel(point: Pick<HistoryPoint, "collectedAt">, locale: string): string {
  return new Date(point.collectedAt).toLocaleDateString(locale, { month: "short", day: "numeric" });
}

export function changedValue(
  value: HistoryValue,
  before: HistoryValue | null,
): boolean {
  return (
    before?.state === "present" &&
    value.state === "present" &&
    JSON.stringify(value.value) !== JSON.stringify(before.value)
  );
}
export function formatHistoryValue(
  value: HistoryValue,
  states: Record<string, string>,
  yes: string,
  no: string,
): string {
  if (value.state !== "present")
    return states[value.state] ?? states.not_observed;
  if (typeof value.value === "boolean") return value.value ? yes : no;
  if (typeof value.value === "object")
    return Array.isArray(value.value)
      ? value.value.map(String).join(", ")
      : JSON.stringify(value.value);
  return String(value.value);
}
