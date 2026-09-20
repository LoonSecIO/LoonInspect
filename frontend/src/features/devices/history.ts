import { apiRequest } from "@/config/api";

export interface HistoryPoint {
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
