import { apiRequest } from "@/config/api";

export interface SummaryOptions {
  enabled: boolean;
  provider: string;
  preprompt: string;
  intervalSeconds: number;
}
export interface SummaryMetrics {
  enabled: boolean;
  provider: string;
  counts: Record<string, number>;
  attempts: number;
  overloadJobs: number;
  averageLatencyMs: number | null;
  dropRate: number | null;
  successRate: number | null;
  oldestQueuedAt: string | null;
  asOf: string;
  reasons: { reason: string; count: number; nextCheck: string }[];
}
const path = "/inventory-summaries";
export const loadSummarySettings = () =>
  apiRequest<SummaryOptions>(`${path}/settings`);
export const saveSummarySettings = (value: SummaryOptions) =>
  apiRequest<SummaryOptions>(`${path}/settings`, {
    method: "PUT",
    json: value,
  });
export const loadSummaryMetrics = () =>
  apiRequest<SummaryMetrics>(`${path}/metrics`);
