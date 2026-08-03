import { apiRequest } from "@/config/api";
import type { FeatureFlag } from "@/features/settings/types";

export function listFeatureFlags(): Promise<FeatureFlag[]> {
  return apiRequest<FeatureFlag[]>("/feature-flags");
}

export function updateFeatureFlag(key: string, enabled: boolean): Promise<FeatureFlag> {
  return apiRequest<FeatureFlag>(`/feature-flags/${encodeURIComponent(key)}`, {
    method: "PATCH",
    json: { enabled }
  });
}
