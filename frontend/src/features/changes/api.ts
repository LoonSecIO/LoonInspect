import { apiRequest } from "@/config/api";
import type {
  ChangeFilters,
  ChangePolicy,
  ChangePolicyUpdate,
  DeviceChangeListResponse
} from "@/features/changes/types";

export function listChanges(filters: ChangeFilters): Promise<DeviceChangeListResponse> {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.artifact) params.set("artifact", filters.artifact);
  if (filters.level) params.set("level", filters.level);
  if (filters.minLevel) params.set("minLevel", filters.minLevel);
  if (filters.section) params.set("section", filters.section);
  if (filters.since) params.set("since", filters.since);
  if (filters.connectionId !== undefined) params.set("connectionId", String(filters.connectionId));
  if (filters.subjectId) params.set("subjectId", filters.subjectId);
  params.set("page", String(filters.page ?? 1));
  params.set("pageSize", String(filters.pageSize ?? 50));
  return apiRequest<DeviceChangeListResponse>(`/changes?${params.toString()}`);
}

export function getChangePolicy(): Promise<ChangePolicy> {
  return apiRequest<ChangePolicy>("/changes/policy");
}

export function putChangePolicy(update: ChangePolicyUpdate): Promise<ChangePolicy> {
  return apiRequest<ChangePolicy>("/changes/policy", { method: "PUT", json: update });
}
