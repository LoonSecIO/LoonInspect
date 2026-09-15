import { apiRequest } from "@/config/api";
import type {
  ChangeFilters,
  ChangePolicy,
  ChangePolicyUpdate,
  DeviceChangeListResponse,
  PromptRequest,
  PromptResult,
  PromptStatus
} from "@/features/changes/types";

export function listChanges(filters: ChangeFilters): Promise<DeviceChangeListResponse> {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.artifact) params.set("artifact", filters.artifact);
  if (filters.level) params.set("level", filters.level);
  if (filters.minLevel) params.set("minLevel", filters.minLevel);
  if (filters.section) params.set("section", filters.section);
  if (filters.change) params.set("change", filters.change);
  if (filters.since) params.set("since", filters.since);
  if (filters.connectionId !== undefined) params.set("connectionId", String(filters.connectionId));
  if (filters.subjectId) params.set("subjectId", filters.subjectId);
  if (filters.subjectKind) params.set("subjectKind", filters.subjectKind);
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

/** Whether the Prompt bar shows, and which saved providers it may use. Readable with
 *  device:read alone, because viewers use the bar and cannot read Settings › AI. */
export function getPromptStatus(): Promise<PromptStatus> {
  return apiRequest<PromptStatus>("/changes/prompt");
}

/** The question goes to this server, which sends it — and only it — to the saved
 *  provider. What comes back is filter settings and a count Postgres wrote. `signal`
 *  lets the bar drop a reply nobody is waiting for any more. */
export function askPrompt(body: PromptRequest, signal?: AbortSignal): Promise<PromptResult> {
  return apiRequest<PromptResult>("/changes/prompt", { method: "POST", json: body, signal });
}
