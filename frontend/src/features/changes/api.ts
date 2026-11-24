import { apiRequest } from "@/config/api";
import { paramsFromFilters } from "@/features/changes/filters";
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
  const params = paramsFromFilters(filters);
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
