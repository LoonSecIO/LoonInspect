import { apiRequest } from "@/config/api";

export interface UpdateStatusResponse {
  enabled: boolean;
  currentVersion: string;
  /** null is "unknown" (disabled, dev build, or provider unreachable) — render
   *  nothing. false is "checked and current". */
  updateAvailable: boolean | null;
  latestSha: string | null;
  checkedAt: string | null;
}

export function getUpdateStatus(): Promise<UpdateStatusResponse> {
  return apiRequest<UpdateStatusResponse>("/system/update-status");
}
