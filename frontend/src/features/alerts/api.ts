import { apiRequest } from "@/config/api";
import type { AlertFilters, AlertListResponse } from "@/features/alerts/types";

/**
 * The latches, oldest first.
 *
 * Oldest first is the endpoint's own ordering and not an accident (`backend/app/api/
 * alerts.py`): this is a list of things that are still true, so the row that has been
 * true longest is the one that has gone unanswered longest — which is exactly how Needs
 * Attention ranks within a level. That agreement is what makes a bounded page the *right*
 * page rather than an arbitrary slice.
 */
export function listAlerts(filters: AlertFilters = {}): Promise<AlertListResponse> {
  const params = new URLSearchParams();
  if (filters.open !== undefined) params.set("open", String(filters.open));
  if (filters.kind) params.set("kind", filters.kind);
  params.set("page", String(filters.page ?? 1));
  params.set("pageSize", String(filters.pageSize ?? 50));
  return apiRequest<AlertListResponse>(`/alerts?${params.toString()}`);
}
