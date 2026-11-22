import { apiRequest } from "@/config/api";
import type { MigrationDetail } from "./migrationTypes";

export function fleetDetailScope(search: URLSearchParams): string {
  const scope = new URLSearchParams();
  for (const key of ["connectionId", "clock", "days"]) {
    const value = search.get(key);
    if (value) scope.set(key, value);
  }
  return scope.toString();
}

export function getFleetDetail(
  kind: "apps" | "titles",
  id: string,
  scope: string,
  targetVersion?: string
): Promise<MigrationDetail> {
  const params = new URLSearchParams(scope);
  if (targetVersion) params.set("targetVersion", targetVersion);
  const query = params.toString();
  return apiRequest<MigrationDetail>(`/fleet-catalog/migration/${kind}/${encodeURIComponent(id)}${query ? `?${query}` : ""}`);
}
