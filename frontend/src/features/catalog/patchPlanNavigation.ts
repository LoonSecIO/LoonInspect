import type { ApplicationScope, RiskSeverity } from "@/features/devices/applicationsApi";
import type { PatchPlan } from "./patchPlanTypes";

export const installedAppsPath = "/devices/applications";
export const patchPlansPath = "/patch-plans";

export function applicationFilters(params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams();
  for (const key of ["deviceScope", "q", "severity", "hasKev"]) {
    for (const value of params.getAll(key)) next.append(key, value);
  }
  return next;
}

export function applicationScopeFromParams(params: URLSearchParams): ApplicationScope {
  const bands: RiskSeverity[] = ["critical", "high", "medium", "low"];
  return { q: params.get("q") ?? "", severities: bands.filter(band => params.getAll("severity").includes(band)), hasKev: params.get("hasKev") === "true" };
}

export function patchPlanHref(params: URLSearchParams, hashes?: string[]): string {
  const next = applicationFilters(params);
  if (hashes) [...new Set(hashes)].forEach(hash => next.append("appHash", hash));
  else if (params.get("plan")) next.set("plan", params.get("plan")!);
  return `${patchPlansPath}?${next}`;
}

export function planInventoryHref(plan: PatchPlan): string {
  const params = new URLSearchParams({ deviceScope: JSON.stringify(plan.snapshot.scope) });
  const scope = plan.snapshot.applicationScope;
  if (scope?.q) params.set("q", scope.q);
  scope?.severities.forEach(severity => params.append("severity", severity));
  if (scope?.hasKev) params.set("hasKev", "true");
  return `${installedAppsPath}?${params}`;
}
