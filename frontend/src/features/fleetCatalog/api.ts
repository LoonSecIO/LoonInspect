import { apiRequest } from "@/config/api";
import type { MigrationDetail, MigrationPortfolio } from "@/features/fleetCatalog/migrationTypes";
import type { FleetCatalog, FleetCatalogState, FleetTitleHistory } from "@/features/fleetCatalog/types";

// A few hundred titles at most, so the page reads them in one request and searches and
// sorts what it holds, as the Jamf Patch tab does.
const ALL_TITLES_PAGE_SIZE = 5000;

/** Fleet's titles beside this organization's Macs. Reads what the instance holds; asks GitHub nothing. */
export function getFleetCatalog(installedOnly: boolean): Promise<FleetCatalog> {
  const params = new URLSearchParams({ installedOnly: String(installedOnly), pageSize: String(ALL_TITLES_PAGE_SIZE) });
  return apiRequest<FleetCatalog>(`/fleet-catalog?${params.toString()}`);
}

/** The migration answers' query: the page URL's `deviceScope`, the filter Installed Apps and Patch Plans
 *  share, or "" without one, which the server reads as every Mac, as it reads `defaultScope`. Never
 *  parsed: `readScope` reads a malformed filter as null, and dropping that would widen the request to
 *  every Mac. The server refuses a malformed one with its own sentence. */
export function fleetScopeQuery(params: URLSearchParams): string {
  const scope = params.get("deviceScope");
  return scope === null ? "" : new URLSearchParams({ deviceScope: scope }).toString();
}

/** The apps on the Macs `scope` (`fleetScopeQuery`) selects, against Fleet's and Jamf's catalogs. */
export function getMigrationReport(scope: string, signal?: AbortSignal): Promise<MigrationPortfolio> {
  return apiRequest<MigrationPortfolio>(`/fleet-catalog/migration${scope ? `?${scope}` : ""}`, { signal });
}

/** One installed app (`apps`, by app hash) or Fleet title (`titles`, by slug) on the Macs `scope` selects,
 *  against `targetVersion`, else Fleet's latest. */
export function getFleetDetail(
  kind: "apps" | "titles", id: string, scope: string, targetVersion?: string, signal?: AbortSignal
): Promise<MigrationDetail> {
  const params = new URLSearchParams(scope);
  if (targetVersion) params.set("targetVersion", targetVersion);
  const query = params.toString();
  return apiRequest<MigrationDetail>(`/fleet-catalog/migration/${kind}/${encodeURIComponent(id)}${query ? `?${query}` : ""}`, { signal });
}

/** Check Fleet's catalog now. patch:catalog-sync; a refusal is a 409 whose detail is the sentence to show. */
export function refreshFleetCatalog(): Promise<FleetCatalogState> {
  return apiRequest<FleetCatalogState>("/fleet-catalog/refresh", { method: "POST" });
}

/** One title's version history as the instance holds it (#838). Asks GitHub nothing. */
export function getTitleHistory(slug: string): Promise<FleetTitleHistory> {
  return apiRequest<FleetTitleHistory>(`/fleet-catalog/${encodeURIComponent(slug)}/history`);
}

/** Read one title's whole history from Fleet's commits now. patch:catalog-sync; a refusal is a 409
 *  whose detail is the sentence to show. */
export function readTitleHistory(slug: string): Promise<FleetTitleHistory> {
  return apiRequest<FleetTitleHistory>(`/fleet-catalog/${encodeURIComponent(slug)}/history`, { method: "POST" });
}
