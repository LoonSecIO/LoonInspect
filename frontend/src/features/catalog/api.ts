import { apiRequest } from "@/config/api";
import type {
  CatalogBand,
  CatalogJamfFilter,
  CatalogListResponse,
  CatalogLookup,
  CatalogOrder,
  CatalogVulnFilter
} from "@/features/catalog/types";

// Search, sort and filter happen client-side over the tenant's catalog (distinct apps, not
// installs — a few thousand rows at most), so this pulls everything in one request.
const ALL_ROWS_PAGE_SIZE = 5000;

export interface CatalogQuery {
  jamf?: CatalogJamfFilter;
  installedOnly?: boolean;
  appHash?: string;
  pageSize?: number;
  /** The server's own search over name, bundle id and version — not the Catalog tab's
   *  client-side filter, because this list is paged and filtered server-side (#529). */
  q?: string;
  vuln?: CatalogVulnFilter;
  band?: CatalogBand;
  order?: CatalogOrder;
  page?: number;
}

export function listCatalog(params: CatalogQuery = {}): Promise<CatalogListResponse> {
  const query = new URLSearchParams({ pageSize: String(params.pageSize ?? ALL_ROWS_PAGE_SIZE) });
  if (params.jamf) query.set("jamf", params.jamf);
  if (params.installedOnly !== undefined) query.set("installedOnly", String(params.installedOnly));
  if (params.q) query.set("q", params.q);
  // Omitted rather than sent as "all": the unfiltered list keeps the Catalog tab's own
  // order, and a vulnerability filter on a tenant nothing answers for is a 409 (§8).
  if (params.vuln && params.vuln !== "all") query.set("vuln", params.vuln);
  if (params.band) query.set("band", params.band);
  if (params.order) query.set("order", params.order);
  if (params.page) query.set("page", String(params.page));
  // One application's rows, with the device counts scoped inside the join and no summary (#299).
  if (params.appHash) query.set("appHash", params.appHash);
  return apiRequest<CatalogListResponse>(`/catalog?${query.toString()}`);
}

/** The name behind a hash, for a chip (#299): by build when `versionHash` is given, else
 *  the app's newest version seen. */
export function lookupCatalog(params: { appHash?: string; versionHash?: string }): Promise<CatalogLookup[]> {
  const query = new URLSearchParams();
  if (params.versionHash) query.set("versionHash", params.versionHash);
  else if (params.appHash) query.set("appHash", params.appHash);
  return apiRequest<CatalogLookup[]>(`/catalog/lookup?${query.toString()}`);
}
