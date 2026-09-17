import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { ApiError } from "@/config/api";
import { Button } from "@/components/ui/button";
import { FilterBar } from "@/features/devices/FilterBar";
import { lookupCatalog } from "@/features/catalog/api";
import { listDevices } from "@/features/devices/api";
import { departureState, includeDepartedFrom } from "@/features/devices/departure";
import type { Device, DeviceFilters, VersionOperator } from "@/features/devices/types";
import { useLocale } from "@/i18n/LocaleContext";

/** `?vuln=` narrowed rather than cast (#535): the two values the endpoint accepts, and
 *  nothing else. A cast seats a third value in a typed field, where the chip that clears it
 *  would have to print one of the two labels over a value that is neither — and sends it to
 *  a `422` this page has no words for. Something nobody can select and nobody can name is
 *  not a filter, so the list answers unfiltered, which is what the unpressed chips say. */
function vulnFilterFrom(params: URLSearchParams): DeviceFilters["vuln"] {
  const value = params.get("vuln");
  return value === "findings" || value === "kev" ? value : undefined;
}

function filtersFromSearchParams(params: URLSearchParams): DeviceFilters {
  const managed = params.get("managed");
  const supervised = params.get("supervised");

  return {
    q: params.get("q") ?? undefined,
    osVersion: params.get("osVersion") ?? undefined,
    osVersionOperator: (params.get("osVersionOperator") as VersionOperator | null) ?? undefined,
    site: params.get("site") ?? undefined,
    building: params.get("building") ?? undefined,
    department: params.get("department") ?? undefined,
    managed: managed === null ? undefined : managed === "true",
    supervised: supervised === null ? undefined : supervised === "true",
    lastCheckInBefore: params.get("lastCheckInBefore") ?? undefined,
    lastCheckInAfter: params.get("lastCheckInAfter") ?? undefined,
    appHash: params.get("appHash") ?? undefined,
    versionHash: params.get("versionHash") ?? undefined,
    includeDeparted: includeDepartedFrom(params),
    vuln: vulnFilterFrom(params),
    page: params.get("page") ? Number(params.get("page")) : 1
  };
}

function searchParamsFromFilters(filters: DeviceFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.osVersion) {
    params.set("osVersion", filters.osVersion);
    params.set("osVersionOperator", filters.osVersionOperator ?? "eq");
  }
  if (filters.site) params.set("site", filters.site);
  if (filters.building) params.set("building", filters.building);
  if (filters.department) params.set("department", filters.department);
  if (filters.managed !== undefined) params.set("managed", String(filters.managed));
  if (filters.supervised !== undefined) params.set("supervised", String(filters.supervised));
  // Carried through paging too, or page 2 of a saved search would silently be the fleet.
  if (filters.lastCheckInBefore) params.set("lastCheckInBefore", filters.lastCheckInBefore);
  if (filters.lastCheckInAfter) params.set("lastCheckInAfter", filters.lastCheckInAfter);
  // The application record page's carrier links (#299). Omitted here, page 2 of "who
  // runs this build" would silently be the whole fleet — #107's shape again.
  if (filters.appHash) params.set("appHash", filters.appHash);
  if (filters.versionHash) params.set("versionHash", filters.versionHash);
  if (filters.includeDeparted) params.set("includeDeparted", "true"); // shared links carry it (#475)
  if (filters.vuln) params.set("vuln", filters.vuln); // the two chips are the URL (#535)
  if (filters.page && filters.page !== 1) params.set("page", String(filters.page));
  return params;
}

export function DevicesPage() {
  const { t } = useLocale();
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => filtersFromSearchParams(searchParams), [searchParams]);

  const [devices, setDevices] = useState<Device[]>([]);
  const [total, setTotal] = useState(0);
  // The stamp the counts came from (#535). Null is "nothing is answering", which is why
  // there is no vulnerability column and no chips rather than a column full of zeros.
  const [corpusAsOf, setCorpusAsOf] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const pageSize = 50;

  // A new set of filters is a new question, and the table has to say it is asking rather
  // than leave the last answer standing as though it were this one. Adjusted here, during
  // the render that moved the filters (React's own "adjusting state when a prop changes",
  // the move the Changes page's filter boxes already make), rather than from the effect
  // below: from an effect it lands a render late, so the old rows paint one frame looking
  // settled. Keyed on everything the effect re-runs for — the locale beside the filters —
  // because a guard on less than that is a re-fetch that clears nothing: switch language
  // after a failed load and the new rows arrive under the old failure's line (#150 in
  // reverse, success reading as failure).
  const [asked, setAsked] = useState({ filters, t });
  if (asked.filters !== filters || asked.t !== t) {
    setAsked({ filters, t });
    setLoading(true);
    setError(null);
  }

  useEffect(() => {
    let cancelled = false;

    // Debounced so typing in the filter doesn't fire a query per keystroke.
    const handle = setTimeout(() => {
      listDevices({ ...filters, pageSize })
        .then((response) => {
          if (cancelled) return;
          setDevices(response.items);
          setTotal(response.total);
          setCorpusAsOf(response.corpusAsOf);
        })
        .catch((caught: unknown) => {
          if (cancelled) return;
          // A `vuln` filter on a tenant nothing answers for is refused rather than answered
          // with an empty page (#535), and the refusal names both of its causes. Printing
          // "Could not load devices" over it would throw those words away — a pasted link
          // is exactly how someone arrives here.
          setError(caught instanceof ApiError && caught.status === 409 && caught.detail ? caught.detail : t.devices.errorLoading);
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 250);

    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [filters, t]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = filters.page ?? 1;
  // Eight, or nine where a corpus answers: the empty and error rows span the table, and a
  // hard-coded 8 beside a conditional column is how one of them stops spanning it.
  const columns = corpusAsOf === null ? 8 : 9;

  function goToPage(next: number) {
    setSearchParams(searchParamsFromFilters({ ...filters, page: next }));
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.devices.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.devices.title}</h1>
      </div>

      <FilterBar
        filters={filters}
        corpusAsOf={corpusAsOf}
        onChange={(next) => setSearchParams(searchParamsFromFilters(next), { replace: true })}
      />
      {/* A saved search the filter bar has no control for (#109's stale tile) shows as a
          removable chip, so a filter the page applies is never one the page hides. */}
      {filters.lastCheckInBefore && (
        <button
          type="button"
          className="inline-flex items-center gap-2 rounded-full border bg-muted px-3 py-1 text-xs"
          onClick={() =>
            setSearchParams(searchParamsFromFilters({ ...filters, lastCheckInBefore: undefined, page: 1 }), {
              replace: true
            })
          }
        >
          {t.devices.staleChip(new Date(filters.lastCheckInBefore).toLocaleString())}
          <span aria-hidden="true">×</span>
          <span className="sr-only">{t.devices.clearFilter}</span>
        </button>
      )}
      {filters.appHash && (
        <CarrierChip
          appHash={filters.appHash}
          versionHash={filters.versionHash}
          onClear={() =>
            setSearchParams(searchParamsFromFilters({ ...filters, appHash: undefined, versionHash: undefined, page: 1 }), {
              replace: true
            })
          }
        />
      )}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.devices.tableHostname}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableSerial}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableOsVersion}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableSite}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableDepartment}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableManaged}</th>
              <th className="px-4 py-2 font-medium">{t.devices.tableSupervised}</th>
              {/* No corpus, no column (#535): there is nothing to put in it, and a `0` per
                  row would be a clean bill nobody looked for. */}
              {corpusAsOf !== null && <th className="px-4 py-2 font-medium">{t.devices.tableAppsWithFindings}</th>}
              <th className="px-4 py-2 font-medium">{t.devices.tableLastCheckIn}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={columns}>
                  {t.devices.loading}
                </td>
              </tr>
            )}
            {!loading && error && (
              <tr>
                <td className="px-4 py-4 text-destructive" colSpan={columns}>
                  {error}
                </td>
              </tr>
            )}
            {!loading && !error && devices.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={columns}>
                  {t.devices.empty}
                </td>
              </tr>
            )}
            {/* Not under a refusal (#535). A `vuln` filter nothing can answer is a 409, and
                the last page's Macs left standing beneath that sentence would read as the
                answer to the question the server just declined to answer. */}
            {!error && devices.map((device) => (
              <tr key={device.id} className="border-b last:border-0">
                <td className="px-4 py-2">
                  <Link to={`/devices/${device.id}`} className="font-medium hover:underline">
                    {device.hostname}
                  </Link>
                  {device.departedAt && (
                    <span className="ml-2 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs text-muted-foreground">
                      {departureState(device.departedAt, new Date()) === "left" ? t.devices.leftChip : t.devices.tailChip}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2">{device.serialNumber}</td>
                <td className="px-4 py-2">{device.osVersion ?? "—"}</td>
                <td className="px-4 py-2">{device.site ?? "—"}</td>
                <td className="px-4 py-2">{device.department ?? "—"}</td>
                <td className="px-4 py-2">
                  {device.managed === null ? "—" : device.managed ? t.devices.yes : t.devices.no}
                </td>
                <td className="px-4 py-2">
                  {device.supervised === null ? "—" : device.supervised ? t.devices.yes : t.devices.no}
                </td>
                {corpusAsOf !== null && (
                  <td className="px-4 py-2 whitespace-nowrap">
                    {device.vulnApps ? (
                      <>
                        {/* The unknowns are printed beside the count, always: a Mac whose
                            apps are all outside the corpus reads "0 · 12 outside", which is
                            not a clean bill and does not look like one (§4a). */}
                        <span className="tabular-nums">
                          {t.devices.appsWithFindings(device.vulnApps.withFindings, device.vulnApps.onKev)}
                        </span>{" "}
                        <span className="text-xs text-muted-foreground">
                          {t.devices.appsOutsideCorpus(device.vulnApps.outsideCorpus)}
                        </span>
                      </>
                    ) : (
                      <span className="text-xs text-muted-foreground">{t.devices.noAppsRead}</span>
                    )}
                  </td>
                )}
                <td className="px-4 py-2">
                  {device.lastCheckIn ? new Date(device.lastCheckIn).toLocaleString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Not under a refusal either (#535), for the reason the rows are not. `total` is
          `0` until a response sets it, so a refused `vuln=kev` would print "0 devices
          total" one line under the sentence refusing to answer that question — §4a's
          reading printed as a number, on the screen built to prevent it — and after a load
          that worked it would print the previous question's total instead, which is worse
          for being plausible. The pager goes with it: `totalPages` counts the same absent
          answer, and there are no rows to page through. */}
      {!error && (
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          {/* The count says which population it counts (#232): v0's devices are
              computers, full stop, so the total is named next to what it is a total
              of rather than left for someone to notice a Mac-sized number against an
              iPad-sized fleet. */}
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span>{t.devices.total(total)}</span>
            <span className="text-xs">{t.common.computersOnlyScope}</span>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => goToPage(page - 1)}>
              {t.devices.previous}
            </Button>
            <span className="self-center">{t.devices.pageOf(page, totalPages)}</span>
            <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => goToPage(page + 1)}>
              {t.devices.next}
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}

/**
 * "Running {app}" — the application record page's carrier link, echoed as a removable chip
 * (#299). The hash in the URL is the record's address, not a name a person can read, so the
 * chip asks the catalog lookup for the name behind it: by build when `versionHash` is set,
 * else the app's newest version seen. Until it answers, or if it cannot, the chip still
 * says a filter is on.
 */
function CarrierChip({ appHash, versionHash, onClear }: { appHash: string; versionHash?: string; onClear: () => void }) {
  const { t } = useLocale();
  const key = `${appHash}:${versionHash ?? ""}`;
  const [named, setNamed] = useState<{ key: string; label: string | null } | null>(null);

  useEffect(() => {
    let cancelled = false;
    lookupCatalog({ appHash, versionHash })
      .then((answers) => {
        if (cancelled) return;
        const tenant = answers[0]?.tenant ?? null;
        setNamed({ key, label: tenant ? (versionHash ? `${tenant.name} ${tenant.version}` : tenant.name) : null });
      })
      .catch(() => {
        if (!cancelled) setNamed({ key, label: null });
      });
    return () => {
      cancelled = true;
    };
  }, [appHash, versionHash, key]);

  const label = named && named.key === key ? named.label : null;
  return (
    <button type="button" className="inline-flex items-center gap-2 rounded-full border bg-muted px-3 py-1 text-xs" onClick={onClear}>
      {label ? t.devices.carrierChip(label) : t.devices.carrierChipUnnamed}
      <span aria-hidden="true">×</span>
      <span className="sr-only">{t.devices.clearFilter}</span>
    </button>
  );
}
