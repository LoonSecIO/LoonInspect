import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { getFleetCatalog, refreshFleetCatalog } from "@/features/fleetCatalog/api";
import {
  emptyState,
  historyStatusOf,
  sortTitles,
  statusOf,
  titleMatches,
  type FleetSortKey,
  type SortDir
} from "@/features/fleetCatalog/catalogView";
import { FleetTitleHistory } from "@/features/fleetCatalog/FleetTitleHistory";
import type { FleetCatalog, FleetCatalogTitle } from "@/features/fleetCatalog/types";
import { useLocale } from "@/i18n/LocaleContext";

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

const LICENCE_URL = "https://github.com/fleetdm/fleet/blob/main/ee/LICENSE";
const SOURCE_URL = "https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/outputs/";
const COLUMNS = 6;

function when(value: string | null): string {
  return value === null ? "" : new Date(value).toLocaleString();
}

/**
 * Devices › Applications › Fleet catalog (#794): the Mac apps Fleet maintains, with Fleet's
 * latest version beside what this organization has installed.
 *
 * The route is behind `RequireFlag`, so this page is only drawn while the flag is on. It
 * reads what the instance holds and never makes the instance ask GitHub; Check now and a
 * title's Read history (#838) are the controls that do, and only for an account that may sync
 * a catalog. A title's row opens its version history.
 */
export function FleetCatalogPage() {
  const { t, locale } = useLocale();
  const canCheck = useHasPermission(PERMISSIONS.PATCH_CATALOG_SYNC);

  const [catalog, setCatalog] = useState<FleetCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState("");
  // Installed titles only, by default, as the Jamf Patch tab opens on titles with devices:
  // the question the tab answers first is "what do we have that Fleet tracks".
  const [installedOnly, setInstalledOnly] = useState(true);
  const [sortKey, setSortKey] = useState<FleetSortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  // The titles whose version history is open under their row.
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());

  function toggleHistory(slug: string) {
    setOpen((was) => {
      const next = new Set(was);
      if (next.has(slug)) next.delete(slug);
      else next.add(slug);
      return next;
    });
  }

  /** The last column: when the latest version arrived. The history's date when it has one (when
   *  Fleet's catalog took it), else the move this instance saw, else that there is neither yet. */
  function arrived(title: FleetCatalogTitle) {
    if (title.inCatalogSince !== null) {
      return (
        <span title={t.fleetCatalog.inCatalogSinceHint}>
          {title.versionBefore !== null
            ? t.fleetCatalog.movedFrom(when(title.inCatalogSince), title.versionBefore)
            : t.fleetCatalog.sinceFirstListed(when(title.inCatalogSince))}
        </span>
      );
    }
    if (title.versionChangedAt !== null) {
      return t.fleetCatalog.movedFrom(when(title.versionChangedAt), title.previousVersion ?? "");
    }
    return (
      <span
        className="text-muted-foreground"
        title={title.historyReadAt === null ? t.fleetCatalog.notMovedHint : t.fleetCatalog.notDatedHint}
      >
        {title.historyReadAt === null ? t.fleetCatalog.notMoved : t.fleetCatalog.notDated}
      </span>
    );
  }

  /** The one read of the list, held against the toggle (the server filters on it) and the
   *  dictionary (the failure line is written in it), so either one moving re-reads. `live`
   *  is how the effect drops a read a later one superseded (CONTRIBUTING.md, #479). */
  const load = useCallback(
    (live: () => boolean = () => true): Promise<void> =>
      getFleetCatalog(installedOnly)
        .then((response) => {
          if (live()) setCatalog(response);
        })
        .catch(() => {
          if (live()) setError(t.fleetCatalog.errorLoading);
        })
        .finally(() => {
          if (live()) setLoading(false);
        }),
    [installedOnly, t]
  );

  // Adjusted during the render that moved the inputs, keyed on the effect's whole
  // dependency array, so the previous answer never paints a frame looking settled.
  const [asked, setAsked] = useState({ load });
  if (asked.load !== load) {
    setAsked({ load });
    setLoading(true);
    setError(null);
  }

  useEffect(() => {
    let cancelled = false;
    void load(() => !cancelled);
    return () => {
      cancelled = true;
    };
  }, [load]);

  function handleCheckNow() {
    setChecking(true);
    setCheckError(null);
    refreshFleetCatalog()
      // The server's sentence when it sent one: the host that did not answer and what to
      // check. Else the page's own line, for a press that got no reason to show.
      .catch((caught: unknown) =>
        setCheckError(caught instanceof ApiError && caught.detail ? caught.detail : t.fleetCatalog.checkError)
      )
      // Read again either way: a failed check still wrote what it found.
      .then(() => {
        setLoading(true);
        setError(null);
        return load();
      })
      .finally(() => setChecking(false));
  }

  function handleSort(key: FleetSortKey) {
    if (key === sortKey) {
      setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "deviceCount" || key === "devicesBehind" || key === "versionChangedAt" ? "desc" : "asc");
    }
  }

  const visible = useMemo(
    () =>
      sortTitles(
        (catalog?.items ?? []).filter((title) => titleMatches(title, searchTerm)),
        sortKey,
        sortDir
      ),
    [catalog, searchTerm, sortKey, sortDir]
  );

  const empty = catalog === null ? null : emptyState(catalog, visible, { searching: searchTerm.trim() !== "", installedOnly });
  const emptyMessage = (() => {
    if (catalog === null) return null;
    switch (empty) {
      case "flagOff":
        return t.fleetCatalog.emptyFlagOff;
      case "neverChecked":
        return canCheck ? t.fleetCatalog.emptyNeverCheckedCanCheck : t.fleetCatalog.emptyNeverChecked;
      case "neverRead":
        return t.fleetCatalog.emptyNeverRead;
      case "noneInstalled":
        return t.fleetCatalog.emptyNoneInstalled(catalog.state?.appCount ?? 0);
      case "noMatchInstalled":
        return t.fleetCatalog.emptyNoMatchInstalled;
      case "noMatch":
        return t.fleetCatalog.emptyNoMatch;
      default:
        return null;
    }
  })();

  const state = catalog?.state ?? null;
  const status = statusOf(state);
  const historyStatus = historyStatusOf(state);

  function sortableHeader(key: FleetSortKey, label: string) {
    const indicator = key !== sortKey ? "" : sortDir === "asc" ? " ▲" : " ▼";
    return (
      <th className="cursor-pointer select-none px-4 py-2 font-medium hover:text-foreground" onClick={() => handleSort(key)}>
        {label}
        {indicator}
      </th>
    );
  }

  return (
    <section className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{t.fleetCatalog.eyebrow}</p>
          <h1 className="text-3xl font-bold tracking-tight">{t.fleetCatalog.title}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t.fleetCatalog.description}</p>
        </div>
        {canCheck && (
          <Button onClick={handleCheckNow} disabled={checking}>
            {checking ? t.fleetCatalog.checking : t.fleetCatalog.checkNow}
          </Button>
        )}
      </div>

      {/* What the last check found, in three states and their own words (rule 1): never
          asked, answered, and no answer. A failed check keeps the titles read before it, so
          its sentence sits above a table that is still true as of the date beside it. */}
      {catalog !== null && catalog.enabled && (
        <div
          role="status"
          className={`rounded-lg border px-4 py-3 text-sm ${status === "failed" ? "border-destructive/50" : "bg-muted/30"}`}
        >
          {status === "never" && <p className="text-muted-foreground">{t.fleetCatalog.statusNever}</p>}
          {status === "answered" && state !== null && (
            <p>
              {state.outcome === "unchanged"
                ? t.fleetCatalog.statusUnchanged(when(state.checkedAt), state.appCount, when(state.changedAt))
                : t.fleetCatalog.statusRead(when(state.checkedAt), state.appCount)}{" "}
              <span className="text-muted-foreground">{t.fleetCatalog.statusSource(catalog.source)}</span>
            </p>
          )}
          {status === "answered" && state?.detail && <p className="mt-1 text-muted-foreground">{state.detail}</p>}
          {status === "failed" && state !== null && (
            <>
              <p className="font-medium text-destructive">{t.fleetCatalog.statusFailed(when(state.checkedAt))}</p>
              {state.detail && <p className="mt-1">{state.detail}</p>}
              <p className="mt-1 text-muted-foreground">
                {state.appCount > 0
                  ? t.fleetCatalog.statusFailedHeld(state.appCount, when(state.changedAt))
                  : t.fleetCatalog.statusFailedNothingHeld}
              </p>
            </>
          )}
          {/* The version history (#838): how many installed titles it has reached, and, when
              the last read held back or failed, the server's sentence for why. */}
          {status !== "never" && catalog.installedTitles > 0 && (
            <p className="mt-2 text-muted-foreground">
              {t.fleetCatalog.historyProgress(catalog.installedTitlesWithHistory, catalog.installedTitles)}
            </p>
          )}
          {historyStatus === "waiting" && state?.historyDetail && <p className="mt-1">{state.historyDetail}</p>}
          {historyStatus === "failed" && state !== null && (
            <p className="mt-1">
              <span className="font-medium text-destructive">
                {t.fleetCatalog.historyFailed(when(state.historyCheckedAt))}
              </span>{" "}
              {state.historyDetail}
            </p>
          )}
        </div>
      )}

      {checkError && <p className="text-sm text-destructive">{checkError}</p>}

      <div className="flex flex-wrap gap-3">
        <input
          className={`${inputClasses} min-w-[240px] flex-1`}
          placeholder={t.fleetCatalog.searchPlaceholder}
          data-page-search=""
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <label className="flex items-center gap-2 text-sm" title={t.fleetCatalog.installedOnlyHint}>
          <input type="checkbox" checked={installedOnly} onChange={(e) => setInstalledOnly(e.target.checked)} />
          {t.fleetCatalog.installedOnly}
        </label>
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              {sortableHeader("name", t.fleetCatalog.tableName)}
              {sortableHeader("bundleId", t.fleetCatalog.tableBundleId)}
              {sortableHeader("latestVersion", t.fleetCatalog.tableLatestVersion)}
              {sortableHeader("deviceCount", t.fleetCatalog.tableDeviceCount)}
              {sortableHeader("devicesBehind", t.fleetCatalog.tableDevicesBehind)}
              {sortableHeader("versionChangedAt", t.fleetCatalog.tableVersionChanged)}
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={COLUMNS}>
                  {t.fleetCatalog.loading}
                </td>
              </tr>
            )}
            {!loading && error && (
              <tr>
                <td className="px-4 py-4 text-destructive" colSpan={COLUMNS}>
                  {error}
                </td>
              </tr>
            )}
            {!loading && !error && emptyMessage !== null && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={COLUMNS}>
                  {emptyMessage}
                </td>
              </tr>
            )}
            {!loading &&
              !error &&
              visible.map((title) => (
                <Fragment key={title.slug}>
                  <tr className={open.has(title.slug) ? "" : "border-b last:border-0"}>
                    <td className="px-4 py-2 font-medium">
                      <button
                        type="button"
                        className="text-left hover:underline"
                        aria-expanded={open.has(title.slug)}
                        aria-controls={`fleet-history-row-${title.slug}`}
                        title={t.fleetCatalog.historyToggleHint}
                        onClick={() => toggleHistory(title.slug)}
                      >
                        <span className="inline-flex items-center gap-1">
                          {open.has(title.slug) ? (
                            <ChevronDown aria-hidden="true" className="h-4 w-4 shrink-0" />
                          ) : (
                            <ChevronRight aria-hidden="true" className="h-4 w-4 shrink-0" />
                          )}
                          {title.name}
                        </span>
                      </button>
                      <a
                        className="mt-1 block w-fit text-xs font-normal text-muted-foreground underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
                        href={`${SOURCE_URL}${encodeURIComponent(title.slug)}/darwin.json`}
                        target="_blank"
                        rel="noreferrer noopener"
                        aria-label={t.fleetCatalog.sourceLabel(title.name)}
                      >
                        {t.fleetCatalog.sourceLink}
                      </a>
                      {title.deviceCount > 0 && <a className="mt-1 block text-xs underline" href={`/devices/applications?q=${encodeURIComponent(title.name)}`}>
                        {locale === "de" ? "Patchplan erstellen" : "Build a patch plan"}
                      </a>}
                    </td>
                    <td className="px-4 py-2">{title.bundleId}</td>
                    <td className="px-4 py-2 tabular-nums">{title.latestVersion}</td>
                    <td className={`px-4 py-2 tabular-nums ${title.deviceCount === 0 ? "text-muted-foreground" : ""}`}>
                      {title.deviceCount}
                    </td>
                    {/* A title on no Mac has nobody behind it and nobody current: a dash, not a
                        zero that would read as "every Mac is up to date". */}
                    <td className="px-4 py-2 tabular-nums">
                      {title.deviceCount === 0 ? (
                        <span className="text-muted-foreground">-</span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5">
                          {title.devicesBehind > 0 && <span className="h-2 w-2 shrink-0 rounded-full bg-[#d03b3b]" />}
                          {title.devicesBehind}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2">{arrived(title)}</td>
                  </tr>
                  {open.has(title.slug) && (
                    <tr id={`fleet-history-row-${title.slug}`} className="border-b bg-muted/20 last:border-0">
                      <td className="px-4 py-3" colSpan={COLUMNS}>
                        <FleetTitleHistory slug={title.slug} canRead={canCheck} onRead={() => void load()} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
          </tbody>
        </table>
      </div>

      {catalog !== null && catalog.enabled && (
        <p className="text-sm text-muted-foreground">
          {t.fleetCatalog.footer(visible.length, state?.appCount ?? 0, catalog.installedTitles)}
        </p>
      )}

      <p className="text-xs text-muted-foreground">
        {t.fleetCatalog.licenceNote}{" "}
        <a className="underline" href={LICENCE_URL} target="_blank" rel="noreferrer noopener">
          {t.fleetCatalog.licenceLink}
        </a>
      </p>
    </section>
  );
}
