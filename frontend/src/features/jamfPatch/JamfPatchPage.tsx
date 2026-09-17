import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { AppNameLine } from "@/features/jamfPatch/AppNameLine";
import { listJamfPatchTitles, syncJamfPatchTitles } from "@/features/jamfPatch/api";
import { PatchingPolicyStatement } from "@/features/jamfPatch/PatchingPolicyStatement";
import { filterTitles } from "@/features/jamfPatch/titleFilter";
import type { JamfPatchTitle } from "@/features/jamfPatch/types";
import { Button } from "@/components/ui/button";
import { useLocale } from "@/i18n/LocaleContext";

type SearchMode = "exact" | "regex" | "fuzzy";
type SortKey =
  | "name"
  | "publisher"
  | "bundleId"
  | "currentVersion"
  | "deviceCount"
  | "devicesOnLatest"
  | "lastModified"
  | "syncedAt";
type SortDir = "asc" | "desc";

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

function fuzzyMatch(term: string, value: string): boolean {
  let termIndex = 0;
  for (let i = 0; i < value.length && termIndex < term.length; i++) {
    if (value[i] === term[termIndex]) termIndex++;
  }
  return termIndex === term.length;
}

function fieldMatches(term: string, mode: SearchMode, value: string | null): boolean {
  if (!value) return false;
  const haystack = value.toLowerCase();
  const needle = term.toLowerCase();

  if (mode === "regex") {
    try {
      return new RegExp(term, "i").test(value);
    } catch {
      return false;
    }
  }
  if (mode === "fuzzy") return fuzzyMatch(needle, haystack);
  return haystack.includes(needle);
}

function titleMatches(title: JamfPatchTitle, term: string, mode: SearchMode): boolean {
  if (!term) return true;
  return (
    fieldMatches(term, mode, title.name) ||
    fieldMatches(term, mode, title.publisher) ||
    fieldMatches(term, mode, title.bundleId) ||
    fieldMatches(term, mode, title.currentVersion)
  );
}

function sortValue(title: JamfPatchTitle, key: SortKey): string | number {
  switch (key) {
    case "name":
      return title.name;
    case "publisher":
      return title.publisher ?? "";
    case "bundleId":
      return title.bundleId ?? "";
    case "currentVersion":
      return title.currentVersion;
    case "deviceCount":
      return title.deviceCount;
    case "devicesOnLatest":
      return title.devicesOnLatest;
    case "lastModified":
      return title.lastModified;
    case "syncedAt":
      return title.syncedAt;
  }
}

function compareSortValues(a: string | number, b: string | number): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b));
}

export function JamfPatchPage() {
  const { t } = useLocale();
  const navigate = useNavigate();

  const [titles, setTitles] = useState<JamfPatchTitle[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState("");
  const [searchMode, setSearchMode] = useState<SearchMode>("exact");
  // Ticked by default (#403), as the Catalog tab's "Installed now only" is, and held in
  // the component: the detail page's back link remounts this page, so a reader returns to
  // the default after every title. The footer always says what it hid.
  const [onlyWithDevices, setOnlyWithDevices] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  /** The one read of the list. Nothing here turns the spinner on or clears the error
   *  line: the first read comes from the effect below, and an effect body is the one
   *  place React asks callers not to set state (#15). `loading` starts true; a re-read
   *  goes through `refresh`, where a click is what asked for it.
   *
   *  Held against the dictionary — the failure line is written in it — so a language switch
   *  re-reads (#479); `live` is how the effect drops a read that switch superseded, leaving
   *  the language just left unable to write the last word. A click's re-read is not the
   *  effect's, is not what the switch replaces, and passes none. */
  const load = useCallback(
    (live: () => boolean = () => true): Promise<void> =>
      listJamfPatchTitles()
        .then((response) => {
          if (!live()) return;
          setTitles(response.items);
          setTotal(response.total);
        })
        .catch(() => {
          if (live()) setError(t.jamfPatch.errorLoading);
        })
        .finally(() => {
          if (live()) setLoading(false);
        }),
    [t]
  );

  function refresh(): Promise<void> {
    setLoading(true);
    setError(null);
    return load();
  }

  // A language switch re-runs the read below, and the page has to read as asking rather than
  // leave the previous language's answer standing as this one's. Adjusted during the render
  // that moved the locale, keyed on the effect's whole dependency array — the frontend rule
  // in CONTRIBUTING.md, and the reason it is there (#479).
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

  function handleSyncNow() {
    setSyncing(true);
    setSyncError(null);

    syncJamfPatchTitles()
      .then(() => refresh())
      .catch(() => setSyncError(t.jamfPatch.syncError))
      .finally(() => setSyncing(false));
  }

  function handleSort(key: SortKey) {
    if (key === sortKey) {
      setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  // The search, then the checkbox, then the sort. `filterTitles` decides which rows show
  // and why none do, so the four empty states are table-tested (`titleFilter.test.ts`).
  const filtered = useMemo(() => {
    const term = searchTerm.trim();
    return filterTitles(titles, {
      matches: (title) => titleMatches(title, term, searchMode),
      searching: term !== "",
      onlyWithDevices
    });
  }, [titles, searchTerm, searchMode, onlyWithDevices]);

  const visibleTitles = useMemo(
    () =>
      [...filtered.visible].sort((a, b) => {
        const result = compareSortValues(sortValue(a, sortKey), sortValue(b, sortKey));
        return sortDir === "asc" ? result : -result;
      }),
    [filtered, sortKey, sortDir]
  );

  const emptyMessage = (() => {
    switch (filtered.empty) {
      case "noCatalog":
        return t.jamfPatch.empty;
      case "noneWithDevices":
        return t.jamfPatch.emptyNoneWithDevices(filtered.hidden);
      case "matchesOnlyWithoutDevices":
        return t.jamfPatch.emptyMatchesOnlyWithoutDevices(filtered.hidden);
      case "noMatch":
        return t.jamfPatch.noMatches;
      default:
        return null;
    }
  })();

  function sortIndicator(key: SortKey): string {
    if (key !== sortKey) return "";
    return sortDir === "asc" ? " ▲" : " ▼";
  }

  function sortableHeader(key: SortKey, label: string) {
    return (
      <th
        className="cursor-pointer select-none px-4 py-2 font-medium hover:text-foreground"
        onClick={() => handleSort(key)}
      >
        {label}
        {sortIndicator(key)}
      </th>
    );
  }

  return (
    <section className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{t.jamfPatch.eyebrow}</p>
          <h1 className="text-3xl font-bold tracking-tight">{t.jamfPatch.title}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t.jamfPatch.description}</p>
        </div>
        <Button onClick={handleSyncNow} disabled={syncing}>
          {syncing ? t.jamfPatch.syncing : t.jamfPatch.syncNow}
        </Button>
      </div>

      {syncError && <p className="text-sm text-destructive">{syncError}</p>}

      {/* The org's stated policy, beside the evidence it is read against (#116). */}
      <PatchingPolicyStatement />

      <div className="flex flex-wrap gap-3">
        <input
          className={`${inputClasses} min-w-[240px] flex-1`}
          placeholder={t.jamfPatch.searchPlaceholder}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <select
          className={inputClasses}
          value={searchMode}
          onChange={(e) => setSearchMode(e.target.value as SearchMode)}
        >
          <option value="exact">{t.jamfPatch.searchModeExact}</option>
          <option value="regex">{t.jamfPatch.searchModeRegex}</option>
          <option value="fuzzy">{t.jamfPatch.searchModeFuzzy}</option>
        </select>
        <label className="flex items-center gap-2 text-sm" title={t.jamfPatch.onlyWithDevicesHint}>
          <input type="checkbox" checked={onlyWithDevices} onChange={(e) => setOnlyWithDevices(e.target.checked)} />
          {t.jamfPatch.onlyWithDevices}
        </label>
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              {sortableHeader("name", t.jamfPatch.tableName)}
              {sortableHeader("publisher", t.jamfPatch.tablePublisher)}
              {sortableHeader("bundleId", t.jamfPatch.tableBundleId)}
              {sortableHeader("currentVersion", t.jamfPatch.tableCurrentVersion)}
              {sortableHeader("deviceCount", t.jamfPatch.tableDeviceCount)}
              {sortableHeader("devicesOnLatest", t.jamfPatch.tableDevicesOnLatest)}
              {sortableHeader("lastModified", t.jamfPatch.tableLastModified)}
              {sortableHeader("syncedAt", t.jamfPatch.tableSyncedAt)}
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  {t.jamfPatch.loading}
                </td>
              </tr>
            )}
            {!loading && error && (
              <tr>
                <td className="px-4 py-4 text-destructive" colSpan={8}>
                  {error}
                </td>
              </tr>
            )}
            {/* Four empty states, each in its own words (#403, docs/diagnosability.md rule 1). */}
            {!loading && !error && emptyMessage !== null && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  {emptyMessage}
                </td>
              </tr>
            )}
            {visibleTitles.map((title) => (
              <tr
                key={title.id}
                onClick={() => navigate(`/devices/applications/jamf-patch/${title.id}`)}
                className="cursor-pointer border-b last:border-0 hover:bg-accent/50"
              >
                {/* The title's name, and under it the app name its content keys are
                    computed from — marked when LoonInspect derived it (#478). */}
                <td className="px-4 py-2 font-medium">
                  {title.name}
                  <AppNameLine title={title} t={t} className="mt-0.5 block text-xs font-normal text-muted-foreground" />
                </td>
                <td className="px-4 py-2">{title.publisher ?? "—"}</td>
                <td className="px-4 py-2">{title.bundleId ?? "—"}</td>
                <td className="px-4 py-2">{title.currentVersion}</td>
                <td className={`px-4 py-2 tabular-nums ${title.deviceCount === 0 ? "text-muted-foreground" : ""}`}>
                  {title.deviceCount}
                </td>
                <td className={`px-4 py-2 tabular-nums ${title.deviceCount === 0 ? "text-muted-foreground" : ""}`}>
                  {title.deviceCount === 0 ? "—" : title.devicesOnLatest}
                </td>
                <td className="px-4 py-2">{title.lastModified}</td>
                <td className="px-4 py-2">{new Date(title.syncedAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">
        {t.jamfPatch.filteredTotal(visibleTitles.length, total)}
        {filtered.hidden > 0 && ` · ${t.jamfPatch.hiddenWithoutDevices(filtered.hidden)}`}
      </p>
    </section>
  );
}
