import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { listCatalog } from "@/features/catalog/api";
import type { CatalogEntry, CatalogJamfFilter } from "@/features/catalog/types";
import { AssessmentCell, CorpusBanner } from "@/features/vulnerabilities/AppAssessment";
import { useLocale } from "@/i18n/LocaleContext";

type SortKey =
  | "name"
  | "version"
  | "deviceCount"
  | "firstSeenAt"
  | "lastSeenAt"
  | "patchState"
  | "latestVersion"
  | "vuln";
type SortDir = "asc" | "desc";

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

// Status colors are fixed (never themed) per the dataviz palette: good / warning / critical / neutral.
const STATE_COLORS: Record<string, string> = {
  latest: "#0ca30c",
  behind: "#d03b3b",
  ahead: "#fab219",
  unknown: "#fab219"
};

function sortValue(entry: CatalogEntry, key: SortKey): string | number {
  switch (key) {
    case "name":
      return entry.name.toLowerCase();
    case "version":
      return entry.version;
    case "deviceCount":
      return entry.deviceCount;
    case "firstSeenAt":
      return entry.firstSeenAt;
    case "lastSeenAt":
      return entry.lastSeenAt;
    case "patchState":
      return entry.patchState ?? "";
    case "latestVersion":
      return entry.latestVersion ?? "";
    case "vuln":
      // Ascending puts what is worth looking at first: findings (most, first), then the
      // apps nobody could look up, then the clean bills, then the apps nobody looked at.
      // `counts` is reachable only inside the `covered` narrowing — which is the point of
      // the union: there is no branch here where an unassessed app can contribute a zero.
      if (entry.vuln.assessment === "covered") return entry.vuln.counts.total > 0 ? -entry.vuln.counts.total : 2;
      return entry.vuln.assessment === "unknown_app" ? 1 : 3;
  }
}

function compare(a: string | number, b: string | number): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b));
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleDateString() : "—";
}

export function CatalogPage() {
  const { t } = useLocale();
  const [entries, setEntries] = useState<CatalogEntry[]>([]);
  const [summary, setSummary] = useState({ entries: 0, installed: 0, matched: 0, unmatched: 0 });
  // The corpus stamp arrives with the rows it describes, so the banner and the column can
  // never be answering from two different corpora (#251).
  const [corpusAsOf, setCorpusAsOf] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [jamfFilter, setJamfFilter] = useState<CatalogJamfFilter>("all");
  const [installedOnly, setInstalledOnly] = useState(true);
  const [sortKey, setSortKey] = useState<SortKey>("deviceCount");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  useEffect(() => {
    let cancelled = false;
    function load() {
      setLoading(true);
      setError(null);
      listCatalog({ jamf: jamfFilter, installedOnly })
        .then((response) => {
          if (cancelled) return;
          setEntries(response.items);
          setSummary(response.summary);
          setCorpusAsOf(response.corpusAsOf);
        })
        .catch(() => {
          if (!cancelled) setError(t.catalog.errorLoading);
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [jamfFilter, installedOnly, t]);

  const visible = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    const filtered = term
      ? entries.filter(
          (entry) =>
            entry.name.toLowerCase().includes(term) ||
            entry.bundleId.toLowerCase().includes(term) ||
            entry.version.toLowerCase().includes(term) ||
            entry.jamfTitles.some((title) => title.name.toLowerCase().includes(term))
        )
      : entries;
    return [...filtered].sort((a, b) => {
      const result = compare(sortValue(a, sortKey), sortValue(b, sortKey));
      return sortDir === "asc" ? result : -result;
    });
  }, [entries, searchTerm, sortKey, sortDir]);

  function handleSort(key: SortKey) {
    if (key === sortKey) setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir(key === "deviceCount" || key === "lastSeenAt" ? "desc" : "asc");
    }
  }

  function header(key: SortKey, label: string) {
    const indicator = key === sortKey ? (sortDir === "asc" ? " ▲" : " ▼") : "";
    return (
      <th className="cursor-pointer select-none px-4 py-2 font-medium hover:text-foreground" onClick={() => handleSort(key)}>
        {label}
        {indicator}
      </th>
    );
  }

  const stateLabels: Record<string, string> = {
    latest: t.catalog.stateLatest,
    behind: t.catalog.stateBehind,
    ahead: t.catalog.stateAhead,
    unknown: t.catalog.stateUnknown
  };

  return (
    <section className="space-y-4">
      <p className="text-sm text-muted-foreground">{t.catalog.description}</p>

      <CorpusBanner corpusAsOf={corpusAsOf} t={t} />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          [t.catalog.summaryEntries, summary.entries],
          [t.catalog.summaryInstalled, summary.installed],
          [t.catalog.summaryMatched, summary.matched],
          [t.catalog.summaryUnmatched, summary.unmatched]
        ].map(([label, value]) => (
          <div key={String(label)} className="rounded-lg border bg-card p-3">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-2xl font-semibold tabular-nums">{value}</p>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <input
          className={`${inputClasses} min-w-[240px] flex-1`}
          placeholder={t.catalog.searchPlaceholder}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <select className={inputClasses} value={jamfFilter} onChange={(e) => setJamfFilter(e.target.value as CatalogJamfFilter)}>
          <option value="all">{t.catalog.filterAll}</option>
          <option value="matched">{t.catalog.filterMatched}</option>
          <option value="unmatched">{t.catalog.filterUnmatched}</option>
        </select>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={installedOnly} onChange={(e) => setInstalledOnly(e.target.checked)} />
          {t.catalog.installedOnly}
        </label>
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              {header("name", t.catalog.tableName)}
              <th className="px-4 py-2 font-medium">{t.catalog.tableBundleId}</th>
              {header("version", t.catalog.tableVersion)}
              {header("deviceCount", t.catalog.tableDevices)}
              {header("firstSeenAt", t.catalog.tableFirstSeen)}
              {header("lastSeenAt", t.catalog.tableLastSeen)}
              <th className="px-4 py-2 font-medium">{t.catalog.tableJamfTitle}</th>
              {header("patchState", t.catalog.tableState)}
              {header("latestVersion", t.catalog.tableLatest)}
              <th className="px-4 py-2 font-medium">{t.catalog.tableReleased}</th>
              {header("vuln", t.catalog.tableVuln)}
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={11}>
                  {t.catalog.loading}
                </td>
              </tr>
            )}
            {!loading && error && (
              <tr>
                <td className="px-4 py-4 text-destructive" colSpan={11}>
                  {error}
                </td>
              </tr>
            )}
            {!loading && !error && visible.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={11}>
                  {entries.length === 0 ? t.catalog.empty : t.catalog.noMatches}
                </td>
              </tr>
            )}
            {!loading &&
              !error &&
              visible.map((entry) => (
                <tr key={entry.id} className="border-b last:border-0">
                  <td className="px-4 py-2 font-medium">{entry.name}</td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{entry.bundleId}</td>
                  <td className="px-4 py-2 tabular-nums">
                    {entry.version}
                    {entry.shortVersion && entry.shortVersion !== entry.version ? (
                      <span className="text-muted-foreground"> ({entry.shortVersion})</span>
                    ) : null}
                  </td>
                  <td className={`px-4 py-2 tabular-nums ${entry.deviceCount === 0 ? "text-muted-foreground" : ""}`}>
                    {entry.deviceCount}
                  </td>
                  <td className="px-4 py-2">{formatDate(entry.firstSeenAt)}</td>
                  <td className="px-4 py-2">{formatDate(entry.lastSeenAt)}</td>
                  <td className="px-4 py-2">
                    {entry.jamfTitles.length === 0 ? (
                      <span className="text-muted-foreground">—</span>
                    ) : (
                      entry.jamfTitles.map((title, index) => (
                        <span key={title.id}>
                          {index > 0 && ", "}
                          <Link to={`/devices/applications/jamf-patch/${title.id}`} className="hover:underline">
                            {title.name}
                          </Link>
                        </span>
                      ))
                    )}
                  </td>
                  <td className="px-4 py-2">
                    {entry.patchState ? (
                      <>
                        <span className="inline-flex items-center gap-1.5">
                          <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: STATE_COLORS[entry.patchState] }} />
                          {stateLabels[entry.patchState] ?? entry.patchState}
                        </span>
                        {/* #68: a date and a count, never a day count — a date does not inflate. */}
                        {entry.patchAvailable && (
                          <span className="block text-xs text-muted-foreground">
                            {t.catalog.behindSince(formatDate(entry.patchAvailableSince), entry.releasesMissed)}
                          </span>
                        )}
                      </>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2 tabular-nums">{entry.latestVersion ?? "—"}</td>
                  <td className="px-4 py-2">{formatDate(entry.releasedAt)}</td>
                  <td className="px-4 py-2">
                    <AssessmentCell vuln={entry.vuln} t={t} />
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">{t.catalog.filteredTotal(visible.length, entries.length)}</p>
    </section>
  );
}
