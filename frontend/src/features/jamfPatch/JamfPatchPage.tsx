import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { listJamfPatchTitles, syncJamfPatchTitles } from "@/features/jamfPatch/api";
import type { JamfPatchTitle } from "@/features/jamfPatch/types";
import { Button } from "@/components/ui/button";
import { useLocale } from "@/i18n/LocaleContext";

type SearchMode = "exact" | "regex" | "fuzzy";
type SortKey = "name" | "publisher" | "bundleId" | "currentVersion" | "lastModified" | "syncedAt";
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

function sortValue(title: JamfPatchTitle, key: SortKey): string {
  switch (key) {
    case "name":
      return title.name;
    case "publisher":
      return title.publisher ?? "";
    case "bundleId":
      return title.bundleId ?? "";
    case "currentVersion":
      return title.currentVersion;
    case "lastModified":
      return title.lastModified;
    case "syncedAt":
      return title.syncedAt;
  }
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
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  function refresh(): Promise<void> {
    setLoading(true);
    setError(null);

    return listJamfPatchTitles()
      .then((response) => {
        setTitles(response.items);
        setTotal(response.total);
      })
      .catch(() => {
        setError(t.jamfPatch.errorLoading);
      })
      .finally(() => {
        setLoading(false);
      });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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

  const visibleTitles = useMemo(() => {
    const term = searchTerm.trim();
    const filtered = term ? titles.filter((title) => titleMatches(title, term, searchMode)) : titles;

    const sorted = [...filtered].sort((a, b) => {
      const result = sortValue(a, sortKey).localeCompare(sortValue(b, sortKey));
      return sortDir === "asc" ? result : -result;
    });

    return sorted;
  }, [titles, searchTerm, searchMode, sortKey, sortDir]);

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
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              {sortableHeader("name", t.jamfPatch.tableName)}
              {sortableHeader("publisher", t.jamfPatch.tablePublisher)}
              {sortableHeader("bundleId", t.jamfPatch.tableBundleId)}
              {sortableHeader("currentVersion", t.jamfPatch.tableCurrentVersion)}
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableDeviceCount}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableDevicesOnLatest}</th>
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
            {!loading && !error && titles.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  {t.jamfPatch.empty}
                </td>
              </tr>
            )}
            {!loading && !error && titles.length > 0 && visibleTitles.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={8}>
                  {t.jamfPatch.noMatches}
                </td>
              </tr>
            )}
            {visibleTitles.map((title) => (
              <tr
                key={title.id}
                onClick={() => navigate(`/devices/applications/jamf-patch/${title.id}`)}
                className="cursor-pointer border-b last:border-0 hover:bg-accent/50"
              >
                <td className="px-4 py-2 font-medium">{title.name}</td>
                <td className="px-4 py-2">{title.publisher ?? "—"}</td>
                <td className="px-4 py-2">{title.bundleId ?? "—"}</td>
                <td className="px-4 py-2">{title.currentVersion}</td>
                {/* Stub — not wired to real device-inventory counts yet. */}
                <td className="px-4 py-2 text-muted-foreground">—</td>
                <td className="px-4 py-2 text-muted-foreground">—</td>
                <td className="px-4 py-2">{title.lastModified}</td>
                <td className="px-4 py-2">{new Date(title.syncedAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">{t.jamfPatch.filteredTotal(visibleTitles.length, total)}</p>
    </section>
  );
}
