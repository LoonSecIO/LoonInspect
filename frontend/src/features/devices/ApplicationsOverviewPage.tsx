import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { Input } from "@/components/ui/input";
import { listApplications, type Application } from "@/features/devices/applicationsApi";
import { listSyncStatus } from "@/features/mdm/api";
import type { MdmSyncStatus } from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

/** Why the table is empty, resolved only on the empty path (#299 §8). */
type EmptyReason = "noConnection" | "noSync" | "synced" | "noMatch";

function emptyReason(q: string, statuses: MdmSyncStatus[]): EmptyReason {
  if (q) return "noMatch";
  if (statuses.length === 0) return "noConnection";
  if (statuses.every((status) => status.lastSyncAt === null)) return "noSync";
  return "synced";
}

/**
 * The applications table, trimmed (#299): a list with a record behind every row. The
 * expansion that lived inside a row is gone with the per-version query that fed it; a
 * row click goes to `/devices/applications/:appHash`, which has an address, so it can be
 * pasted into a ticket and reached for an app the list never fetched.
 *
 * Search lives in the URL (`q`), as the Devices page's does, so a filtered list is a link.
 */
export function ApplicationsOverviewPage() {
  const { t } = useLocale();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const q = useMemo(() => searchParams.get("q") ?? "", [searchParams]);

  const [loaded, setLoaded] = useState<{ q: string; items: Application[]; total: number; statuses: MdmSyncStatus[] | null } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState(q);

  // The box is a draft, applied on a debounce; it follows the URL when the back button
  // moves it. Adjusted during render rather than from an effect.
  const [lastApplied, setLastApplied] = useState(q);
  if (lastApplied !== q) {
    setLastApplied(q);
    setDraft(q);
  }

  useEffect(() => {
    const trimmed = draft.trim();
    if (trimmed === q) return;
    const handle = setTimeout(() => setSearchParams(trimmed ? { q: trimmed } : {}, { replace: true }), 250);
    return () => clearTimeout(handle);
  }, [draft, q, setSearchParams]);

  useEffect(() => {
    let cancelled = false;
    listApplications({ q: q || undefined, pageSize: 200 })
      .then(async (response) => {
        if (cancelled) return;
        // The four empty states need the sync status, and only the empty path reads it.
        const statuses = response.items.length === 0 && !q ? await listSyncStatus().catch(() => null) : null;
        if (cancelled) return;
        setLoaded({ q, items: response.items, total: response.total, statuses });
        setError(null);
      })
      .catch(() => {
        if (!cancelled) setError(t.applications.errorLoading);
      });
    return () => {
      cancelled = true;
    };
  }, [q, t]);

  const current = loaded && loaded.q === q ? loaded : null;
  const loading = current === null && error === null;

  return (
    <section className="space-y-4">
      <Input placeholder={t.applications.searchPlaceholder} value={draft} onChange={(event) => setDraft(event.target.value)} className="max-w-sm" />

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.applications.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableBundleId}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableVersions}</th>
              <th className="px-4 py-2 text-right font-medium">{t.applications.tableDevices}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={4}>
                  {t.applications.loading}
                </td>
              </tr>
            )}
            {current && current.items.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={4}>
                  {current.statuses === null && !q
                    ? t.applications.empty
                    : t.applications.emptyStates[emptyReason(q, current.statuses ?? [])]}
                </td>
              </tr>
            )}
            {current?.items.map((app) => (
              <tr
                key={app.appHash}
                className="cursor-pointer border-b last:border-0 hover:bg-accent/40"
                onClick={() => navigate(`/devices/applications/${app.appHash}`)}
              >
                <td className="px-4 py-2 font-medium">
                  <Link to={`/devices/applications/${app.appHash}`} className="hover:underline" onClick={(event) => event.stopPropagation()}>
                    {app.name}
                  </Link>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{app.bundleId}</td>
                <td className="px-4 py-2 tabular-nums">{app.versionCount}</td>
                <td className="px-4 py-2 text-right font-medium tabular-nums">{app.deviceCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {current && <p className="text-sm text-muted-foreground">{t.applications.total(current.total)}</p>}
    </section>
  );
}
