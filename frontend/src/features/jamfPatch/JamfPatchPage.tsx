import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { listJamfPatchTitles, syncJamfPatchTitles } from "@/features/jamfPatch/api";
import type { JamfPatchTitle } from "@/features/jamfPatch/types";
import { Button } from "@/components/ui/button";
import { useLocale } from "@/i18n/LocaleContext";

export function JamfPatchPage() {
  const { t } = useLocale();
  const navigate = useNavigate();

  const [titles, setTitles] = useState<JamfPatchTitle[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);

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

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tablePublisher}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableBundleId}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableCurrentVersion}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableDeviceCount}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableDevicesOnLatest}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableLastModified}</th>
              <th className="px-4 py-2 font-medium">{t.jamfPatch.tableSyncedAt}</th>
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
            {titles.map((title) => (
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

      <p className="text-sm text-muted-foreground">{t.jamfPatch.total(total)}</p>
    </section>
  );
}
