import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { CollectionsPanel } from "@/features/mdm/CollectionsPanel";
import { ConnectionForm } from "@/features/mdm/ConnectionForm";
import { RunLogPanel } from "@/features/mdm/RunLogPanel";
import { RefreshCw } from "lucide-react";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { deleteConnection, listConnections, listSyncStatus, syncConnection } from "@/features/mdm/api";
import type { MdmConnection, MdmSyncStatus } from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

type FormMode = "closed" | "create" | number;

export function ConnectionsPage() {
  const { t } = useLocale();
  // Auditors reach this page with CONNECTION_READ but can't write. The API refuses
  // regardless; hiding the controls keeps them from discovering that via a 403.
  const canWrite = useHasPermission(PERMISSIONS.CONNECTION_WRITE);
  const canSync = useHasPermission(PERMISSIONS.DEVICE_SYNC);
  const [connections, setConnections] = useState<MdmConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [formMode, setFormMode] = useState<FormMode>("closed");
  const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [syncStatuses, setSyncStatuses] = useState<Record<number, MdmSyncStatus>>({});
  const [syncingId, setSyncingId] = useState<number | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);
  // The run each connection's row is currently showing. Set by clicking Sync now, and
  // kept after the run ends so the outcome stays readable instead of vanishing.
  const [runs, setRuns] = useState<Record<number, { jobId: string; joined: boolean }>>({});

  async function refresh() {
    setLoading(true);
    setLoadError(null);
    try {
      const [rows, statuses] = await Promise.all([listConnections(), listSyncStatus()]);
      setConnections(rows);
      setSyncStatuses(Object.fromEntries(statuses.map((s) => [s.mdmConnectionId, s])));
    } catch {
      // Without this, a failed load leaves connections empty and the table says
      // "no connections yet" — failure must not read as emptiness.
      setLoadError(t.settings.errorLoading);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  // A manual sync runs in the background, so the only way to see it finish is to keep
  // asking. Polling stops as soon as nothing is in flight rather than running forever.
  const anySyncing = Object.values(syncStatuses).some((s) => s.status === "syncing");
  useEffect(() => {
    if (!anySyncing) return;
    const handle = setInterval(() => {
      listSyncStatus()
        .then((statuses) =>
          setSyncStatuses(Object.fromEntries(statuses.map((s) => [s.mdmConnectionId, s])))
        )
        .catch(() => undefined);
    }, 3000);
    return () => clearInterval(handle);
  }, [anySyncing]);

  async function handleSync(id: number) {
    setSyncingId(id);
    setSyncError(null);
    try {
      // Always a jobID, whether this started the run or joined one already in flight —
      // the panel points at the run either way, which is what makes a second click
      // during a cron sweep informative rather than an error.
      const triggered = await syncConnection(id);
      setRuns((held) => ({ ...held, [id]: { jobId: triggered.jobId, joined: !triggered.started } }));
      const statuses = await listSyncStatus();
      setSyncStatuses(Object.fromEntries(statuses.map((s) => [s.mdmConnectionId, s])));
    } catch (caught) {
      setSyncError(
        caught instanceof ApiError && caught.detail ? caught.detail : t.settings.syncError
      );
    } finally {
      setSyncingId(null);
    }
  }

  async function handleDelete(id: number) {
    setDeleting(true);
    setDeleteError(null);
    try {
      await deleteConnection(id);
      setPendingDeleteId(null);
      await refresh();
    } catch (caught) {
      // refresh() reports its own failures, so this catch is the delete call's.
      setDeleteError(
        caught instanceof ApiError && caught.detail ? caught.detail : t.settings.errorDeleting
      );
    } finally {
      setDeleting(false);
    }
  }

  const editingConnection =
    typeof formMode === "number" ? connections.find((c) => c.id === formMode) : undefined;

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
          <h1 className="text-3xl font-bold tracking-tight">{t.settings.title}</h1>
        </div>
        {canWrite && formMode === "closed" && (
          <Button onClick={() => setFormMode("create")}>{t.settings.addConnection}</Button>
        )}
      </div>

      {syncError && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          {syncError}
        </p>
      )}

      {deleteError && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          {deleteError}
        </p>
      )}

      {formMode !== "closed" && (
        <ConnectionForm
          connection={editingConnection}
          onSaved={() => {
            setFormMode("closed");
            refresh();
          }}
          onCancel={() => setFormMode("closed")}
        />
      )}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.settings.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tableProvider}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tableBaseUrl}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tablePatchMgmt}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tableStatus}</th>
              <th className="px-4 py-2 font-medium">{t.settings.tableLastSync}</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={7}>
                  {t.settings.loading}
                </td>
              </tr>
            )}
            {!loading && loadError && (
              <tr>
                <td className="px-4 py-4 text-destructive" colSpan={7}>
                  {loadError}
                </td>
              </tr>
            )}
            {!loading && !loadError && connections.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={7}>
                  {t.settings.empty}
                </td>
              </tr>
            )}
            {connections.map((connection) => (
              <tr key={connection.id} className="border-b last:border-0">
                <td className="px-4 py-2">{connection.name}</td>
                <td className="px-4 py-2">{connection.provider}</td>
                <td className="px-4 py-2">{connection.baseUrl}</td>
                <td className="px-4 py-2">{connection.patchManagementProvider}</td>
                <td className="px-4 py-2">{connection.isActive ? t.settings.active : t.settings.inactive}</td>
                <td className="px-4 py-2 text-xs">
                  {(() => {
                    const state = syncStatuses[connection.id];
                    if (!state) return <span className="text-muted-foreground">{t.settings.syncNever}</span>;
                    if (state.status === "syncing")
                      return <span className="text-primary">{t.settings.syncRunning}</span>;
                    if (state.status === "failed")
                      return <span className="text-destructive">{t.settings.syncFailed}</span>;
                    return (
                      <span className="text-muted-foreground">
                        {state.lastSyncAt ? new Date(state.lastSyncAt).toLocaleString() : t.settings.syncNever}
                        {` · ${t.settings.syncDeviceCount(state.deviceCount)}`}
                      </span>
                    );
                  })()}
                </td>
                <td className="px-4 py-2">
                  {pendingDeleteId === connection.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <span className="text-xs text-muted-foreground">{t.settings.deleteConfirm(connection.name)}</span>
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={deleting}
                        onClick={() => handleDelete(connection.id)}
                      >
                        {deleting ? t.settings.deleting : t.settings.confirm}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={deleting}
                        onClick={() => setPendingDeleteId(null)}
                      >
                        {t.settings.cancel}
                      </Button>
                    </div>
                  ) : (
                    <div className="flex justify-end gap-2">
                      {canSync && (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={
                            syncingId === connection.id ||
                            syncStatuses[connection.id]?.status === "syncing" ||
                            !connection.isActive
                          }
                          onClick={() => handleSync(connection.id)}
                        >
                          <RefreshCw
                            className={
                              syncStatuses[connection.id]?.status === "syncing"
                                ? "mr-1 h-3 w-3 animate-spin"
                                : "mr-1 h-3 w-3"
                            }
                          />
                          {t.settings.syncNow}
                        </Button>
                      )}
                      {canWrite && (
                        <>
                          <Button variant="outline" size="sm" onClick={() => setFormMode(connection.id)}>
                            {t.settings.edit}
                          </Button>
                          <Button variant="destructive" size="sm" onClick={() => setPendingDeleteId(connection.id)}>
                            {t.settings.delete}
                          </Button>
                        </>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
            {/* The run-now panel sits under its connection's row rather than inside a
                cell: the log is wide, and a nested scroll region inside a table cell
                collapses the column widths for every other row. */}
            {connections.flatMap((connection) => {
              const active = runs[connection.id];
              if (!active) return [];
              return [
                <tr key={`run-${connection.id}`} className="border-b last:border-0">
                  <td className="px-4 pb-3" colSpan={7}>
                    <RunLogPanel
                      jobId={active.jobId}
                      joined={active.joined}
                      onFinished={() => {
                        listSyncStatus()
                          .then((statuses) =>
                            setSyncStatuses(Object.fromEntries(statuses.map((s) => [s.mdmConnectionId, s])))
                          )
                          .catch(() => undefined);
                      }}
                    />
                  </td>
                </tr>,
              ];
            })}
          </tbody>
        </table>
      </div>

      {/* What each Jamf connection collects, and when (#27). The connection holds
          credentials; the pulls live here. */}
      {connections
        .filter((connection) => connection.provider === "jamf")
        .map((connection) => (
          <CollectionsPanel key={connection.id} connection={connection} />
        ))}
    </section>
  );
}
