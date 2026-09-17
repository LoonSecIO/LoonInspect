import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { CollectionsPanel } from "@/features/mdm/CollectionsPanel";
import { ConnectionForm } from "@/features/mdm/ConnectionForm";
import { RunLogPanel } from "@/features/mdm/RunLogPanel";
import { FileText, RefreshCw } from "lucide-react";
import { ApiError } from "@/config/api";
import { env } from "@/config/env";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { listDestinations } from "@/features/destinations/api";
import type { Destination } from "@/features/destinations/types";
import { deleteConnection, listConnections, listSyncStatus, reEmitConnection, syncConnection } from "@/features/mdm/api";
import type { MdmConnection, MdmSyncStatus } from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

type FormMode = "closed" | "create" | number;

export function ConnectionsPage() {
  const { t } = useLocale();
  // Auditors reach this page with CONNECTION_READ but can't write. The API refuses
  // regardless; hiding the controls keeps them from discovering that via a 403.
  const canWrite = useHasPermission(PERMISSIONS.CONNECTION_WRITE);
  const canSync = useHasPermission(PERMISSIONS.DEVICE_SYNC);
  // The re-emit re-sends tenant data to a destination, so it is gated like the redrive.
  const canReEmit = useHasPermission(PERMISSIONS.DESTINATION_WRITE);
  // The evidence report is served under AUDIT_READ, so the button matches the endpoint rather than
  // offering a reader a click they would be refused (#301).
  const canAudit = useHasPermission(PERMISSIONS.AUDIT_READ);
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
  // The re-emit asks first (#356): it re-sends the whole fleet's inventory, and the
  // panel says how much before the click that does it. Destinations are read when the
  // panel opens, never before.
  const [pendingReEmitId, setPendingReEmitId] = useState<number | null>(null);
  const [reEmitDestinations, setReEmitDestinations] = useState<Destination[] | null>(null);
  const [reEmitDestinationId, setReEmitDestinationId] = useState<number | "">("");
  const [reEmitting, setReEmitting] = useState(false);
  const [reEmitError, setReEmitError] = useState<string | null>(null);

  /** The one read of the table, as a promise chain rather than `await`: the first read is
   *  started by the effect below, and an effect body is the one place React asks callers
   *  not to set state (#15). `loading` starts true; `refresh` turns it back on and clears
   *  the error line, where a click is what asked for the re-read. */
  function load(): Promise<void> {
    return Promise.all([listConnections(), listSyncStatus()])
      .then(([rows, statuses]) => {
        setConnections(rows);
        setSyncStatuses(Object.fromEntries(statuses.map((s) => [s.mdmConnectionId, s])));
      })
      .catch((caught: unknown) => {
        // Without this, a failed load leaves connections empty and the table says
        // "no connections yet" — failure must not read as emptiness. A 503 carries a
        // sentence worth showing: the stored credentials cannot be read (#374).
        setLoadError(caught instanceof ApiError && caught.status === 503 && caught.detail ? caught.detail : t.settings.errorLoading);
      })
      .finally(() => setLoading(false));
  }

  function refresh(): Promise<void> {
    setLoading(true);
    setLoadError(null);
    return load();
  }

  useEffect(() => {
    void load();
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

  /** The evidence report (#473): one file, downloaded. A raw fetch rather than `apiRequest`, for the
   *  reason Data sharing's share-log download gives — the endpoint answers HTML, not JSON — and the
   *  server names the file, its window and `asOf` being what keeps two reports apart in a downloads
   *  folder. A refusal carries its own sentence (no ledger yet, an empty window, an unreadable rule
   *  catalogue); only a body-less failure falls back to the generic line. */
  async function handleEvidenceReport(id: number) {
    setSyncError(null);
    try {
      const url = `${env.apiBaseUrl}/evidence/report.html?connectionID=${id}`;
      const response = await fetch(url, { credentials: "include" });
      if (!response.ok) {
        const refusal: unknown = await response.json().catch(() => null);
        throw new Error(
          refusal && typeof refusal === "object" && "detail" in refusal ? String(refusal.detail) : ""
        );
      }
      const named = /filename="([^"]+)"/.exec(response.headers.get("content-disposition") ?? "");
      const anchor = document.createElement("a");
      anchor.href = URL.createObjectURL(await response.blob());
      anchor.download = named ? named[1] : "evidence-report.html";
      anchor.click();
      URL.revokeObjectURL(anchor.href);
    } catch (caught) {
      setSyncError(caught instanceof Error && caught.message ? caught.message : t.settings.evidenceReportError);
    }
  }

  function openReEmit(id: number) {
    setPendingReEmitId(id);
    setReEmitDestinationId("");
    setReEmitError(null);
    listDestinations()
      .then((rows) => setReEmitDestinations(rows.filter((row) => row.enabled)))
      .catch(() => setReEmitDestinations([]));
  }

  async function handleReEmit(id: number) {
    setReEmitting(true);
    setReEmitError(null);
    try {
      const triggered = await reEmitConnection(id, reEmitDestinationId === "" ? undefined : reEmitDestinationId);
      setRuns((held) => ({ ...held, [id]: { jobId: triggered.jobId, joined: !triggered.started } }));
      setPendingReEmitId(null);
    } catch (caught) {
      setReEmitError(caught instanceof ApiError && caught.detail ? caught.detail : t.settings.reEmitError);
    } finally {
      setReEmitting(false);
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
                <td className="px-4 py-2">
                  {connection.name}
                  {/* The sweep's refusal, on the row that can fix it (#393). The sentence is
                      the server's — it names this connection and the missing field — so only
                      the label around it is translated. */}
                  {connection.credentialProblem && (
                    <p className="mt-1 max-w-md text-xs text-destructive">
                      <span className="font-medium">{t.settings.credentialProblem}</span>{" "}
                      {connection.credentialProblem}
                    </p>
                  )}
                </td>
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
                      {canReEmit && (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={pendingReEmitId === connection.id}
                          onClick={() => openReEmit(connection.id)}
                        >
                          {t.settings.reEmit}
                        </Button>
                      )}
                      {canAudit && (
                        <Button variant="outline" size="sm" onClick={() => handleEvidenceReport(connection.id)}>
                          <FileText className="mr-1 h-3 w-3" />
                          {t.settings.evidenceReport}
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
            {/* The re-emit's confirm (#356), under its row like the run panel: what it
                will send, to where, and how much, before the click that sends it. */}
            {connections.flatMap((connection) => {
              if (pendingReEmitId !== connection.id) return [];
              const devices = syncStatuses[connection.id]?.deviceCount ?? 0;
              const megabytes = Math.round((devices * 30) / 1024);
              return [
                <tr key={`re-emit-${connection.id}`} className="border-b last:border-0">
                  <td className="px-4 pb-3" colSpan={7}>
                    <div className="space-y-2 rounded-lg border bg-muted/20 p-3 text-sm">
                      <p className="font-medium">{t.settings.reEmitTitle}</p>
                      <p className="text-muted-foreground">{t.settings.reEmitHelp(devices, megabytes)}</p>
                      <label className="flex flex-wrap items-center gap-2">
                        <span>{t.settings.reEmitDestination}</span>
                        <select
                          className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                          value={reEmitDestinationId}
                          onChange={(event) => setReEmitDestinationId(event.target.value === "" ? "" : Number(event.target.value))}
                        >
                          <option value="">{t.settings.reEmitEveryDestination}</option>
                          {(reEmitDestinations ?? []).map((destination) => (
                            <option key={destination.id} value={destination.id}>
                              {destination.name}
                            </option>
                          ))}
                        </select>
                      </label>
                      {reEmitError && <p className="text-destructive">{reEmitError}</p>}
                      <div className="flex gap-2">
                        <Button size="sm" disabled={reEmitting} onClick={() => handleReEmit(connection.id)}>
                          {t.settings.reEmitConfirm}
                        </Button>
                        <Button variant="outline" size="sm" disabled={reEmitting} onClick={() => setPendingReEmitId(null)}>
                          {t.settings.cancel}
                        </Button>
                      </div>
                    </div>
                  </td>
                </tr>,
              ];
            })}
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
          <CollectionsPanel
            key={connection.id}
            connection={connection}
            onConnectionChanged={(updated) =>
              setConnections((current) => current.map((row) => (row.id === updated.id ? updated : row)))
            }
          />
        ))}
    </section>
  );
}
