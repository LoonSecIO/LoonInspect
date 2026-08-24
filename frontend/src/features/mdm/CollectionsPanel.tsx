import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import {
  createCollection,
  deleteCollection,
  listCollections,
  listJamfSections,
  runCollection,
  updateCollection
} from "@/features/mdm/api";
import type {
  Collection,
  CollectionFrequency,
  CollectionInput,
  CollectionKind,
  MdmConnection,
  SectionInfo
} from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

interface CollectionsPanelProps {
  connection: MdmConnection;
}

type FormMode = "closed" | "create" | number;

const inputClasses =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

const selectorPresets: Record<string, string> = {
  all: "",
  managed: "general.remoteManagement.managed==true",
  unmanaged: "general.remoteManagement.managed==false"
};

function pad(value: number | null): string {
  return String(value ?? 0).padStart(2, "0");
}

function browserTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

export function CollectionsPanel({ connection }: CollectionsPanelProps) {
  const { t } = useLocale();
  const tc = t.collections;
  const canWrite = useHasPermission(PERMISSIONS.CONNECTION_WRITE);
  const canRun = useHasPermission(PERMISSIONS.DEVICE_SYNC);

  const [rows, setRows] = useState<Collection[]>([]);
  const [loading, setLoading] = useState(true);
  const [formMode, setFormMode] = useState<FormMode>("closed");
  const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [queuedId, setQueuedId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await listCollections(connection.id));
    } finally {
      setLoading(false);
    }
  }, [connection.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // A queued run finishes in the background; its outcome lands on the row's lastRun
  // fields, so keep asking for a while after queueing rather than forever.
  useEffect(() => {
    if (queuedId === null) return;
    let ticks = 0;
    const handle = setInterval(() => {
      ticks += 1;
      listCollections(connection.id)
        .then(setRows)
        .catch(() => undefined);
      if (ticks >= 20) setQueuedId(null);
    }, 3000);
    return () => clearInterval(handle);
  }, [queuedId, connection.id]);

  async function handleRun(id: number) {
    setBusyId(id);
    setError(null);
    try {
      await runCollection(id);
      setQueuedId(id);
    } catch (caught) {
      setError(caught instanceof ApiError && caught.detail ? caught.detail : tc.runError);
    } finally {
      setBusyId(null);
    }
  }

  async function handleToggle(row: Collection) {
    setBusyId(row.id);
    setError(null);
    try {
      await updateCollection(row.id, { enabled: !row.enabled });
      await refresh();
    } catch (caught) {
      setError(caught instanceof ApiError && caught.detail ? caught.detail : tc.form.error);
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(id: number) {
    setBusyId(id);
    try {
      await deleteCollection(id);
      setPendingDeleteId(null);
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  function describeWhat(row: Collection): string {
    if (row.kind === "catalog") return tc.catalogWhat;
    const parts: string[] = [];
    parts.push(row.sections.length >= 14 ? tc.allSections : tc.sectionsCount(row.sections.length));
    if (row.kind === "device_sweep") parts.push(row.selector ? `${tc.selectorLabel}: ${row.selector}` : tc.noSelector);
    if (row.quarantinedExtensionAttributes.length > 0)
      parts.push(tc.quarantineCount(row.quarantinedExtensionAttributes.length));
    if (row.kind === "webhook") parts.push(tc.webhookWhat);
    return parts.join(" · ");
  }

  function describeWhen(row: Collection): string {
    if (!row.frequency) return tc.eventDriven;
    const zone = row.timezone ?? "UTC";
    const time = `${pad(row.atHour)}:${pad(row.atMinute)}`;
    switch (row.frequency) {
      case "hourly":
        return tc.scheduleHourly(pad(row.atMinute));
      case "daily":
        return tc.scheduleDaily(time, zone);
      case "weekly":
        return tc.scheduleWeekly(tc.weekdays[row.weekday ?? 0] ?? "", time, zone);
      case "every_n_days":
        return tc.scheduleEveryN(row.intervalN ?? 2, time, zone);
      default:
        return row.frequency;
    }
  }

  function describeLastRun(row: Collection): string {
    if (!row.lastRunAt) return tc.never;
    const status =
      row.lastRunStatus === "ok" ? tc.runOk : row.lastRunStatus === "skipped" ? tc.runSkipped : tc.runFailed;
    const summary = row.lastRunSummary ?? {};
    const devices = typeof summary.deviceCount === "number" ? summary.deviceCount : 0;
    const groups = typeof summary.groupCount === "number" ? summary.groupCount : 0;
    const counts = row.lastRunStatus === "ok" ? ` · ${tc.runSummary(devices, groups)}` : "";
    return `${new Date(row.lastRunAt).toLocaleString()} · ${status}${counts}`;
  }

  const editing = typeof formMode === "number" ? rows.find((r) => r.id === formMode) : undefined;

  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-base font-semibold">
            {tc.heading} · {connection.name}
          </h3>
          <p className="text-sm text-muted-foreground">{tc.intro}</p>
        </div>
        {canWrite && formMode === "closed" && (
          <Button size="sm" onClick={() => setFormMode("create")}>
            {tc.add}
          </Button>
        )}
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      {formMode !== "closed" && (
        <CollectionForm
          connectionId={connection.id}
          collection={editing}
          onSaved={() => {
            setFormMode("closed");
            refresh();
          }}
          onCancel={() => setFormMode("closed")}
        />
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="border-b text-left text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">{tc.colName}</th>
              <th className="px-3 py-2 font-medium">{tc.colKind}</th>
              <th className="px-3 py-2 font-medium">{tc.colWhat}</th>
              <th className="px-3 py-2 font-medium">{tc.colWhen}</th>
              <th className="px-3 py-2 font-medium">{tc.colLastRun}</th>
              <th className="px-3 py-2 font-medium">{tc.colNextDue}</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-3 py-3 text-muted-foreground" colSpan={7}>
                  {tc.loading}
                </td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td className="px-3 py-3 text-muted-foreground" colSpan={7}>
                  {tc.empty}
                </td>
              </tr>
            )}
            {rows.map((row) => (
              <tr key={row.id} className={row.enabled ? "border-b last:border-0" : "border-b text-muted-foreground last:border-0"}>
                <td className="px-3 py-2">
                  {row.name}
                  {!row.enabled && <span className="ml-2 text-xs">({tc.disabled})</span>}
                </td>
                <td className="px-3 py-2">{tc.kinds[row.kind] ?? row.kind}</td>
                <td className="px-3 py-2 text-xs">{describeWhat(row)}</td>
                <td className="px-3 py-2 text-xs">{describeWhen(row)}</td>
                <td className="px-3 py-2 text-xs">{describeLastRun(row)}</td>
                <td className="px-3 py-2 text-xs">
                  {row.nextDueAt ? new Date(row.nextDueAt).toLocaleString() : "—"}
                </td>
                <td className="px-3 py-2">
                  {pendingDeleteId === row.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <span className="text-xs text-muted-foreground">{tc.deleteConfirm(row.name)}</span>
                      <Button variant="destructive" size="sm" disabled={busyId === row.id} onClick={() => handleDelete(row.id)}>
                        {t.settings.confirm}
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setPendingDeleteId(null)}>
                        {t.settings.cancel}
                      </Button>
                    </div>
                  ) : (
                    <div className="flex justify-end gap-2">
                      {canRun && row.kind !== "webhook" && (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={busyId === row.id || !row.enabled || !connection.isActive}
                          onClick={() => handleRun(row.id)}
                        >
                          {queuedId === row.id ? (
                            <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                          ) : (
                            <RefreshCw className="mr-1 h-3 w-3" />
                          )}
                          {queuedId === row.id ? tc.runQueued : tc.runNow}
                        </Button>
                      )}
                      {canWrite && (
                        <>
                          <Button variant="outline" size="sm" disabled={busyId === row.id} onClick={() => handleToggle(row)}>
                            {row.enabled ? tc.disable : tc.enable}
                          </Button>
                          <Button variant="outline" size="sm" onClick={() => setFormMode(row.id)}>
                            {tc.edit}
                          </Button>
                          <Button variant="destructive" size="sm" onClick={() => setPendingDeleteId(row.id)}>
                            {tc.delete}
                          </Button>
                        </>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface CollectionFormProps {
  connectionId: number;
  collection?: Collection;
  onSaved: () => void;
  onCancel: () => void;
}

function CollectionForm({ connectionId, collection, onSaved, onCancel }: CollectionFormProps) {
  const { t } = useLocale();
  const tf = t.collections.form;
  const tc = t.collections;

  const [sectionsAvailable, setSectionsAvailable] = useState<SectionInfo[]>([]);
  const [name, setName] = useState(collection?.name ?? "");
  const [kind, setKind] = useState<CollectionKind>(collection?.kind ?? "device_sweep");
  const [enabled, setEnabled] = useState(collection?.enabled ?? true);
  const [sections, setSections] = useState<string[]>(collection?.sections ?? []);
  const [selector, setSelector] = useState(collection?.selector ?? "");
  const [pageSize, setPageSize] = useState<string>(collection?.pageSize != null ? String(collection.pageSize) : "");
  const [quarantine, setQuarantine] = useState((collection?.quarantinedExtensionAttributes ?? []).join(", "));
  const [frequency, setFrequency] = useState<CollectionFrequency>(
    collection?.frequency ?? (collection?.kind === "catalog" ? "hourly" : "daily")
  );
  const [atHour, setAtHour] = useState<number>(collection?.atHour ?? 1);
  const [atMinute, setAtMinute] = useState<number>(collection?.atMinute ?? 0);
  const [weekday, setWeekday] = useState<number>(collection?.weekday ?? 0);
  const [intervalN, setIntervalN] = useState<number>(collection?.intervalN ?? 2);
  const [timezone, setTimezone] = useState(collection?.timezone ?? browserTimezone());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listJamfSections()
      .then((available) => {
        setSectionsAvailable(available);
        // A new device sweep or webhook starts with everything selected.
        if (!collection && sections.length === 0) setSections(available.map((s) => s.name));
      })
      .catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const scheduled = kind !== "webhook";
  const usesSections = kind !== "catalog";

  function toggleSection(sectionName: string) {
    setSections((current) =>
      current.includes(sectionName) ? current.filter((s) => s !== sectionName) : [...current, sectionName]
    );
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const input: CollectionInput = {
      name,
      kind,
      enabled,
      sections: usesSections ? sections : [],
      selector: kind === "device_sweep" && selector.trim() ? selector.trim() : null,
      pageSize: kind === "device_sweep" && pageSize.trim() ? Number(pageSize) : null,
      quarantinedExtensionAttributes: quarantine
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      frequency: scheduled ? frequency : null,
      intervalN: scheduled && frequency === "every_n_days" ? intervalN : null,
      atHour: scheduled && frequency !== "hourly" ? atHour : null,
      atMinute: scheduled ? atMinute : null,
      weekday: scheduled && frequency === "weekly" ? weekday : null,
      timezone: scheduled ? timezone : null
    };
    try {
      if (collection) await updateCollection(collection.id, input);
      else await createCollection(connectionId, input);
      onSaved();
    } catch (caught) {
      setError(caught instanceof ApiError && caught.detail ? caught.detail : tf.error);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 rounded-md border bg-background p-4">
      <h4 className="font-medium">{collection ? tf.editTitle : tf.createTitle}</h4>

      <div className="grid gap-4 md:grid-cols-2">
        <label className="space-y-1 text-sm">
          <span className="font-medium">{tf.name}</span>
          <input className={inputClasses} value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label className="space-y-1 text-sm">
          <span className="font-medium">{tf.kind}</span>
          <select
            className={inputClasses}
            value={kind}
            disabled={Boolean(collection)}
            onChange={(e) => {
              const next = e.target.value as CollectionKind;
              setKind(next);
              if (next === "catalog") setFrequency("hourly");
              if (next === "device_sweep" && frequency === "hourly") setFrequency("daily");
            }}
          >
            {(["device_sweep", "catalog", "webhook"] as CollectionKind[]).map((value) => (
              <option key={value} value={value}>
                {tc.kinds[value]}
              </option>
            ))}
          </select>
          <span className="block text-xs text-muted-foreground">{tf.kindHelp}</span>
        </label>
      </div>

      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        {tf.enabled}
      </label>

      {usesSections && (
        <fieldset className="space-y-2 text-sm">
          <div className="flex items-center justify-between">
            <legend className="font-medium">{tf.sections}</legend>
            <div className="flex gap-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setSections(sectionsAvailable.map((s) => s.name))}>
                {tf.selectAll}
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={() => setSections([])}>
                {tf.selectNone}
              </Button>
            </div>
          </div>
          <div className="grid gap-1 sm:grid-cols-2 md:grid-cols-3">
            {sectionsAvailable.map((section) => (
              <label key={section.name} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={sections.includes(section.name)}
                  onChange={() => toggleSection(section.name)}
                />
                <span>
                  {section.name}
                  <span className="ml-1 text-xs text-muted-foreground">({section.jamfSection})</span>
                </span>
              </label>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">{tf.sectionsHelp}</p>
        </fieldset>
      )}

      {kind === "device_sweep" && (
        <label className="block space-y-1 text-sm">
          <span className="font-medium">{tf.selector}</span>
          <div className="flex gap-2">
            {Object.entries(selectorPresets).map(([key, value]) => (
              <Button key={key} type="button" variant="outline" size="sm" onClick={() => setSelector(value)}>
                {tf.selectorPresets[key]}
              </Button>
            ))}
          </div>
          <input
            className={inputClasses}
            value={selector}
            onChange={(e) => setSelector(e.target.value)}
            placeholder="general.remoteManagement.managed==true"
          />
          <span className="block text-xs text-muted-foreground">{tf.selectorHelp}</span>
        </label>
      )}

      {kind === "device_sweep" && (
        <label className="block space-y-1 text-sm">
          <span className="font-medium">{tf.pageSize}</span>
          <input
            className={inputClasses}
            type="number"
            min={100}
            max={1000}
            step={50}
            value={pageSize}
            onChange={(e) => setPageSize(e.target.value)}
            placeholder={tf.pageSizePlaceholder}
          />
          <span className="block text-xs text-muted-foreground">{tf.pageSizeHelp}</span>
        </label>
      )}

      {usesSections && (
        <label className="block space-y-1 text-sm">
          <span className="font-medium">{tf.quarantine}</span>
          <input className={inputClasses} value={quarantine} onChange={(e) => setQuarantine(e.target.value)} placeholder="9, 22" />
          <span className="block text-xs text-muted-foreground">{tf.quarantineHelp}</span>
        </label>
      )}

      {scheduled && (
        <fieldset className="space-y-2 text-sm">
          <legend className="font-medium">{tf.schedule}</legend>
          <div className="grid gap-3 md:grid-cols-4">
            <label className="space-y-1">
              <span>{tf.frequency}</span>
              <select className={inputClasses} value={frequency} onChange={(e) => setFrequency(e.target.value as CollectionFrequency)}>
                {(["hourly", "daily", "weekly", "every_n_days"] as CollectionFrequency[]).map((value) => (
                  <option key={value} value={value}>
                    {tc.frequency[value]}
                  </option>
                ))}
              </select>
            </label>
            {frequency !== "hourly" && (
              <label className="space-y-1">
                <span>{tf.time}</span>
                <input
                  type="time"
                  className={inputClasses}
                  value={`${pad(atHour)}:${pad(atMinute)}`}
                  onChange={(e) => {
                    const [h, m] = e.target.value.split(":").map((v) => Number(v));
                    if (!Number.isNaN(h)) setAtHour(h);
                    if (!Number.isNaN(m)) setAtMinute(m);
                  }}
                />
              </label>
            )}
            {frequency === "hourly" && (
              <label className="space-y-1">
                <span>{tf.minute}</span>
                <input
                  type="number"
                  min={0}
                  max={59}
                  className={inputClasses}
                  value={atMinute}
                  onChange={(e) => setAtMinute(Number(e.target.value))}
                />
              </label>
            )}
            {frequency === "weekly" && (
              <label className="space-y-1">
                <span>{tf.weekday}</span>
                <select className={inputClasses} value={weekday} onChange={(e) => setWeekday(Number(e.target.value))}>
                  {tc.weekdays.map((label, index) => (
                    <option key={label} value={index}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {frequency === "every_n_days" && (
              <label className="space-y-1">
                <span>{tf.intervalN}</span>
                <input
                  type="number"
                  min={2}
                  className={inputClasses}
                  value={intervalN}
                  onChange={(e) => setIntervalN(Number(e.target.value))}
                />
              </label>
            )}
            <label className="space-y-1">
              <span>{tf.timezone}</span>
              <input className={inputClasses} value={timezone} onChange={(e) => setTimezone(e.target.value)} />
            </label>
          </div>
          <p className="text-xs text-muted-foreground">{tf.timezoneHelp}</p>
        </fieldset>
      )}

      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      <div className="flex gap-2">
        <Button type="submit" disabled={submitting}>
          {submitting ? tf.saving : tf.save}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel} disabled={submitting}>
          {tf.cancel}
        </Button>
      </div>
    </form>
  );
}
