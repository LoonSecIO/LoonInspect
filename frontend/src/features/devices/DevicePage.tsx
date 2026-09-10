import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { ApiError } from "@/config/api";
import { PATCH_STATE_COLORS } from "@/features/catalog/patchState";
import { DiffCell } from "@/features/changes/DiffCell";
import { getChangePolicy, listChanges } from "@/features/changes/api";
import { detailText, diffLines, labelsFromPolicy, whatOf, type LabelMap } from "@/features/changes/render";
import type { DeviceChange } from "@/features/changes/types";
import { getDevice } from "@/features/devices/api";
import { collectedNotOnPage } from "@/features/devices/ledgerSections";
import type { DeviceDetail, ExtensionAttribute, InstalledApp } from "@/features/devices/types";
import { AssessmentCell, CorpusBanner } from "@/features/vulnerabilities/AppAssessment";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";

/** Rows of the recent-changes block: unfiltered, the leading columns of
 *  `ix_device_changes_subject`, and the same three keys the footer link carries. */
const CHANGES_SHOWN = 25;
const SUBJECT_KIND = "computer";

/** "Problems first" is a judgment only `needsAttention.ts` may make by default; behind a
 *  toggle it is the operator's own act (#111). Behind, then ahead and unknown, then latest. */
const PATCH_ORDER: Record<string, number> = { behind: 0, ahead: 1, unknown: 2, latest: 3 };

type Result<T> = { state: "ready"; value: T } | { state: "failed"; notFound: boolean };

function formatInstant(value: string | null): string | null {
  return value ? new Date(value).toLocaleString() : null;
}

function formatDay(value: string | null): string {
  return value ? new Date(value).toLocaleDateString() : "—";
}

/**
 * One device, in full (#300): everything `GET /api/devices/{id}` already returned to
 * nobody. Zero backend files — the page reads what shipped, and says in words what it
 * does not have rather than showing a dash for it.
 *
 * Fetch state is keyed by what was asked for, and set only inside promise callbacks, so a
 * change of `:deviceId` reads as loading without a synchronous set-state in an effect.
 */
export function DevicePage() {
  const { t } = useLocale();
  const td = t.devices.detail;
  const tc = t.changes;
  const { deviceId } = useParams<{ deviceId: string }>();

  const [loaded, setLoaded] = useState<{ id: string; result: Result<DeviceDetail> } | null>(null);
  const [changesLoaded, setChangesLoaded] = useState<{ key: string; result: Result<DeviceChange[]> } | null>(null);
  const [labels, setLabels] = useState<LabelMap>({});
  const [orderByPatch, setOrderByPatch] = useState(false);

  useEffect(() => {
    if (!deviceId) return;
    let cancelled = false;
    getDevice(Number(deviceId))
      .then((device) => {
        if (!cancelled) setLoaded({ id: deviceId, result: { state: "ready", value: device } });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const notFound = error instanceof ApiError && error.status === 404;
        setLoaded({ id: deviceId, result: { state: "failed", notFound } });
      });
    return () => {
      cancelled = true;
    };
  }, [deviceId]);

  const current = loaded && loaded.id === deviceId ? loaded.result : null;
  const device = current?.state === "ready" ? current.value : null;
  const connectionId = device?.mdmConnectionId ?? null;
  const externalId = device?.externalId ?? null;
  const changesKey = connectionId === null || externalId === null ? null : `${connectionId}:${externalId}`;

  useEffect(() => {
    if (changesKey === null || connectionId === null || externalId === null) return;
    let cancelled = false;
    listChanges({ connectionId, subjectKind: SUBJECT_KIND, subjectId: externalId, pageSize: CHANGES_SHOWN })
      .then((response) => {
        if (!cancelled) setChangesLoaded({ key: changesKey, result: { state: "ready", value: response.items } });
      })
      .catch(() => {
        if (!cancelled) setChangesLoaded({ key: changesKey, result: { state: "failed", notFound: false } });
      });
    return () => {
      cancelled = true;
    };
  }, [changesKey, connectionId, externalId]);

  // Field labels for the change rows, as the Changes page reads them; a failure degrades
  // to raw field names, which is a fine answer.
  useEffect(() => {
    let cancelled = false;
    getChangePolicy()
      .then((policy) => {
        if (!cancelled) setLabels(labelsFromPolicy(policy));
      })
      .catch(() => {
        /* raw field names are a fine answer */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Name ascending by default, and the patch-state order only when the reader asks for it.
  const apps = useMemo(() => {
    const rows = [...(device?.apps ?? [])];
    rows.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
    if (orderByPatch) {
      rows.sort((a, b) => (PATCH_ORDER[a.patchState ?? ""] ?? 4) - (PATCH_ORDER[b.patchState ?? ""] ?? 4));
    }
    return rows;
  }, [device?.apps, orderByPatch]);

  const sectionLabels = useMemo(
    () => ({
      section: (name: string) => tc.sections[name] ?? name,
      entryKind: (kind: string) => tc.entryKinds[kind] ?? kind
    }),
    [tc]
  );

  if (!deviceId) return null;

  if (current === null) {
    return <p className="text-sm text-muted-foreground">{td.loading}</p>;
  }

  if (current.state === "failed" || device === null) {
    return (
      <section className="space-y-3">
        <p className="text-sm text-destructive">{current.state === "failed" && current.notFound ? td.notFound : td.errorLoading}</p>
        <Link to="/devices" className="text-sm underline underline-offset-4">
          {td.back}
        </Link>
      </section>
    );
  }

  const changes = changesLoaded && changesLoaded.key === changesKey ? changesLoaded.result : null;
  const changeRows = changes?.state === "ready" ? changes.value : [];
  const latestChange = changeRows[0] ?? null;
  const allChangesHref =
    changesKey === null
      ? null
      : `/devices/changes?${new URLSearchParams({
          connectionId: String(connectionId),
          subjectKind: SUBJECT_KIND,
          subjectId: externalId ?? ""
        }).toString()}`;

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">
          <Link to="/devices" className="hover:underline">
            {t.devices.title}
          </Link>
        </p>
        <h1 className="text-3xl font-bold tracking-tight">{device.hostname}</h1>
        <p className="mt-1 font-mono text-sm text-muted-foreground">{td.subtitle(device.serialNumber, device.externalId)}</p>
      </div>

      {/* Three clocks, each labelled with whose clock it is. Stale data misread as current
          is the fastest route to a wrong conclusion, so this is the first band. A null
          renders its sentence, never a dash. */}
      <div className="grid gap-3 sm:grid-cols-3">
        <Clock label={td.clocks.inventory} value={formatInstant(device.lastInventoryAt)} none={td.clocks.inventoryNone} />
        <Clock label={td.clocks.checkIn} value={formatInstant(device.lastCheckIn)} none={td.clocks.checkInNone} />
        <Clock label={td.clocks.seen} value={formatInstant(device.lastSeenAt)} none={td.clocks.seenNone} />
      </div>

      {/* "Recorded", not "changed": the policy filters at write time, so a digest can move
          with no row behind it, and the page must not claim a precision it does not have. */}
      <p className="text-sm text-muted-foreground" title={td.recordedNote}>
        {changes === null && changesKey !== null
          ? td.changes.loading
          : changes?.state === "failed"
            ? td.changes.errorLoading
            : latestChange
              ? td.lastRecordedChange(new Date(latestChange.observedAt).toLocaleString(), tc.levels[latestChange.level] ?? latestChange.level)
              : td.noRecordedChange}
      </p>

      <Placement device={device} td={td} t={t} />

      <section className="space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-lg font-semibold">
            {td.apps.heading} <span className="text-sm font-normal text-muted-foreground">{td.apps.count(device.apps.length)}</span>
          </h2>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={orderByPatch} onChange={(event) => setOrderByPatch(event.target.checked)} />
            {td.apps.orderByPatch}
          </label>
        </div>
        <CorpusBanner corpusAsOf={device.corpusAsOf} t={t} />
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                <th className="px-4 py-2 font-medium">{td.apps.colName}</th>
                <th className="px-4 py-2 font-medium">{td.apps.colVersion}</th>
                <th className="px-4 py-2 font-medium">{td.apps.colJamfPatch}</th>
                <th className="px-4 py-2 font-medium">{td.apps.colLoonInspect}</th>
                <th className="px-4 py-2 font-medium">{td.apps.colBundleId}</th>
              </tr>
            </thead>
            <tbody>
              {apps.length === 0 && (
                <tr>
                  <td className="px-4 py-4 text-muted-foreground" colSpan={5}>
                    {td.apps.empty}
                  </td>
                </tr>
              )}
              {apps.map((app) => (
                <tr key={app.id} className="border-b align-top last:border-0">
                  <td className="px-4 py-2 font-medium">{app.name}</td>
                  <td className="px-4 py-2 tabular-nums">
                    {app.version}
                    {app.shortVersion && app.shortVersion !== app.version ? (
                      <span className="text-muted-foreground"> ({app.shortVersion})</span>
                    ) : null}
                  </td>
                  <td className="px-4 py-2">
                    <PatchCell app={app} t={t} />
                  </td>
                  <td className="px-4 py-2">
                    <AssessmentCell vuln={app.vuln} t={t} />
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{app.bundleId}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">
          {td.eas.heading}{" "}
          <span className="text-sm font-normal text-muted-foreground">{td.eas.count(device.extensionAttributes.length)}</span>
        </h2>
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                <th className="px-4 py-2 font-medium">{td.eas.colDefinition}</th>
                <th className="px-4 py-2 font-medium">{td.eas.colValues}</th>
                <th className="px-4 py-2 font-medium">{td.eas.colSource}</th>
                <th className="px-4 py-2 font-medium">{td.eas.colEnabled}</th>
              </tr>
            </thead>
            <tbody>
              {device.extensionAttributes.length === 0 && (
                <tr>
                  <td className="px-4 py-4 text-muted-foreground" colSpan={4}>
                    {td.eas.empty}
                  </td>
                </tr>
              )}
              {device.extensionAttributes.map((ea) => (
                <ExtensionAttributeRow key={`${ea.definitionId}:${ea.source}`} ea={ea} td={td} />
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-lg font-semibold">{td.changes.heading}</h2>
          {allChangesHref && (
            <Link to={allChangesHref} className="text-sm underline decoration-dotted underline-offset-4 hover:decoration-solid">
              {td.changes.all}
            </Link>
          )}
        </div>
        <p className="text-sm text-muted-foreground">{td.changes.caption}</p>
        {changesKey === null ? (
          <p className="text-sm text-muted-foreground">{td.changes.noConnection}</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border bg-card">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                <tr>
                  <th className="px-4 py-2 font-medium">{tc.colWhen}</th>
                  <th className="px-4 py-2 font-medium">{tc.colWhat}</th>
                  <th className="px-4 py-2 font-medium">{tc.colChange}</th>
                  <th className="px-4 py-2 font-medium">{tc.colWhatChanged}</th>
                  <th className="px-4 py-2 font-medium">{tc.level}</th>
                </tr>
              </thead>
              <tbody>
                {changes === null && (
                  <tr>
                    <td className="px-4 py-4 text-muted-foreground" colSpan={5}>
                      {td.changes.loading}
                    </td>
                  </tr>
                )}
                {changes?.state === "failed" && (
                  <tr>
                    <td className="px-4 py-4 text-destructive" colSpan={5}>
                      {td.changes.errorLoading}
                    </td>
                  </tr>
                )}
                {changes?.state === "ready" && changeRows.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-muted-foreground" colSpan={5}>
                      {td.changes.empty}
                    </td>
                  </tr>
                )}
                {changeRows.map((row) => {
                  const what = whatOf(row, labels, sectionLabels);
                  const detail = detailText(row, tc);
                  return (
                    <tr key={row.id} className="border-b align-top last:border-0">
                      <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">
                        {new Date(row.observedAt).toLocaleString()}
                      </td>
                      <td className="px-4 py-2">
                        <div className="text-xs text-muted-foreground">{what.head}</div>
                        {what.identity && <div>{what.identity}</div>}
                        {detail && <div className="text-xs text-muted-foreground">{detail}</div>}
                      </td>
                      <td className="px-4 py-2">{tc.changeKinds[row.change] ?? row.change}</td>
                      <td className="px-4 py-2">
                        <DiffCell lines={diffLines(row, labels)} />
                      </td>
                      <td className="px-4 py-2">
                        <span
                          className={
                            row.level === "high" ? "font-medium text-destructive" : row.level === "low" ? "text-muted-foreground" : ""
                          }
                        >
                          {tc.levels[row.level] ?? row.level}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Named from the wire's own registry (`ledgerSections.ts` mirrors `SECTION_WRAPPERS`,
          pinned by a backend test), so this list and the Splunk event enumerate identically. */}
      <footer className="rounded-lg border bg-card p-4 text-sm">
        <p className="font-medium">{td.collected.heading}</p>
        <p className="mt-1 text-muted-foreground">{collectedNotOnPage().map((section) => tc.sections[section] ?? section).join(" · ")}</p>
        <p className="mt-1 text-xs text-muted-foreground">{td.collected.body}</p>
      </footer>
    </section>
  );
}

function Clock({ label, value, none }: { label: string; value: string | null; none: string }) {
  return (
    <div className="rounded-lg border bg-card px-4 py-3">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={`mt-1 text-sm ${value === null ? "text-muted-foreground" : "font-medium"}`}>{value ?? none}</p>
    </div>
  );
}

/** The id-vs-name distinction the endpoint deliberately carries: the id is what Jamf put
 *  on the device, the name is resolved from the connection's catalog and is null until
 *  that catalog has been read — never the id in disguise. */
function orgUnit(name: string | null, id: string | null, td: Translations["devices"]["detail"]): string {
  if (name) return name;
  if (id) return td.placement.nameNotRead(id);
  return td.placement.notSet;
}

function Placement({ device, td, t }: { device: DeviceDetail; td: Translations["devices"]["detail"]; t: Translations }) {
  const yesNo = (value: boolean | null) => (value === null ? td.placement.notRead : value ? t.devices.yes : t.devices.no);
  const facts: [string, string][] = [
    [td.placement.managed, yesNo(device.managed)],
    [td.placement.supervised, yesNo(device.supervised)],
    [td.placement.osVersion, device.osVersion ?? td.placement.notRead],
    [td.placement.site, device.site ?? td.placement.notSet],
    [td.placement.building, orgUnit(device.building, device.buildingId, td)],
    [td.placement.department, orgUnit(device.department, device.departmentId, td)]
  ];
  return (
    <section className="space-y-2">
      <h2 className="text-lg font-semibold">{td.placement.heading}</h2>
      <dl className="grid gap-x-6 gap-y-2 rounded-lg border bg-card p-4 text-sm sm:grid-cols-3">
        {facts.map(([label, value]) => (
          <div key={label}>
            <dt className="text-xs text-muted-foreground">{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

/** #68's sentence from stored columns: a date and a count, never a day count. */
function PatchCell({ app, t }: { app: InstalledApp; t: Translations }) {
  const td = t.devices.detail;
  if (!app.patchState) return <span className="text-muted-foreground">{td.apps.noTitle}</span>;
  const stateLabels: Record<string, string> = {
    latest: t.catalog.stateLatest,
    behind: t.catalog.stateBehind,
    ahead: t.catalog.stateAhead,
    unknown: t.catalog.stateUnknown
  };
  const titleId = app.jamfTitleIds?.[0] ?? null;
  return (
    <div className="space-y-0.5">
      <span className="inline-flex items-center gap-1.5">
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: PATCH_STATE_COLORS[app.patchState] }} />
        {stateLabels[app.patchState] ?? app.patchState}
      </span>
      {app.patchAvailable && (
        <span className="block text-xs text-muted-foreground">
          {t.catalog.behindSince(formatDay(app.patchAvailableSince), app.releasesMissed)}
        </span>
      )}
      {app.latestVersion && <span className="block text-xs text-muted-foreground">{td.apps.latest(app.latestVersion)}</span>}
      {titleId && (
        <Link to={`/devices/applications/jamf-patch/${titleId}`} className="block text-xs underline decoration-dotted underline-offset-4 hover:decoration-solid">
          {td.apps.titleLink}
        </Link>
      )}
    </div>
  );
}

function ExtensionAttributeRow({ ea, td }: { ea: ExtensionAttribute; td: Translations["devices"]["detail"] }) {
  return (
    <tr className="border-b align-top last:border-0">
      <td className="px-4 py-2">
        {ea.name ?? <span className="font-mono text-xs">{ea.definitionId}</span>}
        {ea.name === null && <span className="ml-1 text-xs text-muted-foreground">({td.eas.noName})</span>}
      </td>
      <td className="px-4 py-2 break-words">
        {ea.values.length === 0 ? <span className="text-muted-foreground">{td.eas.noValue}</span> : ea.values.join(", ")}
      </td>
      <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{ea.source}</td>
      <td className="px-4 py-2">
        {ea.enabled === false ? (
          <span className="text-destructive">{td.eas.disabled}</span>
        ) : ea.enabled === true ? (
          td.eas.enabled
        ) : (
          <span className="text-muted-foreground">{td.eas.unknownEnabled}</span>
        )}
      </td>
    </tr>
  );
}
