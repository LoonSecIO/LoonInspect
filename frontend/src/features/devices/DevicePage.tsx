import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { ExternalLink } from "@/components/ui/external-link";
import { Button } from "@/components/ui/button";
import { useAuthStore, useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { ApiError } from "@/config/api";
import { PatchAnswerCell } from "@/features/catalog/PatchAnswerCell";
import { DiffCell } from "@/features/changes/DiffCell";
import { getChangePolicy, listChanges } from "@/features/changes/api";
import { detailText, diffLines, labelsFromPolicy, whatOf, type LabelMap } from "@/features/changes/render";
import type { DeviceChange } from "@/features/changes/types";
import { getDevice, refreshDevice } from "@/features/devices/api";
import { departureState, leavesTheFleetAt } from "@/features/devices/departure";
import { collectedNotOnPage } from "@/features/devices/ledgerSections";
import { DeviceHistoryCard } from "@/features/devices/DeviceHistoryCard";
import { ObservationBlock } from "@/features/devices/ObservationBlock";
import type { DeviceDetail, ExtensionAttribute } from "@/features/devices/types";
import { AssessmentCell, CorpusBanner } from "@/features/vulnerabilities/AppAssessment";
import { rollUpDeviceApps } from "@/features/vulnerabilities/deviceRollup";
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

/**
 * One device, with current inventory, history and a targeted refresh from Jamf.
 *
 * Fetch state is keyed by what was asked for, and set only inside promise callbacks, so a
 * change of `:deviceId` reads as loading without a synchronous set-state in an effect.
 */
export function DevicePage() {
  const user = useAuthStore((state) => state.user);
  const { deviceId } = useParams<{ deviceId: string }>();
  return (
    <DevicePageContent key={`${user?.tenant?.id}:${user?.id}:${deviceId}`} />
  );
}

function DevicePageContent() {
  const { t } = useLocale();
  const td = t.devices.detail;
  const tc = t.changes;
  const { deviceId } = useParams<{ deviceId: string }>();

  const canSync = useHasPermission(PERMISSIONS.DEVICE_SYNC);
  const [revision, setRevision] = useState(0);
  const [updating, setUpdating] = useState(false);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [updateOutcome, setUpdateOutcome] = useState<string | null>(null);
  const readKey = `${deviceId}:${revision}`;

  const [loaded, setLoaded] = useState<{ id: string; result: Result<DeviceDetail> } | null>(null);
  const [changesLoaded, setChangesLoaded] = useState<{ key: string; result: Result<DeviceChange[]> } | null>(null);
  const [labels, setLabels] = useState<LabelMap>({});
  const [orderByPatch, setOrderByPatch] = useState(false);
  const [eaFilter, setEaFilter] = useState("");
  const [eaColumns, setEaColumns] = useState({ id: true, source: false, enabled: false });

  useEffect(() => {
    if (!deviceId) return;
    let cancelled = false;
    getDevice(Number(deviceId))
      .then((device) => {
        if (!cancelled) setLoaded({ id: readKey, result: { state: "ready", value: device } });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const notFound = error instanceof ApiError && error.status === 404;
        setLoaded({ id: readKey, result: { state: "failed", notFound } });
      });
    return () => {
      cancelled = true;
    };
  }, [deviceId, readKey]);

  const current = loaded && loaded.id === readKey ? loaded.result : null;
  const device = current?.state === "ready" ? current.value : null;
  const connectionId = device?.mdmConnectionId ?? null;
  const externalId = device?.externalId ?? null;
  const changesKey = connectionId === null || externalId === null ? null : `${connectionId}:${externalId}:${revision}`;

  async function updateDevice() {
    if (!device || updating) return;
    setUpdating(true);
    setUpdateError(null);
    setUpdateOutcome(null);
    try {
      const result = await refreshDevice(device.id);
      setUpdateOutcome(result.outcome);
      setRevision((value) => value + 1);
    } catch (error) {
      setUpdateError(
        error instanceof ApiError && error.detail
          ? error.detail
          : td.updateFailed,
      );
    } finally {
      setUpdating(false);
    }
  }

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

  // #535: the three numbers over the rows this page already holds — arithmetic, not a
  // request — and null when nothing is answering, where the banner alone already speaks.
  const vulnApps = useMemo(() => rollUpDeviceApps(device?.apps ?? []), [device?.apps]);

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

  const filteredAttributes = device.extensionAttributes.filter((ea) =>
    `${ea.name ?? ""} ${ea.definitionId} ${ea.values[0] ?? ""}`.toLowerCase().includes(eaFilter.toLowerCase())
  );
  const eaColumnCount = 2 + Object.values(eaColumns).filter(Boolean).length;
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
        <p className="mt-1 font-mono text-sm text-muted-foreground">
          {device.serialNumber} ·{" "}
          {device.jamfUrl ? (
            <ExternalLink href={device.jamfUrl}>
              {td.jamfComputer(device.externalId)}
            </ExternalLink>
          ) : (
            td.jamfComputer(device.externalId)
          )}
        </p>
        {canSync &&
          device.mdmProvider === "jamf" &&
          device.mdmConnectionId !== null &&
          device.platform === "macos" && (
            <div className="mt-3 space-y-2">
              <Button
                variant="outline"
                disabled={updating}
                onClick={() => void updateDevice()}
              >
                {updating ? td.updating : td.updateDevice}
              </Button>
              <p className="text-xs text-muted-foreground">{td.updateHint}</p>
              {updateError && (
                <p role="alert" className="text-sm text-destructive">
                  {updateError}
                </p>
              )}
              {updateOutcome && (
                <p role="status" className="text-sm text-muted-foreground">
                  {updateOutcome === "stale"
                    ? td.updateStale
                    : td.updateSucceeded}
                </p>
              )}
            </div>
          )}
      </div>

      <DepartureNote departedAt={device.departedAt} td={td} />

      {/* Four clocks, each labelled with whose clock it is. Stale data misread as current
          is the fastest route to a wrong conclusion, so this is the first band. A null
          renders its sentence, never a dash. */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Clock label={td.clocks.inventory} value={formatInstant(device.lastInventoryAt)} none={td.clocks.inventoryNone} />
        <Clock label={td.clocks.checkIn} value={formatInstant(device.lastCheckIn)} none={td.clocks.checkInNone} />
        <Clock label={td.clocks.seen} value={formatInstant(device.lastSeenAt)} none={td.clocks.seenNone} />
        <Clock label={td.clocks.findings} value={formatInstant(device.findingsReconciledAt)} none={td.clocks.findingsNone} />
      </div>

      {/* "Recorded", not "changed": the policy filters at write time, so a digest can move
          with no row behind it, and the page must not claim a precision it does not have.
          Dated by when it was recorded (#645): the Mac's report clock does not move when
          Jamf's record changes without a new inventory report. */}
      <p className="text-sm text-muted-foreground" title={td.recordedNote}>
        {changes === null && changesKey !== null
          ? td.changes.loading
          : changes?.state === "failed"
            ? td.changes.errorLoading
            : latestChange
              ? td.lastRecordedChange(new Date(latestChange.collectedAt).toLocaleString(), tc.levels[latestChange.level] ?? latestChange.level)
              : td.noRecordedChange}
      </p>

      <DeviceHistoryCard key={revision} deviceId={device.id} />

      <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">{t.deviceHistory.latestInventory}</p>
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
        {/* Beside the banner, because one date governs both: the Mac's own line, in apps.
            Nothing at all under `off` — the banner has just said there is no corpus and no
            date, and three zeros beneath it would be arguing with it. */}
        {vulnApps && (
          <p className="text-sm text-muted-foreground">
            {td.apps.vulnRollup(vulnApps.withFindings, vulnApps.onKev, vulnApps.outsideCorpus)}
          </p>
        )}
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
                    {/* #313: state, #68's sentence, the latest version and the titles by
                        name — each half naming its title when several matched. */}
                    <PatchAnswerCell answer={app} t={t} showLatest showTitles none={td.apps.noTitle} />
                  </td>
                  <td className="px-4 py-2">
                    {/* #482: and what updating to the version the cell left of this one
                        names would do to those findings. */}
                    <AssessmentCell vuln={app.vuln} t={t} row={app} />
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
        <div className="flex flex-wrap items-center gap-3">
          <input type="search" value={eaFilter} onChange={(event) => setEaFilter(event.target.value)}
            aria-label={td.eas.filter} placeholder={td.eas.filter} className="min-w-0 rounded border bg-background px-3 py-2 text-sm" />
          <details className="text-sm">
            <summary className="cursor-pointer">{td.eas.columns}</summary>
            <div className="flex flex-wrap gap-3 py-2">
              {([['id', 'ID'], ['source', td.eas.colSource], ['enabled', td.eas.colEnabled]] as const).map(([key, label]) => (
                <label key={key} className="flex items-center gap-1">
                  <input type="checkbox" checked={eaColumns[key]} onChange={(event) => setEaColumns((held) => ({...held, [key]: event.target.checked}))} />
                  {label}
                </label>
              ))}
            </div>
          </details>
        </div>
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table aria-label={td.eas.heading} className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                <th className="px-4 py-2 font-medium">{td.eas.colDefinition}</th>
                <th className="px-4 py-2 font-medium">{td.eas.colValues}</th>
                {eaColumns.id && <th className="px-4 py-2 font-medium">ID</th>}
                {eaColumns.source && <th className="px-4 py-2 font-medium">{td.eas.colSource}</th>}
                {eaColumns.enabled && <th className="px-4 py-2 font-medium">{td.eas.colEnabled}</th>}
              </tr>
            </thead>
            <tbody>
              {filteredAttributes.length === 0 && (
                <tr>
                  <td className="px-4 py-4 text-muted-foreground" colSpan={eaColumnCount}>
                    {eaFilter ? td.eas.noMatches : td.eas.empty}
                  </td>
                </tr>
              )}
              {filteredAttributes.map((ea) => (
                <ExtensionAttributeRow key={`${ea.definitionId}:${ea.source}`} ea={ea} td={td} columns={eaColumns} />
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
                  {/* The collection clock, not the Changes page's Observed (#645): a row is dated by
                      when this pod recorded it; the Mac's report time rides the cell's tooltip. */}
                  <th className="px-4 py-2 font-medium">{td.changes.colCollected}</th>
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
                      <td
                        className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground"
                        title={td.changes.observedTitle(new Date(row.observedAt).toLocaleString())}
                      >
                        {new Date(row.collectedAt).toLocaleString()}
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

      {/* What the ledger holds, section by section, lazily (#368). */}
      <ObservationBlock key={revision} deviceId={device.id} />

      {/* Named from the wire's own registry (`ledgerSections.ts` mirrors `SECTION_WRAPPERS`,
          pinned by a backend test), so this list and the Splunk event enumerate identically.
          Empty since #368 renders every section above, and hidden then; a fifteenth wire
          section reappears here until its block exists. */}
      {collectedNotOnPage().length > 0 && (
        <footer className="rounded-lg border bg-card p-4 text-sm">
          <p className="font-medium">{td.collected.heading}</p>
          <p className="mt-1 text-muted-foreground">{collectedNotOnPage().map((section) => tc.sections[section] ?? section).join(" · ")}</p>
          <p className="mt-1 text-xs text-muted-foreground">{td.collected.body}</p>
        </footer>
      )}
    </section>
  );
}

/** "Not returned by Jamf since ⟨date⟩; leaves the fleet on ⟨date⟩" — the tail on the page it is about
 *  (#475), above the clocks. Nothing for the Macs Jamf still returns; past the tail the sentence
 *  changes rather than going, because this page is reachable by id whatever the list answers. */
function DepartureNote({ departedAt, td }: { departedAt: string | null; td: Translations["devices"]["detail"] }) {
  const state = departureState(departedAt, new Date());
  if (departedAt === null || state === "present") return null;
  // An instant this page cannot read is no sentence it can write — both halves are dates, and
  // "Invalid Date" is not one. The list's chip still says so. A guard: the API ships ISO-8601.
  const departed = new Date(departedAt);
  if (Number.isNaN(departed.getTime())) return null;
  const since = departed.toLocaleDateString();
  const leaves = leavesTheFleetAt(departedAt).toLocaleDateString();
  return (
    <p className="rounded-lg border border-dashed px-4 py-3 text-sm">
      {state === "left" ? td.departure.left(since) : td.departure.inTail(since, leaves)}
    </p>
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

function ExtensionAttributeRow({ ea, td, columns }: { ea: ExtensionAttribute; td: Translations["devices"]["detail"]; columns: { id: boolean; source: boolean; enabled: boolean } }) {
  return (
    <tr className="border-b align-top last:border-0">
      <td className="px-4 py-2">
        {ea.name ?? <span className="font-mono text-xs">{ea.definitionId}</span>}
        {ea.name === null && <span className="ml-1 text-xs text-muted-foreground">({td.eas.noName})</span>}
      </td>
      <td className="px-4 py-2 break-words">
        {ea.values.length === 0 ? <span className="text-muted-foreground">{td.eas.noValue}</span> : ea.values[0]}
      </td>
      {columns.id && <td className="px-4 py-2 font-mono text-xs">{ea.definitionId}</td>}
      {columns.source && <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{ea.source}</td>}
      {columns.enabled && <td className="px-4 py-2">
        {ea.enabled === false ? (
          <span className="text-destructive">{td.eas.disabled}</span>
        ) : ea.enabled === true ? (
          td.eas.enabled
        ) : (
          <span className="text-muted-foreground">{td.eas.unknownEnabled}</span>
        )}
      </td>}
    </tr>
  );
}
