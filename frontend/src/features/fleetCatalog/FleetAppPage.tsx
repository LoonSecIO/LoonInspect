import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useParams } from "react-router";
import { ArrowLeft } from "lucide-react";
import { ApiError } from "@/config/api";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "@/components/ui/external-link";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { useLocale } from "@/i18n/LocaleContext";
import { FleetTitleHistory } from "./FleetTitleHistory";
import { FleetPilotGuide } from "./FleetPilotGuide";
import { BuildEvidence, FleetTargetComparison } from "./FleetTargetComparison";
import { FleetOperatorNotes } from "./FleetOperatorNotes";
import { fleetDetailScope, getFleetDetail } from "./detailApi";
import { portfolioCopy } from "./portfolioCopy";
import { fleetDetailCopy } from "./fleetDetailCopy";
import type { MigrationDetail } from "./migrationTypes";

const BASE = "/devices/applications/fleet-catalog";
const internalLink = "text-sm font-medium text-primary underline decoration-primary/40 underline-offset-4 hover:decoration-primary";

type Context = { kind: "apps" | "titles"; id: string; scope: string; search: string };

function InstalledVersions({ data }: { data: MigrationDetail }) {
  const { locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const [selectedVersion, setSelectedVersion] = useState<string | null>(null);
  const versions = [...new Set(data.builds.map(build => build.version))];
  const rows = selectedVersion === null ? data.builds : data.builds.filter(build => build.version === selectedVersion);
  const high = Math.max(1, ...data.builds.map(build => build.macs));
  const names = new Map(data.items.map(item => [item.appHash, item.name]));
  return (
    <section className="space-y-3 rounded-xl border bg-card p-5">
      <h3 className="text-lg font-semibold">{c.installed}</h3>
      {!data.builds.length ? <p className="text-sm text-muted-foreground">{c.noBuilds}</p> : <>
        {versions.length > 1 && <label className="inline-flex flex-wrap items-center gap-2 text-sm">
          {c.filterVersion}
          <select className="rounded-md border bg-background px-2 py-1" value={selectedVersion === null ? "" : String(versions.indexOf(selectedVersion))}
            onChange={event => setSelectedVersion(event.target.value === "" ? null : versions[Number(event.target.value)])}>
            <option value="">{c.allVersions}</option>
            {versions.map((version, index) => <option key={version} value={String(index)}>{version || c.unknown}</option>)}
          </select>
        </label>}
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b text-xs text-muted-foreground"><tr>
              <th className="py-2 pr-3" scope="col">{c.version}</th>
              <th className="py-2" scope="col">{c.count}</th>
            </tr></thead>
            <tbody>{rows.map(build => <tr key={`${build.appHash}:${build.versionHash}`} className="border-b last:border-0">
              <td className="py-2 pr-3"><strong>{build.version || c.unknown}</strong>
                {build.shortVersion && build.version !== build.shortVersion && <small className="ml-2 text-muted-foreground">({build.shortVersion})</small>}
                {data.title && data.items.length > 1 && <small className="block text-muted-foreground">{names.get(build.appHash)}</small>}
              </td>
              <td className="w-1/2 py-2"><div className="flex items-center gap-2"><span className="w-10 shrink-0 tabular-nums">{build.macs}</span>
                <span aria-hidden="true" className="h-2 rounded-r-sm bg-[#2a78d6] dark:bg-[#3987e5]" style={{ width: `${build.macs * 75 / high}%` }} /></div>
              </td>
            </tr>)}</tbody>
          </table>
        </div>
        <p className="text-xs text-muted-foreground">{c.countNote}</p>
      </>}
      <div className="border-t pt-3 text-sm">
        {locale === "de" ? `${data.observedChanges.versionChanges} beobachtete Versionswechsel auf ${data.observedChanges.macs} Macs in den letzten ${data.observedChanges.windowDays} Tagen.`
          : `${data.observedChanges.versionChanges} observed version changes across ${data.observedChanges.macs} Macs in the last ${data.observedChanges.windowDays} days.`}
        {data.observedChanges.lastAt && <span className="ml-1 text-muted-foreground">
          {locale === "de" ? "Zuletzt beobachtet" : "Last observed"} {new Date(data.observedChanges.lastAt).toLocaleDateString(locale)}.
        </span>}
        <p className="mt-3 font-medium">{c.adoptionLag}</p>
        <p>{data.observedChanges.medianDaysAfterFleetPublication != null && data.observedChanges.adoptionSamples > 0
          ? c.lagResult(data.observedChanges.medianDaysAfterFleetPublication.toLocaleString(locale), data.observedChanges.adoptionSamples) : c.noLag}</p>
        <p className="mt-1 text-xs text-muted-foreground">{c.lagNote}</p>
      </div>
    </section>
  );
}

function InstalledFindings({ data }: { data: MigrationDetail }) {
  const { locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const identities = data.item ? [data.item] : data.items;
  if (!identities.length) return null;
  return <section className="space-y-3 rounded-xl border bg-card p-5">
    <h3 className="text-lg font-semibold">{c.installedFindings}</h3>
    {identities.map(item => {
      const evidence = data.installedEvidence?.[item.appHash];
      return <div key={item.appHash} className="space-y-2 border-t pt-2">
        {identities.length > 1 && <h4 className="text-sm font-medium">{item.name}</h4>}
        {evidence && evidence.assessedBuilds > 0 ? <>
          {evidence.asOf && <p className="text-xs text-muted-foreground">{c.corpus} {evidence.asOf}</p>}
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-5">{([
            [c.covered, evidence.assessedBuilds], [c.uncovered, evidence.unknownBuilds], [c.affected, evidence.affectedBuilds],
            [c.highCritical, evidence.highOrCriticalBuilds], [c.exploited, evidence.kevBuilds]
          ] as const).map(([label, count]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="font-semibold tabular-nums">{count}</dd></div>)}</dl>
        </> : <p className="text-sm text-muted-foreground">{c.missingCorpus} {evidence && evidence.unknownBuilds > 0 && `(${c.uncovered} · ${evidence.unknownBuilds})`}</p>}
      </div>;
    })}
  </section>;
}

function DetailBody({ data, context, onHistoryRead }: { data: MigrationDetail; context: Context; onHistoryRead: () => void }) {
  const { locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const canRead = useHasPermission(PERMISSIONS.PATCH_CATALOG_SYNC);
  const [target, setTarget] = useState<string | null>(null);
  const comparison = useRef<HTMLDivElement>(null);
  const local = data.item;
  const candidate = data.title ?? (local?.match === "exact" ? local.fleetCandidates[0] : undefined);
  const name = local?.name || data.title?.name;
  const bundle = local?.bundleId || data.title?.bundleId || "";
  const text = !local ? c.catalogFirst : ({ exact: c.exact, ambiguous: c.ambiguous, none: c.noMatch, unknown: c.catalogUnknown })[local.match];
  const ambiguous = local?.match === "ambiguous" || data.items.some(item => item.match === "ambiguous");
  const assessment = local ? data.appAssessments[local.appHash] : candidate ? data.assessments[candidate.slug] : undefined;
  const when = data.scope.days === null ? c.allDates : `${data.scope.clock === "contact" ? c.contact : c.inventory} · ${c.days(data.scope.days)}`;
  const chosenVersion = target ?? candidate?.latestVersion;
  const choose = (version: string) => {
    setTarget(version);
    comparison.current?.scrollIntoView?.({ block: "start" });
    comparison.current?.focus({ preventScroll: true });
  };
  return <div className="space-y-4">
    <header className="rounded-xl border bg-card p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h2 className="break-words text-2xl font-semibold">{name}</h2>
          <p className="mt-1 break-all font-mono text-sm text-muted-foreground">{bundle || c.bundleMissing}</p>
        </div>
        {candidate && <ExternalLink className="text-sm" href={`https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/outputs/${encodeURIComponent(candidate.slug)}/darwin.json`}>{c.source}</ExternalLink>}
      </div>
      <p className="mt-3 text-sm">{c.footprint(data.installedMacs, data.scope.activeMacs)} {text}</p>
      {data.impact && data.installedMacs > 0 && <p className="mt-2 text-sm">{data.impact.olderMacs
        ? c.pilotBelow(data.impact.olderMacs, data.impact.targetVersion)
        : data.impact.unknownMacs ? c.checkUnknown : c.monitorCurrent}</p>}
      {assessment && <p className="mt-2 text-sm font-medium">{assessment.reason}</p>}
      {!local && ambiguous && <p className="mt-2 text-sm">{c.ambiguous}</p>}
      <dl className="mt-4 grid grid-cols-2 gap-x-5 gap-y-3 border-t pt-3 sm:grid-cols-3">
        <div><dt className="text-xs text-muted-foreground">{c.matches}</dt><dd className="text-2xl font-semibold tabular-nums">{data.installedMacs}</dd></div>
        {candidate && <div><dt className="text-xs text-muted-foreground">{c.fleetLatest}</dt><dd className="text-xl font-medium">{candidate.latestVersion}</dd></div>}
        <div><dt className="text-xs text-muted-foreground">{c.asOf}</dt><dd className="pt-1 text-sm">{new Date(data.asOf).toLocaleDateString(locale)} · {when}
          {data.scope.connectionId !== null && <small className="block text-muted-foreground">{locale === "de" ? "Jamf-Verbindung" : "Jamf connection"} #{data.scope.connectionId}</small>}
        </dd></div>
      </dl>
    </header>

    {local && local.match === "ambiguous" && local.fleetCandidates.length > 0 && (
      <section className="space-y-2 rounded-xl border bg-card p-5">
        <h3 className="text-lg font-semibold">{c.candidates}</h3><p className="text-sm text-muted-foreground">{c.selectChannel}</p>
        <ul className="divide-y">{local.fleetCandidates.map(ch => <li key={ch.slug} className="flex flex-wrap items-center justify-between gap-2 py-2">
          <Link className={internalLink} to={`${BASE}/titles/${encodeURIComponent(ch.slug)}${context.search}`}>{ch.name}</Link>
          <span className="font-mono text-sm">{ch.latestVersion}</span></li>)}</ul>
      </section>
    )}
    {data.fleetCatalogReadiness === "partial" && <p className="rounded-lg border bg-muted/20 p-3 text-sm">{portfolioCopy[locale].partialCatalog}</p>}
    <InstalledVersions data={data} />
    <InstalledFindings data={data} />
    <section className="space-y-3 rounded-xl border bg-card p-5">
      <h3 className="text-lg font-semibold">{c.sources}</h3>
      {data.title && <p className="text-sm">{c.titleLink} <code className="rounded bg-muted px-1.5 py-0.5">{data.title.slug}/darwin</code></p>}
      {local && <p className="text-sm"><Link className={internalLink} to={`/devices/applications/${encodeURIComponent(local.appHash)}`}>{c.record}</Link> · {c.recordEvidence}</p>}
      {data.title && data.items.length > 0 && <div><p className="mb-1 text-sm font-medium">{c.localMatches}</p>
        <ul className="flex flex-wrap gap-x-4 gap-y-1">{data.items.map(item => <li key={item.appHash}><Link className={internalLink} to={`${BASE}/apps/${encodeURIComponent(item.appHash)}${context.search}`}>{item.name} ({item.macs})</Link></li>)}</ul></div>}
      {data.jamfTitles.length ? <div><p className="mb-1 text-sm font-medium">{c.jamfTitle}</p><ul className="flex flex-wrap gap-x-4 gap-y-1">
        {data.jamfTitles.map(title => <li key={title.id}><Link className={internalLink} to={`/devices/applications/jamf-patch/${encodeURIComponent(title.id)}`}>{title.name}</Link></li>)}
      </ul><p className="mt-1 text-xs text-muted-foreground">{c.jamfScope}</p></div>
        : data.installedMacs > 0 && <p className="text-sm text-muted-foreground">
          {data.jamfCatalogReady && data.items.every(item => item.jamfEvaluated) && (!local || local.jamfEvaluated) ? c.jamfMissing
            : data.jamfCatalogReady ? (locale === "de" ? "Der Jamf-Abgleich liegt noch nicht für alle Einträge vor." : "Jamf matching has not finished for every record.") : c.jamfUnavailable}
        </p>}
      {assessment && <p className="border-t pt-2 text-sm"><strong>{c[assessment.management]}.</strong> {assessment.managementReason}</p>}
    </section>
    {candidate && chosenVersion && !ambiguous ? <div ref={comparison} tabIndex={-1}>
      <FleetTargetComparison key={chosenVersion} kind={context.kind} id={context.id} scope={context.scope}
        version={chosenVersion} latest={candidate.latestVersion} slug={candidate.slug} initial={data} onReset={() => setTarget(null)} />
    </div> : data.installedMacs > 0 && <BuildEvidence assessment={assessment}/>}
    {candidate && <section className="space-y-3 rounded-xl border bg-card p-5">
      <h3 className="text-lg font-semibold">{c.versions}</h3>
      <FleetTitleHistory key={candidate.slug} slug={candidate.slug} canRead={canRead} onRead={onHistoryRead} detail
        onSelectVersion={ambiguous ? undefined : choose} />
    </section>}
    <FleetOperatorNotes bundleId={bundle === local?.name ? null : bundle}/>
    {(candidate || local?.match !== "ambiguous") && <FleetPilotGuide key={candidate?.slug ?? "unmatched"} candidate={candidate}/>}
  </div>;
}

function LoadDetail(context: Context) {
  const { t, locale } = useLocale();
  const c = fleetDetailCopy[locale];
  const [data, setData] = useState<MigrationDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    getFleetDetail(context.kind, context.id, context.scope).then(value => {
      if (active) { setData(value); setError(null); }
    }).catch((cause: unknown) => {
      if (active) setError(cause instanceof ApiError && cause.detail ? cause.detail : c.readFailed);
    });
    return () => { active = false; };
  }, [context.kind, context.id, context.scope, attempt, c]);
  const reload = () => setAttempt(n => n + 1);
  return <div className="space-y-4">
    <Link className={`inline-flex items-center gap-1 ${internalLink}`} to={`${BASE}${context.search}`}><ArrowLeft size={15} aria-hidden="true"/>{c.back}</Link>
    {error ? <div role="alert" className="space-y-2 rounded-xl border p-5 text-sm"><p>{error}</p><Button size="sm" variant="outline" onClick={reload}>{c.retry}</Button></div>
      : !data ? <p role="status" className="text-sm text-muted-foreground">{c.loading}</p> : !data.enabled ? <p>{t.fleetCatalog.emptyFlagOff}</p>
      : <DetailBody data={data} context={context} onHistoryRead={reload}/>}
  </div>;
}

export function FleetAppPage() {
  const { appHash, slug } = useParams<{ appHash: string; slug: string }>();
  const { search } = useLocation();
  const kind = appHash ? "apps" : "titles";
  const id = appHash ?? slug ?? "";
  const scope = fleetDetailScope(new URLSearchParams(search));
  return <LoadDetail key={`${kind}/${id}?${scope}`} kind={kind} id={id} scope={scope} search={search}/>;
}
