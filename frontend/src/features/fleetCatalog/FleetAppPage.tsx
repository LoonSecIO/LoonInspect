import { ArrowLeft } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useLocation, useParams } from "react-router";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "@/components/ui/external-link";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { fleetCatalogPath, installedAppsPath } from "@/features/catalog/patchPlanNavigation";
import { fleetScopeQuery, getFleetDetail } from "@/features/fleetCatalog/api";
import { detailPath, manifestUrl } from "@/features/fleetCatalog/catalogView";
import { FleetTitleHistory } from "@/features/fleetCatalog/FleetTitleHistory";
import type { MigrationDetail } from "@/features/fleetCatalog/migrationTypes";
import { useLocale } from "@/i18n/LocaleContext";

const link = "font-medium text-primary underline decoration-primary/40 underline-offset-4 hover:decoration-primary";
const card = "space-y-3 rounded-xl border bg-card p-5";
const heading = "text-lg font-semibold";
const label = "text-xs text-muted-foreground";

type Opened = { kind: "apps" | "titles"; id: string; search: string; list: URLSearchParams }; // the list's query, as written and parsed

/** Each build with its Macs, filtered to one exact version; on a title page with several identities, with its app's name. */
function InstalledBuilds({ data }: { data: MigrationDetail }) {
  const { t, locale } = useLocale();
  const words = t.fleetDetail;
  const [picked, setPicked] = useState<string | null>(null);
  // `at` is -1 for every version, and again once a re-read no longer lists the one picked.
  const versions = [...new Set(data.builds.map(build => build.version))], at = picked === null ? -1 : versions.indexOf(picked);
  const high = Math.max(1, ...data.builds.map(build => build.macs)), names = new Map(data.items.map(item => [item.appHash, item.name]));
  return <section className={card}><h3 className={heading}>{words.installed}</h3>
    {!data.builds.length ? <p className="text-sm text-muted-foreground">{words.noBuilds}</p> : <>
      {versions.length > 1 && <label className="flex flex-wrap items-center gap-2 text-sm">{words.filterVersion}
        <select className="max-w-full rounded-md border bg-background px-2 py-1" value={at < 0 ? "" : String(at)}
          onChange={event => setPicked(event.target.value === "" ? null : versions[Number(event.target.value)])}>
          <option value="">{words.allVersions}</option>{versions.map((version, index) => <option key={version} value={String(index)}>{version || words.unknown}</option>)}
        </select></label>}
      <div className="max-h-80 overflow-auto"><table className="w-full text-left text-sm">
        <thead className={`border-b ${label}`}><tr><th className="py-2 pr-3" scope="col">{words.version}</th><th className="py-2" scope="col">{words.count}</th></tr></thead>
        <tbody>{data.builds.filter(build => at < 0 || build.version === picked).map(build =>
          <tr key={`${build.appHash}:${build.versionHash}`} className="border-b last:border-0">
            <td className="break-all py-2 pr-3"><strong>{build.version || words.unknown}</strong>
              {build.shortVersion && build.shortVersion !== build.version && <small className="ml-2 text-muted-foreground">({build.shortVersion})</small>}
              {data.title && data.items.length > 1 && <small className="block text-muted-foreground">{names.get(build.appHash)}</small>}</td>
            <td className="w-1/2 py-2"><div className="flex items-center gap-2"><span className="w-12 shrink-0 tabular-nums">{build.macs.toLocaleString(locale)}</span>
              <span aria-hidden="true" className="h-2 rounded-r-sm bg-[#2a78d6] dark:bg-[#3987e5]" style={{ width: `${(build.macs * 75) / high}%` }} /></div></td>
          </tr>)}</tbody></table></div>
      <p className={label}>{words.countNote}</p>
    </>}
  </section>;
}

/** The answer, and once a Fleet title is known #901's history in its detail layout, with no Compare (that is #908's). */
function DetailBody({ data, opened, onHistoryRead }: { data: MigrationDetail; opened: Opened; onHistoryRead: () => void }) {
  const { t, locale } = useLocale();
  const words = t.fleetDetail, local = data.item, count = (n: number) => n.toLocaleString(locale);
  const canRead = useHasPermission(PERMISSIONS.PATCH_CATALOG_SYNC);
  // The one Fleet title the page may speak for (the title's own, or an `exact` app's only one), and a bundle ID that matches
  // nothing (#895): blank, or the app's name, the inventory's stand-in for none.
  const candidate = data.title ?? (local?.match === "exact" ? local.fleetCandidates[0] : undefined);
  const bundle = local ? local.bundleId : data.title?.bundleId ?? "";
  const bundleMissing = !bundle.trim() || bundle === local?.name;
  const coverage = !local ? words.catalogFirst : local.match === "unknown" ? words.catalogUnknown(bundleMissing)
    : { exact: words.exact, ambiguous: words.ambiguous, none: words.noMatch }[local.match];
  const noJamf = !data.jamfCatalogReady ? words.jamfUnavailable : data.items.every(item => item.jamfEvaluated) ? words.jamfMissing : words.jamfPending;
  return <div className="space-y-4">
    <header className={card}>
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2"><div className="min-w-0">
        <h2 className="break-words text-2xl font-semibold">{local?.name || data.title?.name}</h2>
        <p className="mt-1 break-all font-mono text-sm text-muted-foreground">{bundleMissing ? words.bundleMissing : bundle}</p></div>
        {candidate && <ExternalLink className="text-sm" href={manifestUrl(candidate.slug)}>{words.source}</ExternalLink>}</div>
      <p className="text-sm">{words.footprint(count(data.installedMacs), data.installedMacs === 1, count(data.scope.selectedMacs), data.scope.selectedMacs === 1)} {coverage}</p>
      {!local && data.items.some(item => item.match === "ambiguous") && <p className="text-sm">{words.ambiguous}</p>}
      <dl className="grid grid-cols-2 gap-x-5 gap-y-3 border-t pt-3 sm:grid-cols-3">
        <div><dt className={label}>{words.matches}</dt><dd className="text-2xl font-semibold tabular-nums">{count(data.installedMacs)}</dd></div>
        {candidate && <div><dt className={label}>{words.fleetLatest}</dt><dd className="break-all text-xl font-medium">{candidate.latestVersion}</dd></div>}
        <div className="col-span-2 sm:col-span-1"><dt className={label}>{words.asOf}</dt><dd className="pt-1 text-sm">{new Date(data.asOf).toLocaleString(locale)}
          <small className="block text-muted-foreground">{words.scopeMacs(count(data.scope.selectedMacs), count(data.scope.eligibleMacs), data.scope.eligibleMacs === 1)}</small></dd></div>
      </dl>
    </header>
    {local?.match === "ambiguous" && <section className={card}><h3 className={heading}>{words.candidates}</h3><p className="text-sm text-muted-foreground">{words.selectChannel}</p>
      <ul className="divide-y">{local.fleetCandidates.map(channel => <li key={channel.slug} className="flex flex-wrap items-center justify-between gap-2 py-2">
        <Link className={`text-sm ${link}`} to={detailPath("titles", channel.slug, opened.list)}>{channel.name}</Link><span className="break-all font-mono text-sm">{channel.latestVersion}</span></li>)}</ul>
    </section>}
    {data.fleetCatalogReadiness === "partial" && <p className="rounded-lg border bg-muted/20 p-3 text-sm">{t.fleetPlanning.partialCatalog}</p>}
    <InstalledBuilds data={data} />
    <section className={`${card} text-sm`}><h3 className={heading}>{words.sources}</h3>
      {candidate && <p>{words.titleLink} <code className="break-all rounded bg-muted px-1.5 py-0.5">{candidate.slug}</code></p>}
      {local && <p><Link className={link} to={`${installedAppsPath}/${encodeURIComponent(local.appHash)}`}>{words.record}</Link> · {words.recordEvidence}</p>}
      {!local && data.items.length > 0 && <div><p className="mb-1 font-medium">{words.localMatches}</p><ul className="flex flex-wrap gap-x-4 gap-y-1">
        {data.items.map(item => <li key={item.appHash}><Link className={link} to={detailPath("apps", item.appHash, opened.list)}>{item.name}</Link> ({count(item.macs)})</li>)}</ul></div>}
      {data.jamfTitles.length > 0 ? <div><p className="mb-1 font-medium">{words.jamfTitle}</p><ul className="flex flex-wrap gap-x-4 gap-y-1">
        {data.jamfTitles.map(title => <li key={title.id}><Link className={link} to={`${installedAppsPath}/jamf-patch/${encodeURIComponent(title.id)}`}>{title.name}</Link></li>)}</ul>
        <p className={`mt-1 ${label}`}>{words.jamfScope}</p></div> : data.installedMacs > 0 && <p className="text-muted-foreground">{noJamf}</p>}
    </section>
    {candidate && <section className={card}><h3 className={heading}>{words.versions}</h3>
      <FleetTitleHistory key={candidate.slug} slug={candidate.slug} canRead={canRead} onRead={onHistoryRead} detail /></section>}
  </div>;
}

/** One read, on the list's device filter alone. A refusal shows the server's sentence, a 409 (the flag, #899's only one) main's;
 *  Retry clears it and reads again. A history read that lands reads again with the answer left on screen. */
function LoadDetail({ opened }: { opened: Opened }) {
  const { t } = useLocale();
  const { kind, id } = opened, scope = fleetScopeQuery(opened.list);
  const [data, setData] = useState<MigrationDetail | null>(null);
  const [failed, setFailed] = useState<{ status: number; detail: string | null } | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    getFleetDetail(kind, id, scope, undefined, controller.signal)
      .then(answer => { if (!controller.signal.aborted) setData(answer); })
      .catch((caught: unknown) => { if (!controller.signal.aborted) setFailed(caught instanceof ApiError ? caught : { status: 0, detail: null }); });
    return () => controller.abort();
  }, [kind, id, scope, attempt]);
  const retry = () => { setData(null); setFailed(null); setAttempt(n => n + 1); };
  return <div className="space-y-4">
    <Link className={`inline-flex items-center gap-1 text-sm ${link}`} to={fleetCatalogPath + opened.search}><ArrowLeft aria-hidden="true" className="h-4 w-4" />{t.fleetDetail.back}</Link>
    {failed ? <div role="alert" className="space-y-2 rounded-xl border p-5 text-sm"><p>{failed.status === 409 ? t.fleetCatalog.emptyFlagOff : failed.detail ?? t.fleetDetail.readFailed}</p>
      <Button size="sm" variant="outline" onClick={retry}>{t.fleetDetail.retry}</Button></div>
      : data ? <DetailBody data={data} opened={opened} onHistoryRead={() => setAttempt(n => n + 1)} />
        : <p role="status" className="text-sm text-muted-foreground">{t.fleetDetail.loading}</p>}
  </div>;
}

/** Devices › Applications › Fleet catalog › an installed app (`apps/:appHash`) or a Fleet title and every identity with its
 *  bundle ID (`titles/:slug`) (#906). Keyed on what it reads, so another app, title or filter starts clean. */
export function FleetAppPage() {
  const { appHash, slug } = useParams<{ appHash: string; slug: string }>();
  const { search } = useLocation(), list = new URLSearchParams(search);
  const opened: Opened = { kind: appHash ? "apps" : "titles", id: appHash ?? slug ?? "", search, list };
  return <LoadDetail key={`${opened.kind}/${opened.id}?${fleetScopeQuery(list)}`} opened={opened} />;
}
