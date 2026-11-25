import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { DeviceScopeBuilder } from "@/features/catalog/DeviceScopeBuilder";
import { defaultScope } from "@/features/catalog/deviceScope";
import { fleetCatalogPath } from "@/features/catalog/patchPlanNavigation";
import { fleetScopeQuery, getMigrationReport } from "@/features/fleetCatalog/api";
import { detailPath } from "@/features/fleetCatalog/catalogView";
import { FleetCatalogPage } from "@/features/fleetCatalog/FleetCatalogPage";
import type { MigrationPortfolio } from "@/features/fleetCatalog/migrationTypes";
import { coverage, needsReview, policySummary, portfolioEmpty, portfolioRows, portfolioSorts, quickCounts, readFilter, readSort,
  reviewFilters } from "@/features/fleetCatalog/portfolioView";
import { useLocale } from "@/i18n/LocaleContext";

const field = "rounded-md border border-input bg-background px-3 py-2 text-sm";
const control = "grid gap-1 text-xs text-muted-foreground";
const note = "text-xs text-muted-foreground";
const heading = "px-4 py-2.5 font-medium";
const cell = "px-4 py-3 align-top";
const pageSize = 50;
const scopeCounts = ["selectedMacs", "eligibleMacs", "unknownContactMacs", "unknownInventoryMacs"] as const;

/** The tab in one view, keeping the rest of its query (the device filter, the search, Show and Sort) but the page. */
function viewHref(params: URLSearchParams, titles: boolean): string {
  const query = new URLSearchParams(params);
  query.delete("page");
  if (titles) query.set("view", "catalog"); else query.delete("view");
  return query.toString() ? `${fleetCatalogPath}?${query}` : fleetCatalogPath;
}

/** The address with `key` set to `next`, or without it when `next` is empty, and without the page unless that moved. */
function withParam(params: URLSearchParams, key: string, next: string): URLSearchParams {
  const address = new URLSearchParams(params);
  if (key !== "page") address.delete("page");
  if (next) address.set(key, next); else address.delete(key);
  return address;
}

/** Devices › Applications › Fleet catalog (#904): one heading and one device filter over Migration review, or with
 *  `view=catalog` Fleet titles (#905). The builder, keyed on the filter as on Installed apps so Back and Forward reset its
 *  draft, writes `deviceScope`. Only the view on screen is mounted, and it asks for the report for that filter. */
export function FleetCatalogHome() {
  const { t } = useLocale();
  const [params, setParams] = useSearchParams();
  const showTitles = params.get("view") === "catalog";
  const value = params.get("deviceScope") ?? JSON.stringify(defaultScope);
  return <section className="space-y-5">
    <header><p className="text-sm font-medium text-muted-foreground">{t.fleetCatalog.eyebrow}</p>
      <h1 className="text-3xl font-bold tracking-tight">{t.fleetCatalog.title}</h1></header>
    <nav aria-label={t.fleetCatalog.title} className="flex w-fit gap-1 rounded-lg border bg-muted/30 p-1">
      {[false, true].map(titles => <Link key={String(titles)} to={viewHref(params, titles)} aria-current={titles === showTitles ? "page" : undefined}
        className={`rounded-md px-3 py-2 text-sm font-medium focus-visible:ring-2 ${titles === showTitles ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>
        {titles ? t.fleetPlanning.segments.titles : t.fleetPlanning.segments.review}</Link>)}
    </nav>
    <DeviceScopeBuilder key={value} value={value} onChange={scope => setParams(withParam(params, "deviceScope", scope))} />
    {showTitles ? <FleetTitles /> : <MigrationReview />}
  </section>;
}

/** The last answer, with the query and the Retry count it was asked with, so one they have moved past never paints
 *  (CONTRIBUTING.md, #479). `failed.detail` is the server's own sentence, null when it sent none. */
type Answer = { key: string; revision: number; report?: MigrationPortfolio; failed?: { detail: string | null } };

/** Each app Jamf inventoried on the Macs main's device filter selects, against Fleet's and Jamf's catalogs. The report is
 *  asked for the filter exactly as the address has it (`fleetScopeQuery`), and this page never parses, drops or widens it. */
function MigrationReview() {
  const { t, locale } = useLocale();
  const words = t.fleetPlanning;
  const [params, setParams] = useSearchParams();
  const query = fleetScopeQuery(params);
  const search = params.get("q") ?? "";
  const filter = readFilter(params.get("filter"));
  const sort = readSort(params.get("sort"));
  const [revision, setRevision] = useState(0);
  const [answer, setAnswer] = useState<Answer>();
  useEffect(() => {
    const controller = new AbortController();
    getMigrationReport(query, controller.signal)
      .then(report => { if (!controller.signal.aborted) setAnswer({ key: query, revision, report }); })
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) setAnswer({ key: query, revision, failed: { detail: caught instanceof ApiError ? caught.detail : null } });
      });
    return () => controller.abort();
  }, [query, revision]);
  const current = answer?.key === query && answer.revision === revision ? answer : undefined;
  // A report with the flag off counts nothing, so it says only that: never a scope count or an empty state.
  const report = current?.report?.enabled ? current.report : undefined;
  const rows = useMemo(() => (report ? portfolioRows(report, search, filter, sort) : []), [report, search, filter, sort]);
  const counts = useMemo(() => report && quickCounts(report), [report]);
  const empty = report ? portfolioEmpty(report, rows) : null;
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const page = Math.min(pages, Math.max(1, Math.floor(Number(params.get("page"))) || 1));
  const start = (page - 1) * pageSize;
  function change(key: string, next: string) {
    setParams(withParam(params, key, next), { replace: key === "q" });
  }

  return <div className="space-y-5">
    {report && <dl className="grid grid-cols-2 gap-3 rounded-lg border bg-card p-4 sm:grid-cols-4">
      {scopeCounts.map(key => <div key={key}><dt className="text-xs font-medium text-muted-foreground">{words.scope[key]}</dt>
        <dd className="text-xl font-semibold tabular-nums">{report.scope[key].toLocaleString(locale)}</dd></div>)}
    </dl>}
    {current?.failed && <div role="alert" className="flex flex-wrap items-center gap-3 text-sm"><span className="text-destructive">{current.failed.detail ?? words.loadFailed}</span>
      <Button variant="outline" onClick={() => setRevision(n => n + 1)}>{words.retry}</Button></div>}
    {!current && <p role="status" className="text-sm text-muted-foreground">{words.loading}</p>}
    {current?.report?.enabled === false && <p className="text-sm text-muted-foreground">{t.fleetCatalog.emptyFlagOff}</p>}
    {report && counts && <>
      {!report.fleetCatalogReady && <p className="text-sm">{report.fleetCatalogReadiness === "partial" ? words.partialCatalog : words.notRead}{" "}
        <Link className="underline" to={viewHref(params, true)}>{words.segments.titles}</Link></p>}
      {!report.jamfCatalogReady && <p className="text-sm">{words.noJamf}</p>}
      <div className="flex flex-wrap gap-2">
        {(["candidates", "overdue", "outside"] as const).map(key => <button type="button" key={key} aria-pressed={filter === key}
          className="rounded-md border bg-card px-3 py-1.5 text-sm hover:bg-muted aria-pressed:border-primary aria-pressed:text-primary"
          onClick={() => change("filter", filter === key ? "" : key)}>
          {words.filters[key]} <strong className="ml-1 tabular-nums">{counts[key]?.toLocaleString(locale) ?? words.unknownCount}</strong></button>)}
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <label className={`${control} min-w-52 flex-1`}>{words.search}
          <input className={field} type="search" data-page-search="" value={search} onChange={e => change("q", e.target.value)} /></label>
        <label className={control}>{words.show}
          <select className={field} value={filter} onChange={e => change("filter", e.target.value)}>
            {reviewFilters.map(key => <option key={key} value={key}>{words.filters[key]}</option>)}</select></label>
        <label className={control}>{words.sortBy}
          <select className={field} value={sort} onChange={e => change("sort", e.target.value)}>
            {portfolioSorts.map(key => <option key={key} value={key}>{words.sorts[key]}</option>)}</select></label>
      </div>
      {filter === "outside" && report.fleetCatalogReady && report.jamfCatalogReady && <p className="text-sm text-muted-foreground">{words.outsideNote}</p>}
      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-left text-sm">
          <thead className="border-b bg-muted/30 text-muted-foreground"><tr>
            {Object.values(words.columns).map(name => <th key={name} scope="col" className={heading}>{name}</th>)}
          </tr></thead>
          <tbody>{rows.slice(start, start + pageSize).map(item => {
            const a = report.appAssessments[item.appHash];
            const evidence = report.installedEvidence[item.appHash];
            return <tr key={item.appHash} className="border-b last:border-0">
              <td className={cell}><Link className="block w-fit font-semibold text-primary hover:underline" to={detailPath("apps", item.appHash, params)}>{item.name}</Link><div className={`break-all ${note}`}>{item.bundleId}</div></td>
              <td className={`${cell} tabular-nums`}>{item.macs.toLocaleString(locale)}
                {report.scope.selectedMacs > 0 && <div title={words.prevalence} className={note}>
                  {(item.macs / report.scope.selectedMacs).toLocaleString(locale, { style: "percent", maximumFractionDigits: 1 })}</div>}</td>
              <td className={cell}>{coverage(item, report).map(key => words.coverage[key]).join(" · ")}<div className={note}>{words.builds(item.versionCount)}</div></td>
              <td className={cell}><span className={a?.outOfPolicyBuilds ? "font-semibold" : undefined}>{words.policy[policySummary(a)]}</span>
                {a?.oldestGapDays != null && <div className={note}>{words.gapAge(a.oldestGapDays)}</div>}
                {a && needsReview(a) && <div className={`max-w-xs ${note}`}>{words.reasons[a.priorityReason]}</div>}</td>
              {/* The installed copies' evidence first, then what Fleet's latest would address (`appAssessments`). */}
              <td className={cell}>{evidence?.assessedBuilds ? evidence.affectedBuilds ? words.affected(evidence.affectedBuilds) : words.clean
                : words.unassessedBuilds(evidence?.unknownBuilds ?? item.versionCount)}
                {evidence && evidence.assessedBuilds > 0 && evidence.unknownBuilds > 0 && <div className={note}>{words.unassessedBuilds(evidence.unknownBuilds)}</div>}
                {evidence?.kevBuilds ? <div className="font-medium">{words.kev(evidence.kevBuilds)}</div> : null}
                {a && a.behindBuilds > 0 && <div className={note}>{a.addresses == null ? words.missing : a.addresses > 0 ? words.addressed(a.addresses) : words.zero}</div>}</td>
            </tr>;
          })}</tbody>
        </table>
        {empty && <div className="space-y-2 p-6 text-sm"><p>{words.empty[empty]}</p>
          <Link className="text-primary underline" to={viewHref(params, true)}>{words.browse}</Link></div>}
      </div>
      {rows.length > 0 && <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
        <div>{words.range(start + 1, Math.min(start + pageSize, rows.length), rows.length)}<p className={note}>{words.countsNote}</p></div>
        {pages > 1 && <div className="flex gap-2">
          <Button variant="outline" disabled={page === 1} onClick={() => change("page", String(page - 1))}>{words.previous}</Button>
          <Button variant="outline" disabled={page === pages} onClick={() => change("page", String(page + 1))}>{words.next}</Button></div>}
      </div>}
      <p className={note}>{words.asOf} {new Date(report.asOf).toLocaleString(locale)}</p>
    </>}
  </div>;
}

/** Fleet titles (#905): main's Fleet catalog page, each title counted on the Macs the filter selects. The report is read as
 *  Migration review reads it, but the page draws from the last good one for this filter, never a fresh answer, so Check now
 *  and Retry read again with the table mounted (a refusal's sentence, the sort and open histories stay); a new filter remounts it. */
function FleetTitles() {
  const { t } = useLocale();
  const words = t.fleetPlanning;
  const [params, setParams] = useSearchParams();
  const query = fleetScopeQuery(params);
  const [revision, setRevision] = useState(0);
  const [answer, setAnswer] = useState<Answer>();
  const [held, setHeld] = useState<{ key: string; report: MigrationPortfolio }>();
  useEffect(() => {
    const controller = new AbortController();
    getMigrationReport(query, controller.signal)
      .then(report => { if (!controller.signal.aborted) { setAnswer({ key: query, revision, report }); setHeld({ key: query, report }); } })
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) setAnswer({ key: query, revision, failed: { detail: caught instanceof ApiError ? caught.detail : null } });
      });
    return () => controller.abort();
  }, [query, revision]);
  const current = answer?.key === query && answer.revision === revision ? answer : undefined;
  const report = held?.key === query ? held.report : undefined;
  const change = (key: string, next: string) => setParams(withParam(params, key, next), { replace: key === "q" });
  return <div className="space-y-5">
    {current?.failed && <div role="alert" className="flex flex-wrap items-center gap-3 text-sm"><span className="text-destructive">{current.failed.detail ?? words.loadFailed}</span>
      <Button variant="outline" onClick={() => setRevision(n => n + 1)}>{words.retry}</Button></div>}
    {!current && <p role="status" className="text-sm text-muted-foreground">{words.loading}</p>}
    {report?.enabled === false && <p className="text-sm text-muted-foreground">{t.fleetCatalog.emptyFlagOff}</p>}
    {report?.enabled && <FleetCatalogPage scope={{ search: params.get("q") ?? "", setSearch: q => change("q", q),
      installedOnly: params.get("installedOnly") === "1", setInstalledOnly: on => change("installedOnly", on ? "1" : ""),
      counts: report.fleetDeviceCounts, deviceScope: params.get("deviceScope") ?? undefined, onRefresh: () => setRevision(n => n + 1), titleHref: slug => detailPath("titles", slug, params) }} />}
  </div>;
}
