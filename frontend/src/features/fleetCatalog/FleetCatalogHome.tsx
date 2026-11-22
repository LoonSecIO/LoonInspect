import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { useLocale } from "@/i18n/LocaleContext";
import { FleetCatalogPage } from "./FleetCatalogPage";
import { FleetBriefing } from "./FleetBriefing";
import { fleetDetailScope } from "./detailApi";
import type { MigrationItem, MigrationPortfolio } from "./migrationTypes";
import { portfolioCopy } from "./portfolioCopy";
import { needsReview, outsideCatalogs, policySummary, portfolioRows, reviewFilters } from "./portfolioView";

const field = "rounded-md border border-input bg-background px-3 py-2 text-sm";
const base = "/devices/applications/fleet-catalog";
const pageSize = 50;
const heading = "px-4 py-2.5 font-medium";
const cell = "px-4 py-3 align-top";
type Copy = typeof portfolioCopy.en;

function coverage(item: MigrationItem, report: MigrationPortfolio, copy: Copy) {
  if (outsideCatalogs(item, report)) return copy.outside;
  const parts = [];
  if (item.match === "exact") parts.push(copy.fleet);
  if (item.match === "ambiguous") parts.push(copy.channels);
  if (item.hasJamfMatch) parts.push(copy.jamf);
  return parts.join(" · ") || (item.match === "none" ? copy.noFleet : copy.unavailable);
}

export function FleetCatalogHome() {
  const { locale } = useLocale();
  const copy = portfolioCopy[locale];
  const [params, setParams] = useSearchParams();
  const scope = fleetDetailScope(params);
  const isCatalog = params.get("view") === "catalog";
  const search = params.get("q") ?? "";
  const requestedFilter = params.get("filter");
  const filter = reviewFilters.find(value => value === requestedFilter) ?? "all";
  const sort = ["reach", "age", "name"].find(value => value === params.get("sort")) ?? "priority";
  const sourceId = params.get("connectionId") ?? "";
  const selectedDays = params.get("days") ?? "";
  const windows = [7, 14, 30, 90];
  if (/^[1-9][0-9]*$/.test(selectedDays) && Number(selectedDays) <= 3650 && !windows.includes(Number(selectedDays))) {
    windows.push(Number(selectedDays));
    windows.sort((a, b) => a - b);
  }
  const [revision, setRevision] = useState(0);
  const [response, setResponse] = useState<{key: string; revision: number; report?: MigrationPortfolio; error?: string}>();
  const [connections, setConnections] = useState<MigrationPortfolio["connections"]>([]);
  useEffect(() => {
    const controller = new AbortController();
    apiRequest<MigrationPortfolio>(`/fleet-catalog/migration?${scope}`, { signal: controller.signal }).then(report => {
      if (controller.signal.aborted) return;
      setResponse({key: scope, revision, report});
      setConnections(report.connections);
    }).catch((e: unknown) => {
      if (!controller.signal.aborted) setResponse({key: scope, revision, error: e instanceof ApiError && e.detail ? e.detail : copy.error});
    });
    return () => controller.abort();
  }, [scope, revision, copy.error]);
  const current = response?.key === scope && response.revision === revision ? response : undefined;
  const report = current?.report;
  const rows = useMemo(() => report ? portfolioRows(report, search, filter, sort) : [], [report, search, filter, sort]);
  const rawPage = Number(params.get("page") || 1);
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const page = Number.isInteger(rawPage) ? Math.min(pages, Math.max(1, rawPage)) : 1;
  const start = (page - 1) * pageSize;
  function change(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (key !== "page") next.delete("page");
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: key === "q" });
  }
  function viewUrl(view: string) {
    const query = new URLSearchParams(params);
    query.delete("page");
    if (view === "catalog") query.set("view", view);
    else query.delete("view");
    return base + (query.size ? "?" + query.toString() : "");
  }
  function titleHref(slug: string) {
    return base + "/titles/" + encodeURIComponent(slug) + "?" + params.toString();
  }

  const scopeReport = report?.scope;
  const readOnly = "text-xs font-medium text-muted-foreground";
  const nav = "rounded-md px-3 py-2 text-sm font-medium focus-visible:ring-2";
  return <section className="space-y-5">
    <header>
      <h1 className="text-3xl font-bold tracking-tight">{copy.heading}</h1>
    </header>
    <nav aria-label={copy.heading} className="flex w-fit gap-1 rounded-lg border bg-muted/30 p-1">
      {[[copy.planning, false], [copy.catalog, true]].map(([label, catalog]) =>
        <Link key={String(label)} to={viewUrl(catalog ? "catalog" : "planning")}
          aria-current={isCatalog === catalog ? "page" : undefined}
          className={nav + (isCatalog === catalog ? " bg-background shadow-sm" : " text-muted-foreground hover:text-foreground")}>{label}</Link>)}
    </nav>
    <div className="rounded-lg border bg-card p-4">
      <fieldset className="flex flex-wrap items-end gap-x-4 gap-y-3">
        <legend className="mb-2 text-sm font-semibold">{copy.scope}</legend>
        <label className="grid gap-1 text-xs text-muted-foreground">{copy.connection}
          <select className={field} value={sourceId} onChange={e => change("connectionId", e.target.value)}>
            <option value="">{copy.allConnections}</option>
            {sourceId && !connections.some(c => String(c.id) === sourceId) && <option value={sourceId}>{copy.connection} #{sourceId}</option>}
            {connections.map(c => <option value={c.id} key={c.id}>{c.name}</option>)}
          </select>
        </label>
        <label className="grid gap-1 text-xs text-muted-foreground">{copy.clock}
          <select className={field} value={params.get("clock") ?? "contact"} onChange={e => change("clock", e.target.value)}>
            <option value="contact">{copy.contact}</option><option value="inventory">{copy.inventory}</option>
          </select>
        </label>
        <label className="grid gap-1 text-xs text-muted-foreground">{copy.window}
          <select className={field} value={selectedDays} onChange={e => change("days", e.target.value)}>
            <option value="">{copy.dates}</option>
            {windows.map(n => <option key={n} value={n}>{copy.days(n)}</option>)}
          </select>
        </label>
      </fieldset>
      {scopeReport && <dl className="mt-4 grid grid-cols-2 gap-3 border-t pt-3 sm:grid-cols-4">
        {[[copy.inScope, scopeReport.activeMacs], [copy.tracked, scopeReport.eligibleMacs],
          [copy.stale, scopeReport.days ? scopeReport.staleMacs : "—"], [copy.unknown, scopeReport.days ? scopeReport.unknownMacs : "—"]].map(([label, value]) =>
          <div key={label}><dt className={readOnly}>{label}</dt><dd className="text-xl font-semibold tabular-nums">{value.toLocaleString(locale)}</dd></div>)}
      </dl>}
    </div>
    {current?.error && <div role="alert" className="space-x-3 text-sm">{current.error} <Button variant="outline" onClick={() => setRevision(n => n + 1)}>{copy.retry}</Button></div>}
    {!current && <p role="status" className="text-sm text-muted-foreground">{copy.loading}</p>}
    {report && !report.enabled && <p>{copy.disabled}</p>}
    {report?.enabled && (isCatalog ? <FleetCatalogPage
      planning={{ search, setSearch: q => change("q", q), installedOnly: params.get("installedOnly") === "1",
        setInstalledOnly: on => change("installedOnly", on ? "1" : ""), counts: report.fleetDeviceCounts, titleHref, onRefresh: () => setRevision(n => n + 1) }}
    /> : <>
      {!report.fleetCatalogReady && <p className="text-sm">{report.fleetCatalogReadiness === "partial" ? copy.partialCatalog : copy.notRead} <Link className="underline" to={viewUrl("catalog")}>{copy.catalog}</Link></p>}
      {!report.jamfCatalogReady && <p className="text-sm text-muted-foreground">{copy.noJamf}</p>}
      <div className="flex flex-wrap gap-2">
        {(["candidates", "overdue", "outside"] as const).map(key => {
          const count = report.items.reduce((n, item) => {
            const a = report.appAssessments[item.appHash];
            const matches = key === "outside" ? outsideCatalogs(item, report) : key === "overdue" ? !!a?.outOfPolicyBuilds : needsReview(a);
            return n + Number(matches);
          }, 0);
          return <button type="button" key={key} aria-pressed={filter === key}
            className="rounded-md border bg-card px-3 py-1.5 text-sm hover:bg-muted aria-pressed:border-primary aria-pressed:text-primary"
            onClick={() => change("filter", filter === key ? "all" : key)}>{copy[key]} <strong className="ml-1 tabular-nums">
              {key === "outside" && (!report.jamfCatalogReady || !report.fleetCatalogReady) ? copy.unknownCount : count}
            </strong></button>;
        })}
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <label className="grid min-w-52 flex-1 gap-1 text-xs text-muted-foreground">{copy.search}
          <input className={field} type="search" data-page-search="" value={search} onChange={e => change("q", e.target.value)} /></label>
        <label className="grid gap-1 text-xs text-muted-foreground">{copy.report}
          <select className={field} value={filter} onChange={e => change("filter", e.target.value)}>
            {reviewFilters.map(f => <option key={f} value={f}>{copy[f === "unknown" ? "unknownFilter" : f]}</option>)}
          </select></label>
        <label className="grid gap-1 text-xs text-muted-foreground">{copy.sort}
          <select className={field} value={sort} onChange={e => change("sort", e.target.value)}>
            {(["priority", "reach", "age", "name"] as const).map(s => <option key={s} value={s}>{copy[s]}</option>)}
          </select></label>
      </div>
      {filter === "outside" && report.fleetCatalogReady && report.jamfCatalogReady && <p className="text-sm text-muted-foreground">{copy.outsideNote}</p>}
      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-left text-sm">
          <thead className="border-b bg-muted/30 text-muted-foreground"><tr>
            {[copy.app, copy.macs, copy.coverage, copy.policy, copy.findings].map(col => <th key={col} scope="col" className={heading}>{col}</th>)}
          </tr></thead>
          <tbody>{rows.slice(start, start + pageSize).map(item => {
            const a = report.appAssessments[item.appHash];
            const installed = report.installedEvidence[item.appHash];
            const count = a?.addresses;
            return <tr className="border-b last:border-0 hover:bg-muted/20" key={item.appHash}>
              <td className={cell}><Link className="font-semibold text-primary hover:underline" to={base + "/apps/" + encodeURIComponent(item.appHash) + "?" + params.toString()}>{item.name}</Link>
                <div className="break-all text-xs text-muted-foreground">{item.bundleId}</div></td>
              <td className={cell + " tabular-nums"}>{item.macs.toLocaleString(locale)}
                {report.scope.activeMacs > 0 && <div title={copy.prevalence} className="text-xs text-muted-foreground">{(item.macs / report.scope.activeMacs).toLocaleString(locale, {style:"percent",maximumFractionDigits:1})}</div>}</td>
              <td className={cell}>{coverage(item, report, copy)}<div className="text-xs text-muted-foreground">{copy.builds(item.versionCount)}</div></td>
              <td className={cell}><span className={a?.outOfPolicyBuilds ? "font-semibold" : undefined}>{copy[policySummary(a)]}</span>
                {a?.oldestGapDays != null && <div className="text-xs text-muted-foreground">{copy.gapAge(a.oldestGapDays)}</div>}
                {a && needsReview(a) && <div className="max-w-xs text-xs text-muted-foreground">{a.reason}</div>}</td>
              <td className={cell}>{installed?.assessedBuilds ? (installed.affectedBuilds ? copy.affected(installed.affectedBuilds) : copy.clean) : copy.unavailableFindings}
                {!!installed?.kevBuilds && <div className="font-medium">{copy.kev(installed.kevBuilds)}</div>}
                {a && a.behindBuilds > 0 && <div className="text-xs text-muted-foreground">{count == null ? copy.missing : count > 0 ? copy.addressed(count) : copy.zero}</div>}</td>
            </tr>;
          })}</tbody>
        </table>
        {rows.length === 0 && <div className="space-y-2 p-6 text-sm"><p>{copy.empty}</p><Link className="text-primary underline" to={viewUrl("catalog")}>{copy.browse}</Link></div>}
      </div>
      {rows.length > 0 && <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
        <div>{copy.range(start + 1, Math.min(start + pageSize, rows.length), rows.length)}<p className="text-xs text-muted-foreground">{copy.activityNote}</p></div>
        {pages > 1 && <div className="flex gap-2"><Button variant="outline" disabled={page === 1} onClick={() => change("page", String(page - 1))}>{copy.previous}</Button>
          <Button variant="outline" disabled={page === pages} onClick={() => change("page", String(page + 1))}>{copy.next}</Button></div>}
      </div>}
      <FleetBriefing key={scope} scope={scope} />
      <p className="text-xs text-muted-foreground">{copy.asOf} {new Date(report.asOf).toLocaleString(locale)}</p>
    </>)}
  </section>;
}
