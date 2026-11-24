import { useEffect, useMemo, useState } from "react";
import { Link, Navigate, useNavigate, useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { useHasPermission } from "@/features/auth/store";
import { DeviceScopeBuilder } from "@/features/catalog/DeviceScopeBuilder";
import { patchPlanHref } from "@/features/catalog/patchPlanNavigation";
import { defaultScope } from "@/features/catalog/patchPlanTypes";
import { ApiError } from "@/config/api";
import { ApplicationRiskCells } from "./ApplicationRiskCells";
import { Input } from "@/components/ui/input";
import { PATCH_STATE_COLORS } from "@/features/catalog/patchState";
import { listApplications, type Application, type ApplicationListResponse, type ApplicationScope, type RiskSeverity } from "@/features/devices/applicationsApi";
import { listSyncStatus } from "@/features/mdm/api";
import type { MdmSyncStatus } from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";

/** Why the table is empty, resolved only on the empty path (#299 §8). */
type EmptyReason = "noConnection" | "noSync" | "synced" | "noMatch";

function emptyReason(q: string, statuses: MdmSyncStatus[]): EmptyReason {
  if (q) return "noMatch";
  if (statuses.length === 0) return "noConnection";
  if (statuses.every((status) => status.lastSyncAt === null)) return "noSync";
  return "synced";
}

/**
 * The applications table, trimmed (#299): a list with a record behind every row. The
 * expansion that lived inside a row is gone with the per-version query that fed it; a
 * row click goes to `/devices/applications/:appHash`, which has an address, so it can be
 * pasted into a ticket and reached for an app the list never fetched.
 *
 * Search lives in the URL (`q`), as the Devices page's does, so a filtered list is a link.
 */
export function ApplicationsOverviewPage() {
  const [params] = useSearchParams();
  const scope = params.get("deviceScope") ?? JSON.stringify(defaultScope);
  if (params.get("plan")) return <Navigate replace to={patchPlanHref(params)} />;
  return <InstalledApplications key={scope} deviceScope={scope} />;
}

function InstalledApplications({ deviceScope }: { deviceScope: string }) {
  const canPlan = useHasPermission("patch:plan-write");
  const [selected, setSelected] = useState<string[]>([]);
  const { t } = useLocale();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const q = useMemo(() => searchParams.get("q") ?? "", [searchParams]);

  const bands = ["critical", "high", "medium", "low"] as const;
  const severityKey = bands.filter(band => searchParams.getAll("severity").includes(band)).join(",");
  const hasKev = searchParams.get("hasKev") === "true";
  const page = Math.max(1, Math.min(1000000, Math.floor(Number(searchParams.get("page"))) || 1));
  const applicationScope = useMemo<ApplicationScope>(() => ({ q, severities: severityKey ? severityKey.split(",") as RiskSeverity[] : [], hasKev }), [q, severityKey, hasKev]);
  const filterKey = JSON.stringify([deviceScope, q, severityKey, hasKev]);
  const queryKey = `${filterKey}:${page}`;
  const [selectedFilter, setSelectedFilter] = useState(filterKey);
  if (selectedFilter !== filterKey) { setSelectedFilter(filterKey); setSelected([]); }
  const [loaded, setLoaded] = useState<{ queryKey: string; response: ApplicationListResponse; statuses: MdmSyncStatus[] | null } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState(q);
  const loadDependencies = [q, deviceScope, t, queryKey, page, applicationScope, hasKev, severityKey] as const;
  const [loadInputs, setLoadInputs] = useState(loadDependencies);
  if (loadDependencies.some((input, index) => input !== loadInputs[index])) {
    setLoadInputs(loadDependencies);
    setLoaded(null);
    setError(null);
  }

  // The box is a draft, applied on a debounce; it follows the URL when the back button
  // moves it. Adjusted during render rather than from an effect.
  const [lastApplied, setLastApplied] = useState(q);
  if (lastApplied !== q) {
    setLastApplied(q);
    setDraft(q);
  }

  useEffect(() => {
    const trimmed = draft.trim();
    if (trimmed === q) return;
    const handle = setTimeout(() => setSearchParams(current => {
      const next = new URLSearchParams(current); if (trimmed) next.set("q", trimmed); else next.delete("q");
      next.delete("page"); return next;
    }, { replace: true }), 250);
    return () => clearTimeout(handle);
  }, [draft, q, setSearchParams]);

  useEffect(() => {
    let cancelled = false;
    listApplications({ q: q || undefined, page, pageSize: 100, deviceScope, severities: applicationScope.severities, hasKev })
      .then(async (response) => {
        if (cancelled) return;
        // The four empty states need the sync status, and only the empty path reads it.
        const statuses = response.items.length === 0 && !q && !severityKey && !hasKev ? await listSyncStatus().catch(() => null) : null;
        if (cancelled) return;
        setLoaded({ queryKey, response, statuses });
        setError(null);
      })
      .catch(e => {
        if (!cancelled) setError(e instanceof ApiError && typeof e.detail === "string" ? e.detail : t.applications.errorLoading);
      });
    return () => {
      cancelled = true;
    };
  }, [q, deviceScope, t, queryKey, page, applicationScope, hasKev, severityKey]);

  const current = loaded && loaded.queryKey === queryKey ? loaded : null;
  const loading = current === null && error === null;
  function changeRisk(change: (params: URLSearchParams) => void) {
    setSearchParams(previous => { const next = new URLSearchParams(previous); change(next); next.delete("page"); return next; });
  }

  return (
    <section className="space-y-4">
      <DeviceScopeBuilder value={deviceScope} onChange={value => {
        const next = new URLSearchParams(searchParams); next.set("deviceScope", value); next.delete("plan"); next.delete("page"); setSearchParams(next);
      }} />
      <section className="space-y-3 rounded-lg border bg-card p-4" aria-label="Application scope">
        <div><h2 className="font-semibold">Application scope</h2><p className="text-sm text-muted-foreground">Narrow the apps found on the devices above. Severity choices match any selected band; KEV adds another condition.</p></div>
        <div className="flex flex-wrap items-end gap-3">
          <Input aria-label="Application name or bundle ID" maxLength={255} data-page-search="" placeholder={t.applications.searchPlaceholder} value={draft} onChange={event => setDraft(event.target.value)} className="max-w-sm" />
          <fieldset className="flex flex-wrap gap-2"><legend className="mb-1 text-xs text-muted-foreground">Has severity</legend>
            {bands.map(band => <label key={band} className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm capitalize">
              <input type="checkbox" checked={applicationScope.severities.includes(band)} onChange={event => { const checked = event.currentTarget.checked; changeRisk(next => {
                const values = next.getAll("severity").filter(value => value !== band); if (checked) values.push(band);
                next.delete("severity"); values.forEach(value => next.append("severity", value));
              }); }} />{band}</label>)}
          </fieldset>
          <label className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm"><input type="checkbox" checked={hasKev} onChange={event => { const checked = event.currentTarget.checked; changeRisk(next => {
            if (checked) next.set("hasKev", "true"); else next.delete("hasKev");
          }); }} />Has KEV</label>
          <Button variant="ghost" onClick={() => { setDraft(""); changeRisk(next => { next.delete("q"); next.delete("severity"); next.delete("hasKev"); }); }}>Clear app filters</Button>
        </div>
        <p className="text-xs text-muted-foreground">Known findings are the uncapped totals across assessed installed builds, counted once per device/build. The same CVE can appear in multiple builds. Average = known findings ÷ assessed devices; unknown builds are excluded.</p>
        {current && <p className="text-xs text-muted-foreground">{current.response.corpusAsOf ? `Vulnerability source dated ${current.response.corpusAsOf} · release ${current.response.corpusRelease}` : "Vulnerability assessment is unavailable. Check data sharing and the vulnerability source; unknown coverage is shown as a dash."}</p>}
      </section>
      {canPlan && <div className="flex flex-wrap items-center gap-3">
        <Button disabled={!selected.length || selected.length > 50} onClick={() => navigate(patchPlanHref(searchParams, selected))}>Plan for {selected.length} selected apps</Button>
        {selected.length > 0 && <Button variant="ghost" onClick={() => setSelected([])}>Clear selection</Button>}
        {selected.length > 50 && <p role="status" className="text-sm">Select up to 50 applications per report.</p>}
      </div>}

      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              {canPlan && <th className="px-4 py-2 font-medium">Patch plan</th>}
              <th className="px-4 py-2 font-medium">{t.applications.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableBundleId}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tableVersions}</th>
              <th className="px-4 py-2 font-medium">{t.applications.tablePatch}</th>
              <th className="px-4 py-2 text-right font-medium">{t.applications.tableDevices}</th>
              <th className="px-4 py-2 font-medium">Vulnerability coverage</th>
              <th className="px-4 py-2 text-right font-medium">Known findings</th>
              <th className="px-4 py-2 text-right font-medium">Avg / assessed device</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={canPlan ? 9 : 8}>
                  {t.applications.loading}
                </td>
              </tr>
            )}
            {current && current.response.items.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={canPlan ? 9 : 8}>
                  {severityKey || hasKev || deviceScope !== JSON.stringify(defaultScope) ? "No applications match this combination of device and application filters." : current.statuses === null && !q
                    ? t.applications.empty
                    : t.applications.emptyStates[emptyReason(q, current.statuses ?? [])]}
                </td>
              </tr>
            )}
            {current?.response.items.map((app) => (
              <tr
                key={app.appHash}
                className="cursor-pointer border-b last:border-0 hover:bg-accent/40"
                onClick={() => navigate(`/devices/applications/${app.appHash}`)}
              >
                {canPlan && <td className="px-4 py-2" onClick={e => e.stopPropagation()}><div className="flex items-center gap-2">
                  <input type="checkbox" aria-label={`Select ${app.name} for a patch plan`} checked={selected.includes(app.appHash)}
                    onChange={e => setSelected(current => e.target.checked ? [...current, app.appHash] : current.filter(hash => hash !== app.appHash))} />
                  <Button variant="outline" size="sm" onClick={() => navigate(patchPlanHref(searchParams, [app.appHash]))}>Plan application</Button>
                </div></td>}
                <td className="px-4 py-2 font-medium">
                  <Link to={`/devices/applications/${app.appHash}`} className="hover:underline" onClick={(event) => event.stopPropagation()}>
                    {app.name}
                  </Link>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{app.bundleId}</td>
                <td className="px-4 py-2 tabular-nums">{app.versionCount}</td>
                <td className="px-4 py-2">
                  <PatchSummary app={app} t={t} />
                </td>
                <td className="px-4 py-2 text-right font-medium tabular-nums">{app.deviceCount}</td>
                <ApplicationRiskCells app={app} />
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {current && <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">{t.applications.total(current.response.total)} · page {page}</p>
        <div className="flex gap-2"><Button variant="outline" disabled={page <= 1} onClick={() => setSearchParams(previous => { const next = new URLSearchParams(previous); next.set("page", String(page - 1)); return next; })}>Previous</Button>
          <Button variant="outline" disabled={page * current.response.pageSize >= current.response.total} onClick={() => setSearchParams(previous => { const next = new URLSearchParams(previous); next.set("page", String(page + 1)); return next; })}>Next</Button></div>
      </div>}
    </section>
  );
}

/**
 * The patch answer at the list's grain (#313): how many of the Macs carrying this app have
 * a patch available, over how many matched a Jamf Patch title at all. Three renderings
 * that never look alike — no title (no answer, muted), none behind (green), some behind
 * (red) — because "0 with a patch available" on an app no title matches would be a clean
 * bill nobody issued. The record page has the per-build spread; this is the glance.
 */
function PatchSummary({ app, t }: { app: Application; t: Translations }) {
  const ta = t.applications;
  if (app.matchedDeviceCount === 0) return <span className="text-muted-foreground">{ta.patchNoTitle}</span>;
  const behind = app.patchAvailableDeviceCount > 0;
  return (
    <span className="inline-flex items-center gap-1.5" title={ta.patchCountHint}>
      <span
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ backgroundColor: behind ? PATCH_STATE_COLORS.behind : PATCH_STATE_COLORS.latest }}
      />
      {behind ? ta.patchAvailableFor(app.patchAvailableDeviceCount, app.matchedDeviceCount) : ta.patchNone}
    </span>
  );
}
