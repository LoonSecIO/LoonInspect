import { useCallback, useEffect, useImperativeHandle, useRef, useState, type Ref } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { useAuthStore, useHasPermission } from "@/features/auth/store";
import { readScope, type PatchPlan, type PlanSummary } from "./patchPlanTypes";
import { readReviewDraft } from "./patchPlanDraft";
import { planInventoryHref } from "./patchPlanNavigation";
import { PatchPlanReview } from "./PatchPlanReview";
import type { ApplicationScope } from "@/features/devices/applicationsApi";

const base = "/application-patch-plans";
const input = "rounded-md border border-input bg-background px-3 py-2 text-sm";
type AIStatus = { available: boolean; reason: string | null; providers: { provider: string; model: string }[] };
export type PatchPlanActions = { build: (hashes: string[]) => void };
function failure(e: unknown, fallback: string) { return e instanceof ApiError && e.detail ? e.detail : fallback; }
function stamp(value: string | null | undefined) { return value ? new Date(value).toLocaleString() : "Not recorded"; }

export function PatchPlanWorkspace({ ref, scope, applicationScope, selected, planId, onOpen, onClear }: {
  ref?: Ref<PatchPlanActions>; scope: string; selected: string[]; planId: string | null;
  onOpen: (id: string) => void; onClear: () => void;
  applicationScope?: ApplicationScope;
}) {
  const user = useAuthStore(state => state.user);
  const canWrite = useHasPermission("patch:plan-write");
  const [plan, setPlan] = useState<PatchPlan>();
  const [plans, setPlans] = useState<PlanSummary[]>([]);
  const [refresh, setRefresh] = useState(0);
  const [ai, setAI] = useState<AIStatus>();
  const [provider, setProvider] = useState("");
  const [useAI, setUseAI] = useState(false);
  const [title, setTitle] = useState("Application patch plan");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [reviewState, setReviewState] = useState({ key: "", dirty: false });
  const alive = useRef(true);
  const running = useRef(false);
  const panel = useRef<HTMLElement>(null);
  const shown = plan?.id === planId ? plan : undefined;
  const reviewKey = shown ? `${shown.id}:${shown.revision}` : "";
  const draftKey = `looninspect.patch-review.${user?.tenant?.id}.${user?.id}.${planId}`;
  const reviewDirty = reviewState.key === reviewKey && reviewState.dirty;
  if (reviewState.key !== reviewKey) setReviewState({ key: reviewKey, dirty: !!shown && canWrite && !!readReviewDraft(draftKey) });
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    const controller = new AbortController();
    apiRequest<PlanSummary[]>(base, { signal: controller.signal }).then(data => { if (!controller.signal.aborted) setPlans(data); })
      .catch(e => { if (!controller.signal.aborted) setError(failure(e, "Saved plans could not be read. Check connectivity and reload.")); });
    apiRequest<AIStatus>(`${base}/ai-status`, { signal: controller.signal }).then(data => { if (!controller.signal.aborted) setAI(data); })
      .catch(() => { if (!controller.signal.aborted) setAI({ available: false, reason: "unreachable", providers: [] }); });
    return () => controller.abort();
  }, [refresh]);
  useEffect(() => {
    if (!planId) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = () => {
      apiRequest<PatchPlan>(`${base}/${planId}`, { signal: controller.signal }).then(data => {
        if (controller.signal.aborted) return;
        setPlan(data);
        if (data.researchStatus === "running") timer = setTimeout(poll, 2500);
      }).catch(e => { if (!controller.signal.aborted) setError(failure(e, "The plan could not be read. Check connectivity and refresh the plan.")); });
    };
    poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [planId, refresh]);
  const build = useCallback(async (hashes: string[]) => {
    const deviceScope = readScope(scope);
    if (!hashes.length || running.current) return;
    if (!deviceScope) {
      setError("The plan cannot be built because its device scope is invalid. Choose installed apps and apply the device filters again.");
      return;
    }
    if (hashes.length > 50) { setError("Select up to 50 applications per report."); return; }
    running.current = true;
    setBusy("Building plan…"); setError("");
    try {
      const data = await apiRequest<PatchPlan>(base, { method: "POST", json: { scope: deviceScope, appHashes: hashes, title,
        ...(applicationScope ? { applicationScope } : {}) } });
      if (!alive.current) return;
      setPlan(data); onOpen(data.id); setRefresh(n => n + 1);
      panel.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) { if (alive.current) setError(failure(e, "The plan could not be built. Refresh inventory and try again.")); }
    finally { running.current = false; if (alive.current) setBusy(""); }
  }, [scope, applicationScope, title, onOpen]);
  useImperativeHandle(ref, () => ({ build: hashes => { void build(hashes); } }), [build]);
  async function investigate() {
    if (!shown || running.current) return;
    running.current = true; setBusy("Starting investigation…"); setError("");
    try {
      const data = await apiRequest<PatchPlan>(`${base}/${shown.id}/research`, { method: "POST",
        json: { installomator: true, provider: useAI ? provider || ai?.providers[0]?.provider : null } });
      if (alive.current) { setPlan(data); setRefresh(n => n + 1); }
    } catch (e) { if (alive.current) setError(failure(e, "Investigation could not start. Check connectivity and try again.")); }
    finally { running.current = false; if (alive.current) setBusy(""); }
  }
  async function download() {
    if (!shown || running.current) return;
    running.current = true; setBusy("Exporting PDF…"); setError("");
    try {
      const blob = await apiRequest<Blob>(`${base}/${shown.id}/pdf?revision=${shown.revision}`, { responseType: "blob" });
      if (!alive.current) return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `patch-plan-${shown.id}-r${shown.revision}.pdf`;
      document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { if (alive.current) setError(failure(e, "The PDF could not be exported. Refresh the plan and try again.")); }
    finally { running.current = false; if (alive.current) setBusy(""); }
  }
  return <section ref={panel} className="space-y-4 rounded-lg border bg-card p-4" aria-label="Patch planning">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-lg font-semibold">Patch planning</h2><p className="text-sm text-muted-foreground">Build from installed applications. Keep the scope, sources and review steps together.</p></div>
      {shown && <Button variant="outline" onClick={() => void download()} disabled={!!busy || reviewDirty || shown.researchStatus === "running"}>Export plan as PDF</Button>}
    </div>
    <div className="flex flex-wrap items-center gap-2">
      {canWrite && <><input aria-label="Patch plan title" className={`${input} min-w-64`} value={title} maxLength={160} onChange={e => setTitle(e.target.value)} />
        <Button disabled={!selected.length || !!busy || !title.trim()} onClick={() => void build(selected)}>Build plan for {selected.length} selected apps</Button>
        {selected.length > 0 && <Button variant="ghost" onClick={onClear}>Clear selection</Button>}</>}
      <select aria-label="Saved patch plans" className={`${input} max-w-full`} value={planId ?? ""} onChange={e => onOpen(e.target.value)}>
        <option value="">Open a saved patch plan</option>{plans.map(p => <option key={p.id} value={p.id}>{p.title} · {p.applications.length} apps · {stamp(p.createdAt)}</option>)}
      </select>
      <Button variant="ghost" disabled={reviewDirty} onClick={() => { setError(""); setRefresh(n => n + 1); }}>Refresh plans and AI</Button>
    </div>
    <div className="rounded-md border bg-muted/20 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-3"><strong>AI services</strong>
        {ai?.available ? <><label className="flex items-center gap-2"><input type="checkbox" checked={useAI} onChange={e => setUseAI(e.target.checked)} />Include AI review priorities</label>
          <select aria-label="Patch plan AI provider" className={input} value={provider || ai.providers[0]?.provider || ""} onChange={e => setProvider(e.target.value)}>
            {ai.providers.map(p => <option key={p.provider} value={p.provider}>{p.provider} · {p.model}</option>)}
          </select></> : <span className="text-muted-foreground">{ai ? `Unavailable: ${ai.reason?.replaceAll("_", " ") ?? "check settings"}` : "Checking AI availability…"}</span>}
        <Link to="/settings/ai" className="underline">AI settings and prompt testing</Link>
      </div>
      <p className="mt-2 text-muted-foreground">Investigation checks public Installomator definitions. AI receives app identities, versions, catalog options and counts; it prioritizes the documented review steps.</p>
    </div>
    {busy && <p role="status">{busy}</p>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {planId && !shown && !error && <p role="status">Loading saved plan…</p>}
    {shown && <div className="space-y-5">
      <header className="border-t pt-4"><p className="text-sm font-medium text-muted-foreground">{shown.snapshot.organization} · revision {shown.revision} · {shown.snapshot.status}</p>
        <h3 className="mt-1 text-xl font-semibold">{shown.title}</h3>
        <Link className="text-sm underline" to={planInventoryHref(shown)}>View current installed apps in this scope</Link>
        <p className="mt-2 text-sm">{shown.snapshot.applications.length} apps have documented plans, covering {shown.snapshot.applicationDevices} distinct Macs in a scope of {shown.snapshot.scopedDevices} Macs.</p>
        <p className="text-sm text-muted-foreground">Prepared by {shown.createdBy} · inventory snapshot {stamp(shown.snapshot.asOf)}</p>
      </header>
      <details className="rounded-md border p-3"><summary className="cursor-pointer font-medium">Device scope and source inventory</summary>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">{shown.snapshot.scopeDescription.map((s, i) => <li key={i} className="whitespace-pre-wrap">{s}</li>)}</ul>
        {shown.snapshot.applicationScopeDescription && <p className="mt-3 text-sm">Application scope: {shown.snapshot.applicationScopeDescription.join(" · ")}</p>}
        {shown.snapshot.vulnerabilitySource && <p className="mt-2 break-all text-xs text-muted-foreground">Vulnerability source: {shown.snapshot.vulnerabilitySource.asOf ?? "Not recorded"} · release {shown.snapshot.vulnerabilitySource.release ?? "unavailable"}</p>}
        {shown.snapshot.sources.map(s => <p key={s.connectionId} className="mt-2 text-sm">{s.mdm} · {s.name} · {s.devices} Macs. Inventory: {stamp(s.oldestInventoryAt)} to {stamp(s.newestInventoryAt)}. Unknown dates: {s.unknownInventoryDates}.</p>)}
      </details>
      <div className="overflow-x-auto rounded-md border"><table className="w-full text-left text-sm"><thead className="bg-muted/30"><tr>
        {["Application", "Macs", "Proposed target", "Source coverage", "Plan status"].map(h => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}
      </tr></thead><tbody>{shown.snapshot.applications.map(app => <tr key={app.appHash} className="border-t">
        <td className="px-3 py-3"><a href={`#plan-app-${app.appHash}`} className="font-medium underline">{app.name}</a><p className="text-muted-foreground">{app.bundleId}</p></td>
        <td className="px-3 py-3">{app.devices}</td><td className="px-3 py-3">{app.targetVersion ?? "Needs verification"}</td>
        <td className="px-3 py-3">{[...new Set([
          ...app.options.map(o => o.source),
          ...(shown.research?.applications?.some(r => r.appHash === app.appHash && ["candidate", "needs_review"].includes(r.status)) ? ["Installomator (review required)"] : []),
        ])].join(" · ") || "Needs investigation"}</td>
        <td className="px-3 py-3">{app.status.replaceAll("_", " ")}</td>
      </tr>)}</tbody></table></div>
      <div className="flex flex-wrap items-center gap-3">
        {canWrite && <Button variant="outline" disabled={!!busy || reviewDirty || shown.researchStatus === "running"} onClick={() => void investigate()}>
          {shown.researchStatus === "running" ? "Investigating in background…" : "Investigate patch methods"}</Button>}
        <p className="text-sm" role="status">Investigation: {shown.researchStatus.replaceAll("_", " ")}. {shown.research?.detail}</p>
      </div>
      <PatchPlanReview key={reviewKey} plan={shown} canWrite={canWrite} draftKey={draftKey}
        onDirty={dirty => setReviewState({ key: reviewKey, dirty })} onSaved={setPlan} />
      {shown.snapshot.applications.map(app => {
        const research = shown.research?.applications?.find(r => r.appHash === app.appHash);
        const priorities = shown.research?.ai?.priorities?.[app.appHash];
        return <details key={app.appHash} id={`plan-app-${app.appHash}`} open={shown.snapshot.applications.length === 1} className="rounded-md border p-4">
          <summary className="cursor-pointer font-semibold">{app.name} · {app.devices} Macs · patch methods and rollout</summary>
          <p className="mt-3 text-sm text-muted-foreground">Installed: {app.versions.map(v => `${v.version} (${v.devices} Macs, ${v.relation.replaceAll("_", " ")})`).join("; ")}</p>
          {app.vulnerabilities && <p className="mt-2 text-sm">Known findings: {app.vulnerabilities.counts?.total ?? "unknown"} · KEV: {app.vulnerabilities.counts?.kev ?? "unknown"} · average per assessed device: {app.vulnerabilities.averagePerAssessedDevice?.toFixed(2) ?? "unknown"}. Coverage: {app.vulnerabilities.assessment.replaceAll("_", " ")} · {app.vulnerabilities.assessedDeviceCount}/{app.devices} devices assessed · {app.vulnerabilities.unknownBuildCount} unknown builds.</p>}
          <div className="my-4 grid gap-3 lg:grid-cols-2">{app.options.map(o => <article key={`${o.source}:${o.reference}`} className="space-y-2 rounded-md bg-muted/30 p-3 text-sm">
            <p className="font-semibold">{o.source} · {o.title}</p><p>{o.status.replaceAll("_", " ")} · target {o.targetVersion}</p><p>{o.detail}</p>
            <a href={o.url} target="_blank" rel="noreferrer" className="underline">View source</a>
            <p className="break-all text-muted-foreground">Read {stamp(o.observedAt)} · revision {o.sourceRevision}</p>
          </article>)}</div>
          {research && <article className="mb-4 space-y-2 rounded-md border p-3 text-sm"><p className="font-semibold">Installomator · {research.status.replaceAll("_", " ")}</p>
            <p>{research.detail}</p>{research.url && <a href={research.url} target="_blank" rel="noreferrer" className="underline">Source at investigated revision</a>}
            <p className="break-all text-muted-foreground">Checked {stamp(research.checkedAt)}{research.signingTeam ? ` · signing team ${research.signingTeam}` : ""}{research.revision ? ` · revision ${research.revision}` : ""}</p>
          </article>}
          <h4 className="font-medium">Proposed Jamf rollout</h4><ol className="mt-2 list-decimal space-y-2 pl-5 text-sm">{app.steps.map((s, i) => <li key={s}>{s}{priorities?.includes(i + 1) && <span className="ml-2 rounded bg-primary/10 px-2 py-0.5 text-xs">AI review priority</span>}</li>)}</ol>
          <h4 className="mt-4 font-medium">Open review items at plan creation</h4><ul className="mt-2 list-disc space-y-1 pl-5 text-sm">{app.gaps.map(g => <li key={g}>{g}</li>)}</ul>
        </details>;
      })}
      {shown.research?.ai && <p className="text-sm">AI: {shown.research.ai.status} · {shown.research.ai.provider} · {shown.research.ai.reportedModel || shown.research.ai.requestedModel}. {shown.research.ai.detail}</p>}
      <div className="space-y-1 text-sm text-muted-foreground">{shown.snapshot.limitations.map(l => <p key={l}>{l}</p>)}
        <p className="break-all">Report data SHA-256: {shown.sha256}</p></div>
    </div>}
  </section>;
}
