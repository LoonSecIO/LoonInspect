import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import { changeScope, defaultScope, readScope, scopeSize, type DeviceScope } from "./deviceScope";
import type { ScopeOptions } from "./patchPlanTypes";
import { ScopeGroupEditor, scopeInput as input } from "./ScopeGroupEditor";
import { ScopeProposal } from "./ScopeProposal";

export function DeviceScopeBuilder({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const user = useAuthStore(s => s.user);
  const storageKey = `looninspect.device-scopes.${user?.tenant?.id}.${user?.id}`;
  const [draft, setDraft] = useState<DeviceScope>(() => readScope(value) ?? defaultScope);
  const [options, setOptions] = useState<ScopeOptions>();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [name, setName] = useState("");
  const [jsonDraft, setJsonDraft] = useState("");
  const [saved, setSaved] = useState<{ name: string; scope: DeviceScope }[]>(() => {
    try {
      const items = JSON.parse(localStorage.getItem(storageKey) ?? "[]");
      return Array.isArray(items) ? items.flatMap(item => {
        const scope = readScope(JSON.stringify(item?.scope));
        return typeof item?.name === "string" && scope ? [{ name: item.name, scope }] : [];
      }).slice(0, 20) : [];
    } catch { return []; }
  });
  useEffect(() => {
    const controller = new AbortController();
    apiRequest<ScopeOptions>(`/application-patch-plans/scope-options?deviceScope=${encodeURIComponent(value)}`, { signal: controller.signal })
      .then(data => { if (!controller.signal.aborted) setOptions(data); })
      .catch(e => { if (!controller.signal.aborted) setError(e instanceof ApiError && e.detail ? e.detail : "Device scope could not be read. Check connectivity and reload."); });
    return () => controller.abort();
  }, [value]);
  const valid = readScope(JSON.stringify(draft));
  const dirty = JSON.stringify(valid) !== JSON.stringify(readScope(value));
  const size = scopeSize(draft);
  function save() {
    const title = name.trim();
    if (!title) { setError("Name this filter before saving it."); return; }
    if (!valid) { setError("Complete the conditions and remove any empty nested groups before saving."); return; }
    const next = [...saved.filter(s => s.name !== title), { name: title, scope: valid }].slice(-20);
    try { localStorage.setItem(storageKey, JSON.stringify(next)); setSaved(next); setName(""); setError(""); setNotice("Filter saved on this browser. Apply it when ready."); }
    catch { setError("This browser could not save the filter. Copy its JSON to keep it."); }
  }
  function loadJson() {
    const parsed = readScope(jsonDraft);
    if (!parsed) { setError("This JSON is not a valid device filter. Check field names and values, use at most 20 conditions and four group levels, and remove empty nested groups."); return; }
    setDraft(parsed); setError(""); setNotice("JSON loaded into the draft. Review the brackets and apply when ready.");
  }
  return <section className="space-y-4 rounded-lg border bg-card p-4" aria-label="Device scope">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="font-semibold">Device scope</h2><p className="text-sm text-muted-foreground">
        {options ? `${options.devices.toLocaleString()} current Jamf Macs match the applied filter.` : "Choose which devices contribute installed applications and patch plans."}
      </p></div>
      <label className="grid gap-1 text-xs text-muted-foreground">Jamf connection <select className={input} aria-label="Jamf connection" value={draft.connectionId ?? ""}
        onChange={e => setDraft({ ...draft, connectionId: e.target.value ? Number(e.target.value) : null })}>
        <option value="">All connections</option>{options?.connections.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
      </select></label>
    </div>
    <ScopeGroupEditor group={draft} connectionId={draft.connectionId} options={options} size={size}
      onChange={(path, change) => { setDraft(current => changeScope(current, path, change)); setNotice(""); }} />
    <datalist id="patch-scope-attributes">{options?.attributes.map(a => <option key={`${a.id}:${a.name}`} value={a.name}>{a.id}</option>)}</datalist>
    <div className="flex flex-wrap items-center gap-2 border-t pt-3">
      <Button disabled={!valid} onClick={() => { if (valid) onChange(JSON.stringify(valid)); }}>Apply device filter</Button>
      <Button variant="ghost" onClick={() => { setDraft(defaultScope); onChange(JSON.stringify(defaultScope)); }}>Clear filter</Button>
      <span className="text-xs text-muted-foreground">{size.conditions}/20 conditions · {size.groups}/10 groups{dirty ? " · draft changes" : " · applied"}</span>
    </div>
    {!valid && <p role="status" className="text-sm text-amber-700 dark:text-amber-300">Complete each condition and remove empty nested groups before applying. Up to four group levels are supported.</p>}
    <ScopeProposal key={JSON.stringify(draft)} scope={draft} onLoad={scope => { setDraft(scope); setError(""); setNotice("AI proposal loaded as a draft. Review and apply the device filter when ready."); }} />
    <details className="rounded-lg border p-3"><summary className="cursor-pointer text-sm font-medium">Save or inspect scope JSON</summary>
      <div className="mt-3 space-y-3">
        <div className="flex flex-wrap gap-2">
          <input className={input} aria-label="Filter name" placeholder="Name this filter" value={name} maxLength={80} onChange={e => setName(e.target.value)} />
          <Button variant="outline" disabled={!valid} onClick={save}>Save filter</Button>
          {saved.length > 0 && <select className={input} aria-label="Saved filters" value="" onChange={e => { const item = saved[Number(e.target.value)]; if (item) { setDraft(item.scope); setNotice("Saved filter loaded as a draft. Apply it when ready."); } }}>
            <option value="">Saved filters on this browser</option>{saved.map((s, i) => <option key={s.name} value={i}>{s.name}</option>)}
          </select>}
        </div>
        <textarea aria-label="Current scope JSON" className={`${input} max-h-72 w-full font-mono text-xs`} rows={8} readOnly value={JSON.stringify(draft, null, 2)} />
        <Button size="sm" variant="outline" onClick={() => { (navigator.clipboard ? navigator.clipboard.writeText(JSON.stringify(draft, null, 2)) : Promise.reject()).then(() => setNotice("Scope JSON copied.")).catch(() => setError("Clipboard access was refused. Select and copy the JSON text above.")); }}>Copy JSON</Button>
        <label className="grid gap-1 text-sm">Import scope JSON<textarea aria-label="Import scope JSON" className={`${input} w-full font-mono text-xs`} rows={3} maxLength={12000} value={jsonDraft} onChange={e => setJsonDraft(e.target.value)} /></label>
        <Button size="sm" variant="outline" disabled={!jsonDraft.trim()} onClick={loadJson}>Load JSON into builder</Button>
      </div>
    </details>
    <p className="text-xs text-muted-foreground">Brackets define each group. Unknown contact dates and unobserved EA or group membership do not count as a negative match.</p>
    {notice && <p role="status" className="text-sm">{notice}</p>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
  </section>;
}
