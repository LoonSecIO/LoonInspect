import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { apiRequest, ApiError } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import { defaultScope, readScope, type DeviceScope, type ScopeField, type ScopeOperator, type ScopeOptions, type ScopeRule } from "./patchPlanTypes";

const input = "rounded-md border border-input bg-background px-3 py-2 text-sm";
const fields: [ScopeField, string][] = [["managed", "Managed"], ["group", "Jamf group"], ["contact", "Last contact"],
  ["inventory", "Last inventory"], ["ea", "Extension attribute"], ["site", "Site"], ["department", "Department ID"],
  ["building", "Building ID"], ["os_version", "macOS version"]];
const labels: Record<ScopeOperator, string> = { is: "is", is_not: "is not", contains: "contains", within: "within days", older: "older than days", unknown: "unknown" };
function operators(field: ScopeField): ScopeOperator[] {
  if (field === "contact" || field === "inventory") return ["within", "older", "unknown"];
  if (field === "managed") return ["is", "unknown"];
  if (field === "group") return ["is", "is_not"];
  if (field === "ea") return ["is", "is_not", "unknown"];
  return ["is", "is_not", "contains", "unknown"];
}
function newRule(field: ScopeField): ScopeRule {
  return { field, operator: operators(field)[0], value: field === "managed" ? "true" : field === "contact" || field === "inventory" ? "14" : "", key: "" };
}

export function DeviceScopeBuilder({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const user = useAuthStore(s => s.user);
  const storageKey = `looninspect.device-scopes.${user?.tenant?.id}.${user?.id}`;
  const [draft, setDraft] = useState<DeviceScope>(() => readScope(value) ?? defaultScope);
  const [options, setOptions] = useState<ScopeOptions>();
  const [error, setError] = useState("");
  const [name, setName] = useState("");
  const [saved, setSaved] = useState<{ name: string; scope: DeviceScope }[]>(() => {
    try {
      const items = JSON.parse(localStorage.getItem(storageKey) ?? "[]");
      return Array.isArray(items) ? items.filter(i => typeof i?.name === "string" && readScope(JSON.stringify(i.scope))).slice(0, 20) : [];
    } catch { return []; }
  });
  useEffect(() => {
    const controller = new AbortController();
    apiRequest<ScopeOptions>(`/application-patch-plans/scope-options?deviceScope=${encodeURIComponent(value)}`, { signal: controller.signal })
      .then(data => { if (!controller.signal.aborted) setOptions(data); })
      .catch(e => { if (!controller.signal.aborted) setError(e instanceof ApiError && e.detail ? e.detail : "Device scope could not be read. Check connectivity and try again."); });
    return () => controller.abort();
  }, [value]);
  function update(index: number, change: Partial<ScopeRule>) {
    setDraft({ ...draft, rules: draft.rules.map((r, i) => i === index ? { ...r, ...change } : r) });
  }
  function save() {
    const title = name.trim();
    if (!title) { setError("Name this filter before saving it."); return; }
    const next = [...saved.filter(s => s.name !== title), { name: title, scope: draft }].slice(-20);
    try { localStorage.setItem(storageKey, JSON.stringify(next)); setSaved(next); setName(""); setError(""); }
    catch { setError("This browser could not save the filter. Apply it and keep the page URL to reuse it."); }
  }
  return <section className="space-y-3 rounded-lg border bg-card p-4" aria-label="Device scope">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="font-semibold">Device scope</h2><p className="text-sm text-muted-foreground">
        {options ? `${options.devices.toLocaleString()} current Jamf Macs match the applied filter.` : "Choose which devices contribute installed applications and patch plans."}
      </p></div>
      <label className="text-sm">Jamf connection <select className={input} aria-label="Jamf connection" value={draft.connectionId ?? ""}
        onChange={e => setDraft({ ...draft, connectionId: e.target.value ? Number(e.target.value) : null })}>
        <option value="">All connections</option>{options?.connections.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
      </select></label>
    </div>
    <div className="flex flex-wrap items-center gap-2 text-sm">Match
      <select aria-label="Combine conditions" className={input} value={draft.match} onChange={e => setDraft({ ...draft, match: e.target.value as "all" | "any" })}>
        <option value="all">all conditions</option><option value="any">any condition</option>
      </select><span className="text-muted-foreground">within the selected connection</span>
    </div>
    {draft.rules.map((rule, i) => <div key={i} className="flex flex-wrap items-center gap-2">
      <select aria-label={`Condition ${i + 1} field`} className={input} value={rule.field} onChange={e => update(i, newRule(e.target.value as ScopeField))}>
        {fields.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
      </select>
      {rule.field === "ea" && <input aria-label={`Condition ${i + 1} attribute`} className={input} list="patch-scope-attributes" placeholder="EA name or definition ID" value={rule.key} onChange={e => update(i, { key: e.target.value })} />}
      <select aria-label={`Condition ${i + 1} comparison`} className={input} value={rule.operator} onChange={e => update(i, { operator: e.target.value as ScopeOperator })}>
        {operators(rule.field).map(op => <option key={op} value={op}>{labels[op]}</option>)}
      </select>
      {rule.operator !== "unknown" && (rule.field === "group" ? <>
        <select aria-label={`Condition ${i + 1} group`} className={`${input} max-w-full`} value={rule.key && rule.value ? `${rule.key}:${rule.value}` : ""}
          onChange={e => { const [key, value] = e.target.value.split(":"); update(i, { key: key ?? "", value: value ?? "" }); }}>
          <option value="">Select observed group</option>{options?.groups.filter(g => !draft.connectionId || g.connectionId === draft.connectionId).map(g =>
            <option key={`${g.connectionId}:${g.id}`} value={`${g.connectionId}:${g.id}`}>{g.name} · connection {g.connectionId} · #{g.id}</option>)}
        </select>
        <input className={`${input} w-32`} aria-label={`Condition ${i + 1} group connection ID`} placeholder="Connection ID" value={rule.key} onChange={e => update(i, { key: e.target.value })} />
        <input className={`${input} w-28`} aria-label={`Condition ${i + 1} group ID`} placeholder="Group ID" value={rule.value} onChange={e => update(i, { value: e.target.value })} />
      </> : rule.field === "managed" ? <select aria-label={`Condition ${i + 1} value`} className={input} value={rule.value} onChange={e => update(i, { value: e.target.value })}>
        <option value="true">Yes</option><option value="false">No</option>
      </select> : <input className={input} aria-label={`Condition ${i + 1} value`} placeholder="Value" value={rule.value} onChange={e => update(i, { value: e.target.value })} />)}
      <Button variant="ghost" onClick={() => setDraft({ ...draft, rules: draft.rules.filter((_, index) => index !== i) })} aria-label={`Remove condition ${i + 1}`}>Remove</Button>
    </div>)}
    <datalist id="patch-scope-attributes">{options?.attributes.map(a => <option key={`${a.id}:${a.name}`} value={a.name}>{a.id}</option>)}</datalist>
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={draft.rules.length >= 20} onClick={() => setDraft({ ...draft, rules: [...draft.rules, newRule("managed")] })}>Add condition</Button>
      <Button onClick={() => onChange(JSON.stringify(draft))}>Apply device filter</Button>
      <Button variant="ghost" onClick={() => { setDraft(defaultScope); onChange(JSON.stringify(defaultScope)); }}>Clear filter</Button>
      <input className={input} aria-label="Filter name" placeholder="Name this filter" value={name} maxLength={80} onChange={e => setName(e.target.value)} />
      <Button variant="outline" onClick={save}>Save filter</Button>
      {saved.length > 0 && <select className={input} aria-label="Saved filters" value="" onChange={e => { const item = saved[Number(e.target.value)]; if (item) { setDraft(item.scope); onChange(JSON.stringify(item.scope)); } }}>
        <option value="">Saved filters on this browser</option>{saved.map((s, i) => <option key={s.name} value={i}>{s.name}</option>)}
      </select>}
    </div>
    <p className="text-sm text-muted-foreground">Unknown contact dates and unobserved EA or group membership do not count as a negative match.</p>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
  </section>;
}
