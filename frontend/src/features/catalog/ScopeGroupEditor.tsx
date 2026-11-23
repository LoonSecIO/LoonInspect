import { Button } from "@/components/ui/button";
import { comparisonLabels, isScopeGroup, newRule, operators, scopeFields, type ScopeField, type ScopeGroup, type ScopeNode, type ScopeOperator, type ScopeRule } from "./deviceScope";
import type { ScopeOptions } from "./patchPlanTypes";

export const scopeInput = "min-w-0 max-w-full rounded-md border border-input bg-background px-3 py-2 text-sm";
export function ScopeGroupEditor({ group, path = [], depth = 1, options, connectionId, size, onChange }: {
  group: ScopeGroup; path?: number[]; depth?: number; options?: ScopeOptions; connectionId?: number | null;
  size: { conditions: number; groups: number }; onChange: (path: number[], change: (node: ScopeNode) => ScopeNode | null) => void;
}) {
  const label = path.length ? `Group ${path.map(i => i + 1).join(".")}` : "Root group";
  const append = (node: ScopeNode) => onChange(path, current => isScopeGroup(current) ? { ...current, rules: [...current.rules, node] } : current);
  return <fieldset aria-label={label} className={`relative min-w-0 rounded-r-lg border-l-2 border-primary/40 pb-3 pl-3 pr-2 sm:pl-5 ${depth > 1 ? "ml-2 bg-muted/20 pt-2 sm:ml-4" : "pt-1"}`}>
    <legend className="-ml-3 flex max-w-full items-center gap-2 pb-2 sm:-ml-5">
      <select aria-label={`${label} operator`} className="rounded-md border border-primary/40 bg-background px-2 py-1.5 text-xs font-bold tracking-wide text-primary"
        value={group.match} onChange={e => onChange(path, current => ({ ...current, match: e.target.value as "all" | "any" }))}>
        <option value="all">AND</option><option value="any">OR</option>
      </select>
      <span className="text-xs text-muted-foreground">{group.match === "all" ? "All inside this bracket" : "Any inside this bracket"}</span>
    </legend>
    <div className="space-y-3">
      {group.rules.map((node, i) => {
        const childPath = [...path, i];
        const id = childPath.map(n => n + 1).join(".");
        if (isScopeGroup(node)) return <ScopeGroupEditor key={i} group={node} path={childPath} depth={depth + 1} options={options} connectionId={connectionId} size={size} onChange={onChange} />;
        const update = (change: Partial<ScopeRule>) => onChange(childPath, current => ({ ...current, ...change }));
        return <div key={i} className="flex min-w-0 flex-wrap items-center gap-2 rounded-md border bg-card p-2">
          <select aria-label={`Condition ${id} field`} className={scopeInput} value={node.field} onChange={e => onChange(childPath, () => newRule(e.target.value as ScopeField))}>
            {scopeFields.map(([key, name]) => <option key={key} value={key}>{name}</option>)}
          </select>
          {node.field === "ea" && <input aria-label={`Condition ${id} attribute`} className={scopeInput} list="patch-scope-attributes" placeholder="EA name or definition ID" value={node.key} onChange={e => update({ key: e.target.value })} />}
          <select aria-label={`Condition ${id} comparison`} className={scopeInput} value={node.operator} onChange={e => { const operator = e.target.value as ScopeOperator; update({ operator, value: operator === "unknown" ? "" : node.value || newRule(node.field).value }); }}>
            {operators(node.field).map(op => <option key={op} value={op}>{comparisonLabels[op]}</option>)}
          </select>
          {node.operator !== "unknown" && (node.field === "group" ? <>
            <select aria-label={`Condition ${id} group`} className={scopeInput} value={node.key && node.value ? `${node.key}:${node.value}` : ""}
              onChange={e => { const [key, value] = e.target.value.split(":"); update({ key: key ?? "", value: value ?? "" }); }}>
              <option value="">Select observed group</option>{options?.groups.filter(g => !connectionId || g.connectionId === connectionId).map(g =>
                <option key={`${g.connectionId}:${g.id}`} value={`${g.connectionId}:${g.id}`}>{g.name} · connection {g.connectionId} · #{g.id}</option>)}
            </select>
            <input className={`${scopeInput} w-28`} aria-label={`Condition ${id} group connection ID`} placeholder="Connection ID" value={node.key} onChange={e => update({ key: e.target.value })} />
            <input className={`${scopeInput} w-24`} aria-label={`Condition ${id} group ID`} placeholder="Group ID" value={node.value} onChange={e => update({ value: e.target.value })} />
          </> : node.field === "managed" ? <select aria-label={`Condition ${id} value`} className={scopeInput} value={node.value} onChange={e => update({ value: e.target.value })}>
            <option value="true">Yes</option><option value="false">No</option>
          </select> : <input className={`${scopeInput} min-w-24 flex-1 basis-36`} aria-label={`Condition ${id} value`} placeholder={node.field === "contact" || node.field === "inventory" ? "Days" : "Value"} value={node.value} maxLength={255} onChange={e => update({ value: e.target.value })} />)}
          <Button variant="ghost" size="sm" aria-label={`Remove condition ${id}`} onClick={() => onChange(childPath, () => null)}>Remove</Button>
        </div>;
      })}
      {!group.rules.length && <p className="text-sm text-muted-foreground">{depth === 1 ? "All current Jamf Macs in this connection. Add a condition to narrow the scope." : "Add a condition or remove this empty group."}</p>}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" disabled={size.conditions >= 20} onClick={() => append(newRule())}>Add condition</Button>
        <Button size="sm" variant="outline" disabled={depth >= 4 || size.groups >= 10 || size.conditions >= 20} onClick={() => append({ match: "any", rules: [newRule()] })}>Add group</Button>
        {path.length > 0 && <Button size="sm" variant="ghost" aria-label={`Remove ${label.toLowerCase()}`} onClick={() => onChange(path, () => null)}>Remove group</Button>}
      </div>
    </div>
  </fieldset>;
}
