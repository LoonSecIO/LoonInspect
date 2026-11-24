import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { localTime, timeBound } from "@/features/changes/filters";
import { isPersonToken } from "@/features/changes/personToken";
import { browserZone } from "@/features/changes/prompt";
import type { ChangeFilters, ChangePolicy, UserFilter } from "@/features/changes/types";
import { useLocale } from "@/i18n/LocaleContext";

const inputClasses = "rounded-md border border-input bg-background px-3 py-2 text-sm";
const DEVICE_TEXT_KEYS = ["model", "osVersion", "site", "department", "user"] as const;
const DRAFT_KEYS = ["field", "changedTo", "since", "until", "connectionId", "model", "osVersion", "fileVault", "site", "department", "managed", "user"] as const;
type Draft = Record<(typeof DRAFT_KEYS)[number], string>;

function draftOf(filters: ChangeFilters): Draft {
  return {
    field: filters.field ?? "", changedTo: filters.changedTo ?? "",
    since: localTime(filters.since), until: localTime(filters.until),
    connectionId: filters.connectionId?.toString() ?? "", model: filters.model ?? "", osVersion: filters.osVersion ?? "",
    fileVault: filters.fileVault ?? "", site: filters.site ?? "", department: filters.department ?? "",
    managed: filters.managed ?? "", user: filters.user ?? ""
  };
}

/** Historical stamps only: this form never asks the current-device scope builder. */
export function HistoricalFilters({ filters, policy, policyError, userFilter, onApply, onDirtyChange, onRetry }: {
  filters: ChangeFilters; policy: ChangePolicy | null; policyError: boolean; userFilter: UserFilter | null;
  onApply: (next: Partial<ChangeFilters>) => void; onDirtyChange: (dirty: boolean) => void; onRetry: () => void;
}) {
  const { t } = useLocale();
  const words = t.changes.historical;
  const applied = draftOf(filters);
  const [draft, setDraft] = useState(applied);
  const [error, setError] = useState<string | null>(null);
  const [userEdited, setUserEdited] = useState(false);
  // Unapplied drafts survive every other move on the page (Section, Level, Change, the two
  // search boxes, a page, another key's chip): the field list waits on Section, so a window
  // typed first must still be there when the field is chosen. Only a key whose applied value
  // moved takes it, as the search boxes do; a new section or field takes the target with it.
  // Back, Forward and Clear remount this form instead, which discards every draft.
  const [synced, setSynced] = useState({ applied, section: filters.section });
  const moved = DRAFT_KEYS.filter(key => applied[key] !== synced.applied[key]);
  if (moved.length > 0 || synced.section !== filters.section) {
    const fieldMoved = moved.includes("field") || synced.section !== filters.section;
    setSynced({ applied, section: filters.section });
    setDraft(previous => ({ ...previous, ...Object.fromEntries(moved.map(key => [key, applied[key]])),
      ...(fieldMoved ? { field: applied.field, changedTo: applied.changedTo } : {}) }));
    if (moved.includes("user")) setUserEdited(false);
    setError(null);
  }
  const dirty = DRAFT_KEYS.some(key => draft[key] !== applied[key]);
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  const fields = policy?.sections.find(section => section.section === filters.section)?.fields.filter(field => field.scalar) ?? [];
  function edit(key: keyof Draft, value: string) {
    setDraft(previous => ({ ...previous, [key]: value, ...(key === "field" ? { changedTo: "" } : {}) }));
    setError(null);
    if (key === "user") setUserEdited(true);
  }
  // Only an unchanged applied token gets a readable alias. Once the operator edits,
  // keep their literal draft, and never borrow a name from a different query's reply.
  const resolvedUser = userFilter?.token === draft.user ? userFilter.display : null;
  const userValue = !userEdited && isPersonToken(draft.user) ? resolvedUser || words.resolvedUser : draft.user;
  function apply(example = false) {
    let since: string | undefined, until: string | undefined;
    try { since = timeBound(draft.since, filters.since); until = timeBound(draft.until, filters.until); }
    catch { setError(words.invalidTime); return; }
    if (since && until && new Date(since) >= new Date(until)) { setError(words.reversed); return; }
    if (!example && draft.changedTo && !draft.field) { setError(words.fieldRequired); return; }
    onApply({
      field: draft.field || undefined,
      // An empty exact target from a shared URL is still a filter. Changing the field
      // clears it; applying unrelated historical dimensions preserves it.
      changedTo: draft.changedTo || (filters.changedTo === "" && draft.field === filters.field ? "" : undefined), since, until,
      connectionId: draft.connectionId ? Number(draft.connectionId) : undefined,
      model: draft.model.trim() || undefined, osVersion: draft.osVersion.trim() || undefined,
      fileVault: draft.fileVault || undefined, site: draft.site.trim() || undefined,
      department: draft.department.trim() || undefined, managed: draft.managed || undefined, user: draft.user.trim() || undefined,
      ...(example ? { section: "operating_system", field: "version", changedTo: "27.2.1", change: "changed",
        subjectKind: "computer", artifact: undefined, version: undefined, spanId: undefined, trigger: undefined,
        level: undefined, minLevel: undefined } : {})
    });
  }
  return <form className="space-y-4 rounded-lg border bg-card p-4" onSubmit={event => { event.preventDefault(); apply(); }}>
    <div className="flex flex-wrap items-end gap-3">
      <label className="space-y-1 text-sm"><span className="block">{words.field}</span>
        <select className={inputClasses} value={draft.field} onChange={event => edit("field", event.target.value)}>
          <option value="">{words.anyField}</option>
          {draft.field && !fields.some(field => field.field === draft.field) && <option value={draft.field}>{draft.field}</option>}
          {fields.map(field => <option key={field.field} value={field.field}>{field.label}</option>)}
        </select>
      </label>
      <label className="space-y-1 text-sm"><span className="block">{words.changedTo}</span>
        <input className={inputClasses} maxLength={512} value={draft.changedTo} disabled={!draft.field}
          onChange={event => edit("changedTo", event.target.value)} placeholder="27.2.1" />
      </label>
      <Button type="button" variant="outline" onClick={() => apply(true)}>{words.example}</Button>
    </div>
    <p className="text-xs text-muted-foreground">{words.scalarHint} {words.exampleHint}</p>
    {policyError && <p role="alert" className="text-sm text-destructive">{words.policyError} <Button type="button" variant="outline" size="sm" onClick={onRetry}>{words.retry}</Button></p>}
    <div className="flex flex-wrap gap-3">
      {(["since", "until"] as const).map(key => <label key={key} className="space-y-1 text-sm">
        <span className="block">{key === "since" ? words.start : words.end}</span>
        <input className={inputClasses} type="datetime-local" step="0.001" value={draft[key]} onChange={event => edit(key, event.target.value)} />
      </label>)}
    </div>
    <p className="text-xs text-muted-foreground">{words.zone} <strong>{browserZone() ?? Intl.DateTimeFormat().resolvedOptions().timeZone}</strong></p>
    <fieldset className="space-y-3"><legend className="text-sm font-semibold">{words.title}</legend>
      <p className="text-xs text-muted-foreground">{words.hint}</p>
      <div className="flex flex-wrap gap-3">
        <label className="space-y-1 text-sm"><span className="block">{words.connection}</span>
          <input className={inputClasses} type="number" min="1" step="1" value={draft.connectionId} onChange={event => edit("connectionId", event.target.value)} />
        </label>
        {DEVICE_TEXT_KEYS.map(key => <label key={key} className="space-y-1 text-sm"><span className="block">{words[key]}</span>
          <input className={inputClasses} value={key === "user" ? userValue : draft[key]}
            onChange={event => edit(key, event.target.value)} />
        </label>)}
        <label className="space-y-1 text-sm"><span className="block">{words.fileVault}</span>
          <select className={inputClasses} value={draft.fileVault} onChange={event => edit("fileVault", event.target.value)}>
            <option value="">{words.any}</option>
            {draft.fileVault && !(draft.fileVault in t.changes.fileVaultStates) && <option value={draft.fileVault}>{draft.fileVault}</option>}
            {Object.entries(t.changes.fileVaultStates).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>
        <label className="space-y-1 text-sm"><span className="block">{words.managed}</span>
          <select className={inputClasses} value={draft.managed} onChange={event => edit("managed", event.target.value)}>
            <option value="">{words.any}</option><option value="true">{words.yes}</option><option value="false">{words.no}</option>
          </select>
        </label>
      </div>
    </fieldset>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    <Button type="submit">{words.apply}</Button>
  </form>;
}
