import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { getChangePolicy, putChangePolicy } from "@/features/changes/api";
import type { ChangeLevel, ChangePolicy, ChangePolicyUpdate } from "@/features/changes/types";
import { useLocale } from "@/i18n/LocaleContext";

const inputClasses =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

function toUpdate(policy: ChangePolicy, fields: Record<string, boolean>, entries: Record<string, boolean>): ChangePolicyUpdate {
  return {
    minimumLevel: policy.minimumLevel,
    fields,
    entries,
    systemAppsIndividually: policy.systemAppsIndividually,
    mutedGroups: policy.mutedGroups,
    mutedExtensionAttributes: policy.mutedExtensionAttributes
  };
}

/** Settings → Change tracking: every field and entry kind the ledger can observe, with its
 *  default pre-set by level and the reason beside it. Admins flip what they want; the
 *  server stores only the flips, so untouched rows follow future defaults. */
export function ChangeTrackingPage() {
  const { t } = useLocale();
  const tc = t.changeTracking;
  const canWrite = useHasPermission(PERMISSIONS.CONNECTION_WRITE);

  const [policy, setPolicy] = useState<ChangePolicy | null>(null);
  const [fieldOverrides, setFieldOverrides] = useState<Record<string, boolean>>({});
  const [entryOverrides, setEntryOverrides] = useState<Record<string, boolean>>({});
  const [minimumLevel, setMinimumLevel] = useState<ChangeLevel>("normal");
  const [systemApps, setSystemApps] = useState(false);
  const [mutedGroups, setMutedGroups] = useState<string[]>([]);
  const [mutedEas, setMutedEas] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [showLow, setShowLow] = useState(false);

  function adopt(next: ChangePolicy) {
    setPolicy(next);
    setMinimumLevel(next.minimumLevel);
    setSystemApps(next.systemAppsIndividually);
    setMutedGroups(next.mutedGroups);
    setMutedEas(next.mutedExtensionAttributes);
    const fields: Record<string, boolean> = {};
    for (const section of next.sections) for (const f of section.fields) if (f.overridden) fields[f.key] = f.enabled;
    const entries: Record<string, boolean> = {};
    for (const e of next.entries) {
      if (e.overridden) {
        entries[`${e.kind}.added`] = e.added;
        entries[`${e.kind}.removed`] = e.removed;
        for (const f of e.fields) if (f.overridden) entries[`${e.kind}.${f.name}`] = f.enabled;
      }
    }
    setFieldOverrides(fields);
    setEntryOverrides(entries);
  }

  useEffect(() => {
    let cancelled = false;
    getChangePolicy()
      .then((next) => {
        if (!cancelled) adopt(next);
      })
      .catch(() => {
        if (!cancelled) setError(tc.errorLoading);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const rank: Record<ChangeLevel, number> = { high: 0, normal: 1, low: 2 };
  const defaultOn = (level: ChangeLevel) => rank[level] <= rank[minimumLevel];
  const fieldOn = (key: string, level: ChangeLevel) => (key in fieldOverrides ? fieldOverrides[key] : defaultOn(level));
  const entryOn = (key: string, level: ChangeLevel) => (key in entryOverrides ? entryOverrides[key] : defaultOn(level));

  function setField(key: string, level: ChangeLevel, value: boolean) {
    setFieldOverrides((current) => {
      const next = { ...current };
      if (value === defaultOn(level)) delete next[key];
      else next[key] = value;
      return next;
    });
  }

  function setEntry(key: string, level: ChangeLevel, value: boolean) {
    setEntryOverrides((current) => {
      const next = { ...current };
      if (value === defaultOn(level)) delete next[key];
      else next[key] = value;
      return next;
    });
  }

  async function handleSave() {
    if (!policy) return;
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const next = await putChangePolicy({
        ...toUpdate({ ...policy, minimumLevel, systemAppsIndividually: systemApps, mutedGroups, mutedExtensionAttributes: mutedEas }, fieldOverrides, entryOverrides)
      });
      adopt(next);
      setSaved(true);
    } catch (caught) {
      setError(caught instanceof ApiError && caught.detail ? caught.detail : tc.errorSaving);
    } finally {
      setSaving(false);
    }
  }

  function handleReset() {
    setFieldOverrides({});
    setEntryOverrides({});
    setMinimumLevel("normal");
    setSystemApps(false);
    setMutedGroups([]);
    setMutedEas([]);
  }

  if (loading) return <p className="text-sm text-muted-foreground">{tc.loading}</p>;
  if (!policy) return <p className="text-sm text-destructive">{error ?? tc.errorLoading}</p>;

  const overrideCount = Object.keys(fieldOverrides).length + Object.keys(entryOverrides).length;

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{tc.title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{tc.description}</p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
      {saved && <p className="text-sm text-muted-foreground">{tc.saved}</p>}

      <div className="space-y-3 rounded-lg border bg-card p-4">
        <h2 className="font-semibold">{tc.presetTitle}</h2>
        <p className="text-sm text-muted-foreground">{tc.presetHelp}</p>
        <div className="flex flex-wrap gap-4 text-sm">
          {(["high", "normal", "low"] as ChangeLevel[]).map((level) => (
            <label key={level} className="flex items-center gap-2">
              <input type="radio" name="minimumLevel" checked={minimumLevel === level} disabled={!canWrite} onChange={() => setMinimumLevel(level)} />
              {tc.presets[level]}
            </label>
          ))}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={systemApps} disabled={!canWrite} onChange={(e) => setSystemApps(e.target.checked)} />
          {tc.systemApps}
        </label>
        <p className="text-xs text-muted-foreground">{tc.systemAppsHelp}</p>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={showLow} onChange={(e) => setShowLow(e.target.checked)} />
          {tc.showLow}
        </label>
      </div>

      <div className="space-y-3 rounded-lg border bg-card p-4">
        <h2 className="font-semibold">{tc.entriesTitle}</h2>
        <div className="space-y-4">
          {policy.entries.map((entry) => (
            <div key={entry.kind} className="space-y-2 border-b pb-3 last:border-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-medium">{entry.label}</span>
                <span className="text-xs text-muted-foreground">{tc.levels[entry.level]}</span>
                <label className="flex items-center gap-1 text-sm">
                  <input type="checkbox" disabled={!canWrite} checked={entryOn(`${entry.kind}.added`, entry.level)} onChange={(e) => setEntry(`${entry.kind}.added`, entry.level, e.target.checked)} />
                  {tc.added}
                </label>
                <label className="flex items-center gap-1 text-sm">
                  <input type="checkbox" disabled={!canWrite} checked={entryOn(`${entry.kind}.removed`, entry.level)} onChange={(e) => setEntry(`${entry.kind}.removed`, entry.level, e.target.checked)} />
                  {tc.removed}
                </label>
              </div>
              <p className="text-xs text-muted-foreground">{entry.why}</p>
              {entry.fields.length > 0 && (
                <div className="grid gap-1 pl-4 sm:grid-cols-2 md:grid-cols-3">
                  {entry.fields
                    .filter((f) => showLow || f.level !== "low" || entryOn(`${entry.kind}.${f.name}`, f.level))
                    .map((f) => (
                      <label key={f.name} className="flex items-center gap-2 text-sm" title={f.why}>
                        <input type="checkbox" disabled={!canWrite} checked={entryOn(`${entry.kind}.${f.name}`, f.level)} onChange={(e) => setEntry(`${entry.kind}.${f.name}`, f.level, e.target.checked)} />
                        <span>
                          {f.label} <span className="text-xs text-muted-foreground">({tc.levels[f.level]})</span>
                        </span>
                      </label>
                    ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="space-y-3 rounded-lg border bg-card p-4">
        <h2 className="font-semibold">{tc.fieldsTitle}</h2>
        {policy.sections.map((section) => {
          const visible = section.fields.filter((f) => showLow || f.level !== "low" || fieldOn(f.key, f.level));
          if (visible.length === 0) return null;
          return (
            <div key={section.section} className="space-y-2 border-b pb-3 last:border-0 last:pb-0">
              <h3 className="text-sm font-medium">{tc.sections[section.section] ?? section.section}</h3>
              <div className="grid gap-1 sm:grid-cols-2 md:grid-cols-3">
                {visible.map((f) => (
                  <label key={f.key} className="flex items-center gap-2 text-sm" title={f.why}>
                    <input type="checkbox" disabled={!canWrite} checked={fieldOn(f.key, f.level)} onChange={(e) => setField(f.key, f.level, e.target.checked)} />
                    <span>
                      {f.label} <span className="text-xs text-muted-foreground">({tc.levels[f.level]})</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-2 rounded-lg border bg-card p-4">
          <h2 className="font-semibold">{tc.mutedGroups}</h2>
          <p className="text-xs text-muted-foreground">{tc.mutedGroupsHelp}</p>
          {policy.knownGroups.length === 0 && <p className="text-sm text-muted-foreground">{tc.noneKnown}</p>}
          <div className="grid gap-1">
            {policy.knownGroups.map((group) => (
              <label key={group.id} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  disabled={!canWrite}
                  checked={mutedGroups.includes(group.id)}
                  onChange={(e) => setMutedGroups((current) => (e.target.checked ? [...current, group.id] : current.filter((g) => g !== group.id)))}
                />
                {group.name ?? group.id} <span className="text-xs text-muted-foreground">#{group.id}</span>
              </label>
            ))}
          </div>
        </div>
        <div className="space-y-2 rounded-lg border bg-card p-4">
          <h2 className="font-semibold">{tc.mutedEas}</h2>
          <p className="text-xs text-muted-foreground">{tc.mutedEasHelp}</p>
          {policy.knownExtensionAttributes.length === 0 && <p className="text-sm text-muted-foreground">{tc.noneKnown}</p>}
          <div className="grid gap-1">
            {policy.knownExtensionAttributes.map((ea) => (
              <label key={ea.definitionId} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  disabled={!canWrite}
                  checked={mutedEas.includes(ea.definitionId)}
                  onChange={(e) =>
                    setMutedEas((current) => (e.target.checked ? [...current, ea.definitionId] : current.filter((id) => id !== ea.definitionId)))
                  }
                />
                {ea.name ?? ea.definitionId} <span className="text-xs text-muted-foreground">#{ea.definitionId}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      {canWrite && (
        <div className="flex items-center gap-3">
          <Button onClick={handleSave} disabled={saving}>
            {saving ? tc.saving : tc.save}
          </Button>
          <Button variant="outline" onClick={handleReset} disabled={saving}>
            {tc.reset}
          </Button>
          <span className="text-xs text-muted-foreground">{tc.overrideCount(overrideCount)}</span>
          <input className={`${inputClasses} hidden`} readOnly value={policy.version} />
        </div>
      )}
    </section>
  );
}
