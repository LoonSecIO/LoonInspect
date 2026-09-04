import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { listChanges } from "@/features/changes/api";
import type { ChangeFilters, ChangeLevel, DeviceChange } from "@/features/changes/types";
import { useLocale } from "@/i18n/LocaleContext";

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

const asLevel = (value: string | null): ChangeLevel | undefined =>
  value === "high" || value === "normal" || value === "low" ? value : undefined;

function filtersFromParams(params: URLSearchParams): ChangeFilters {
  return {
    q: params.get("q") ?? undefined,
    artifact: params.get("artifact") ?? undefined,
    level: asLevel(params.get("level")),
    // #107: the Overview feed links here with `since` and `minLevel`. Before it read
    // them, that link landed on an unfiltered feed — the window silently dropped, which
    // is the failure the absolute anchor exists to prevent.
    minLevel: asLevel(params.get("minLevel")),
    since: params.get("since") ?? undefined,
    section: params.get("section") ?? undefined,
    page: params.get("page") ? Number(params.get("page")) : 1
  };
}

function paramsFromFilters(filters: ChangeFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.artifact) params.set("artifact", filters.artifact);
  if (filters.level) params.set("level", filters.level);
  if (filters.minLevel) params.set("minLevel", filters.minLevel);
  if (filters.since) params.set("since", filters.since);
  if (filters.section) params.set("section", filters.section);
  if (filters.page && filters.page !== 1) params.set("page", String(filters.page));
  return params;
}

function renderValue(value: Record<string, unknown> | null): string {
  if (value === null) return "—";
  if ("value" in value && Object.keys(value).length === 1) {
    const inner = value.value;
    if (inner === null || inner === undefined) return "—";
    if (Array.isArray(inner)) return inner.map(String).join(", ");
    return String(inner);
  }
  return JSON.stringify(value);
}

export function ChangesPage() {
  const { t } = useLocale();
  const tc = t.changes;
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => filtersFromParams(searchParams), [searchParams]);
  const [rows, setRows] = useState<DeviceChange[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [draftQuery, setDraftQuery] = useState(filters.q ?? "");
  const [draftArtifact, setDraftArtifact] = useState(filters.artifact ?? "");
  const pageSize = 50;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    listChanges({ ...filters, pageSize })
      .then((response) => {
        if (cancelled) return;
        setRows(response.items);
        setTotal(response.total);
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
  }, [filters, tc.errorLoading]);

  function update(next: Partial<ChangeFilters>) {
    // Picking an exact level drops the range one. Arriving from the Overview feed puts
    // `minLevel` in the URL, and the API refuses both together (#107) — so without this,
    // the first touch of the dropdown would turn a working feed into a 422 the operator
    // did nothing to deserve.
    const cleared = "level" in next && next.level ? { minLevel: undefined } : {};
    setSearchParams(paramsFromFilters({ ...filters, ...next, ...cleared, page: next.page ?? 1 }));
  }

  function describe(row: DeviceChange): string {
    if (row.field) return `${row.section} · ${row.field}`;
    const kind = row.entryKind ? tc.entryKinds[row.entryKind] ?? row.entryKind : row.section;
    const identity = row.entryLabel ?? summarizeIdentity(row.entryIdentity);
    return identity ? `${kind} · ${identity}` : kind;
  }

  function summarizeIdentity(identity: Record<string, unknown> | null): string {
    if (!identity) return "";
    const preferred = ["name", "username", "groupId", "profileIdentifier", "definitionId", "commonName"];
    for (const key of preferred) {
      if (identity[key] !== undefined && identity[key] !== null) return String(identity[key]);
    }
    return Object.values(identity).map(String).join(" ");
  }

  function detailText(row: DeviceChange): string | null {
    const details = row.details ?? {};
    const parts: string[] = [];
    if (typeof details.systemAppsUpdated === "number") parts.push(tc.systemAppsUpdated(details.systemAppsUpdated));
    if (typeof details.collapsedSystemApps === "number") parts.push(tc.systemAppsUpdated(details.collapsedSystemApps));
    if (details.criteriaChanged === true) parts.push(tc.criteriaMoved);
    if (details.criteriaChanged === false) parts.push(tc.deviceDrifted);
    if (Array.isArray(details.changedFields)) parts.push(tc.changedFields(details.changedFields.map(String).join(", ")));
    return parts.length ? parts.join(" · ") : null;
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = filters.page ?? 1;

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.nav.devices}</p>
        <h1 className="text-3xl font-bold tracking-tight">{tc.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{tc.description}</p>
      </div>

      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          update({ q: draftQuery.trim() || undefined, artifact: draftArtifact.trim() || undefined });
        }}
      >
        <label className="space-y-1 text-sm">
          <span className="block text-muted-foreground">{tc.search}</span>
          <input className={inputClasses} value={draftQuery} onChange={(e) => setDraftQuery(e.target.value)} placeholder={tc.searchPlaceholder} />
        </label>
        {/* Deliberately its own box rather than a mode switch on the one above: the two
            compose, and the pair "this fleet" + "this app" is the whole investigation. */}
        <label className="space-y-1 text-sm">
          <span className="block text-muted-foreground">{tc.artifact}</span>
          <input className={inputClasses} value={draftArtifact} onChange={(e) => setDraftArtifact(e.target.value)} placeholder={tc.artifactPlaceholder} />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-muted-foreground">{tc.level}</span>
          <select
            className={inputClasses}
            value={filters.level ?? ""}
            onChange={(e) => update({ level: (e.target.value || undefined) as ChangeLevel | undefined })}
          >
            <option value="">{tc.anyLevel}</option>
            <option value="high">{tc.levels.high}</option>
            <option value="normal">{tc.levels.normal}</option>
            <option value="low">{tc.levels.low}</option>
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-muted-foreground">{tc.section}</span>
          <input className={inputClasses} value={filters.section ?? ""} onChange={(e) => update({ section: e.target.value || undefined })} placeholder="security" />
        </label>
        <Button type="submit" variant="outline" size="sm">
          {tc.apply}
        </Button>
      </form>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{tc.colWhen}</th>
              <th className="px-4 py-2 font-medium">{tc.colDevice}</th>
              <th className="px-4 py-2 font-medium">{tc.colWhat}</th>
              <th className="px-4 py-2 font-medium">{tc.colChange}</th>
              <th className="px-4 py-2 font-medium">{tc.colFrom}</th>
              <th className="px-4 py-2 font-medium">{tc.colTo}</th>
              <th className="px-4 py-2 font-medium">{tc.level}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={7}>{tc.loading}</td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={7}>{tc.empty}</td>
              </tr>
            )}
            {rows.map((row) => {
              const detail = detailText(row);
              return (
                <tr key={row.id} className="border-b align-top last:border-0">
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">{new Date(row.observedAt).toLocaleString()}</td>
                  <td className="px-4 py-2">
                    <div>{row.subjectLabel ?? row.subjectId}</div>
                    <div className="text-xs text-muted-foreground">{row.serialNumber ?? row.subjectKind}</div>
                  </td>
                  <td className="px-4 py-2">
                    <div>{describe(row)}</div>
                    {detail && <div className="text-xs text-muted-foreground">{detail}</div>}
                  </td>
                  <td className="px-4 py-2">{tc.changeKinds[row.change] ?? row.change}</td>
                  <td className="max-w-xs truncate px-4 py-2 text-xs" title={renderValue(row.oldValue)}>
                    {row.change === "added" ? "—" : renderValue(row.oldValue)}
                  </td>
                  <td className="max-w-xs truncate px-4 py-2 text-xs" title={renderValue(row.newValue)}>
                    {row.change === "removed" ? "—" : renderValue(row.newValue)}
                  </td>
                  <td className="px-4 py-2">
                    <span className={row.level === "high" ? "font-medium text-destructive" : row.level === "low" ? "text-muted-foreground" : ""}>
                      {tc.levels[row.level]}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>{tc.count(total)}</span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => update({ page: page - 1 })}>
            {tc.previous}
          </Button>
          <span className="self-center">{tc.pageOf(page, totalPages)}</span>
          <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => update({ page: page + 1 })}>
            {tc.next}
          </Button>
        </div>
      </div>
    </section>
  );
}
