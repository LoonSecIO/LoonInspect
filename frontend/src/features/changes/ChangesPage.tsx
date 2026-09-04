import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { Button } from "@/components/ui/button";
import { getChangePolicy, listChanges } from "@/features/changes/api";
import {
  artifactValueOf,
  diffLines,
  labelsFromPolicy,
  SECTION_ORDER,
  whatOf,
  type DiffLine,
  type LabelMap
} from "@/features/changes/render";
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

/**
 * What moved, field by field.
 *
 * Values wrap rather than truncate. The column exists because truncation put an app's new
 * version off the right-hand edge while the two cells beside it stayed identical for their
 * whole visible width — so a cell that runs long here takes a second line instead.
 */
function DiffCell({ lines }: { lines: DiffLine[] }) {
  // Nothing to pair: the collapsed-system-apps row carries a count and no entry, and its
  // sentence is already printed under What.
  if (lines.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <div className="max-w-sm space-y-0.5 break-words">
      {lines.map((line) => (
        <div key={line.key} className="flex flex-wrap items-baseline gap-x-2">
          {line.label && <span className="text-xs text-muted-foreground">{line.label}</span>}
          <span className="font-mono text-xs">
            {line.pair ? (
              <>
                <span className="text-muted-foreground">{line.from ?? "—"}</span>
                <span className="px-1.5 text-muted-foreground">→</span>
                <span className="font-medium text-foreground">{line.to ?? "—"}</span>
              </>
            ) : (
              (line.from ?? line.to)
            )}
          </span>
        </div>
      ))}
    </div>
  );
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
  const [labels, setLabels] = useState<LabelMap>({});
  const pageSize = 50;

  // The two text boxes are drafts — typed, then applied. They still have to follow the URL
  // when something else moves it: the back button, and a click on an identity in the table
  // below, which sets `artifact` without going through the box. Adjusted during render
  // rather than from an effect (React's own "adjusting state when a prop changes"), so the
  // box never paints a frame still showing the filter that was just replaced.
  const applied = { q: filters.q ?? "", artifact: filters.artifact ?? "" };
  const [lastApplied, setLastApplied] = useState(applied);
  if (lastApplied.q !== applied.q || lastApplied.artifact !== applied.artifact) {
    setLastApplied(applied);
    setDraftQuery(applied.q);
    setDraftArtifact(applied.artifact);
  }

  // Field labels only — "Version" rather than `version`, "Bundle version" rather than
  // `cfBundleVersion`. The policy document already carries one for every field the ledger
  // can log and needs no permission this page does not already hold, and a failure here
  // degrades to the raw field name rather than to a missing control, which is why the
  // *section* list beside it is a constant instead of a second read of this document.
  useEffect(() => {
    let cancelled = false;
    getChangePolicy()
      .then((policy) => {
        if (!cancelled) setLabels(labelsFromPolicy(policy));
      })
      .catch(() => {
        /* raw field names are a fine answer; nothing to tell the operator */
      });
    return () => {
      cancelled = true;
    };
  }, []);

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

  const sectionLabels = useMemo(
    () => ({
      section: (name: string) => tc.sections[name] ?? name,
      entryKind: (kind: string) => tc.entryKinds[kind] ?? kind
    }),
    [tc]
  );

  function detailText(row: DeviceChange): string | null {
    const details = row.details ?? {};
    const parts: string[] = [];
    if (typeof details.systemAppsUpdated === "number") parts.push(tc.systemAppsUpdated(details.systemAppsUpdated));
    if (typeof details.collapsedSystemApps === "number") parts.push(tc.systemAppsUpdated(details.collapsedSystemApps));
    if (details.criteriaChanged === true) parts.push(tc.criteriaMoved);
    if (details.criteriaChanged === false) parts.push(tc.deviceDrifted);
    // `changedFields` is no longer named here: the What-changed column prints those fields
    // with both of their values, which is what naming them was standing in for.
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
        className="flex flex-wrap items-start gap-3"
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
            compose, and the pair "this fleet" + "this app" is the whole investigation.
            The hint names what it refuses, because the API refuses those on purpose and
            a reasonable guess would otherwise be answered with an empty feed. */}
        <label className="space-y-1 text-sm">
          <span className="block text-muted-foreground">{tc.artifact}</span>
          <span className="relative block">
            <input
              className={`${inputClasses} pr-8`}
              value={draftArtifact}
              onChange={(e) => setDraftArtifact(e.target.value)}
              placeholder={tc.artifactPlaceholder}
            />
            {filters.artifact && (
              <button
                type="button"
                className="absolute inset-y-0 right-0 px-2 text-muted-foreground hover:text-foreground"
                onClick={() => update({ artifact: undefined })}
                aria-label={tc.clearFilter}
              >
                ✕
              </button>
            )}
          </span>
          <span className="block max-w-xs text-xs text-muted-foreground">{tc.artifactHint}</span>
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
        {/* A closed vocabulary of fifteen snake_case names, so it is picked and not typed.
            As a text box this was the one route to a whole entry kind — a certificate
            carries no label and is reachable by section alone — behind a control whose
            only hint was the word "security", where a near miss returned an empty feed. */}
        <label className="space-y-1 text-sm">
          <span className="block text-muted-foreground">{tc.section}</span>
          <select
            className={inputClasses}
            value={filters.section ?? ""}
            onChange={(e) => update({ section: e.target.value || undefined })}
          >
            <option value="">{tc.anySection}</option>
            {SECTION_ORDER.map((name) => (
              <option key={name} value={name}>
                {tc.sections[name] ?? name}
              </option>
            ))}
          </select>
        </label>
        <Button type="submit" variant="outline" size="sm" className="mt-6">
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
              <th className="px-4 py-2 font-medium">{tc.colWhatChanged}</th>
              <th className="px-4 py-2 font-medium">{tc.level}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>{tc.loading}</td>
              </tr>
            )}
            {!loading && rows.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>{tc.empty}</td>
              </tr>
            )}
            {rows.map((row) => {
              const detail = detailText(row);
              const what = whatOf(row, labels, sectionLabels);
              // Offered only where the filter would actually find the row again — see
              // `artifactValueOf`. A certificate and a field change get plain text.
              const artifact = artifactValueOf(row);
              return (
                <tr key={row.id} className="border-b align-top last:border-0">
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-muted-foreground">{new Date(row.observedAt).toLocaleString()}</td>
                  <td className="px-4 py-2">
                    <div>{row.subjectLabel ?? row.subjectId}</div>
                    <div className="text-xs text-muted-foreground">{row.serialNumber ?? row.subjectKind}</div>
                  </td>
                  <td className="px-4 py-2">
                    <div className="text-xs text-muted-foreground">{what.head}</div>
                    {what.identity &&
                      (artifact ? (
                        <button
                          type="button"
                          className="text-left underline decoration-dotted underline-offset-4 hover:decoration-solid"
                          title={tc.filterTo(artifact)}
                          onClick={() => update({ artifact })}
                        >
                          {what.identity}
                        </button>
                      ) : (
                        <div>{what.identity}</div>
                      ))}
                    {detail && <div className="text-xs text-muted-foreground">{detail}</div>}
                  </td>
                  <td className="px-4 py-2">{tc.changeKinds[row.change] ?? row.change}</td>
                  <td className="px-4 py-2">
                    <DiffCell lines={diffLines(row, labels)} />
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
