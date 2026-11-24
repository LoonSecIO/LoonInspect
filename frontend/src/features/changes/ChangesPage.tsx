import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { ApiError } from "@/config/api";
import { HistoricalFilters } from "@/features/changes/HistoricalFilters";
import { asChange, filtersFromParams, paramsFromFilters } from "@/features/changes/filters";
import { Button } from "@/components/ui/button";
import { LoonLoading } from "@/components/icons/LoonLoading";
import { getChangePolicy, listChanges } from "@/features/changes/api";
import { changeResetLine, emptyTable } from "@/features/changes/changeKinds";
import { DiffCell } from "@/features/changes/DiffCell";
import { PromptBar } from "@/features/changes/PromptBar";
import { rowUserName, rowUserToken, userChipLabel, userTokenRewrite } from "@/features/changes/personToken";
import { hasSomethingToClear } from "@/features/changes/prompt";
import {
  artifactValueOf,
  canMatch,
  CHANGE_KINDS,
  detailText,
  diffLines,
  kindsRecordedBy,
  departmentNamesFromPolicy,
  labelsFromPolicy,
  SECTION_ORDER,
  whatOf,
  type LabelMap
} from "@/features/changes/render";
import { HIDDEN_KEYS } from "@/features/changes/types";
import type { ChangeFilters, ChangeLevel, ChangePolicy, DeviceChange, UserFilter } from "@/features/changes/types";
import { useLocale } from "@/i18n/LocaleContext";

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

export function ChangesPage() {
  const { t } = useLocale();
  const tc = t.changes;
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => filtersFromParams(searchParams), [searchParams]);
  const [rows, setRows] = useState<DeviceChange[]>([]);
  const [total, setTotal] = useState(0);
  const [devicesTotal, setDevicesTotal] = useState(0);
  const [policy, setPolicy] = useState<ChangePolicy | null>(null);
  const [policyError, setPolicyError] = useState(false);
  const [policyRetry, setPolicyRetry] = useState(0);
  const [filterDraftDirty, setFilterDraftDirty] = useState(false);
  // What the applied `user` filter resolved to (#446): a name for its chip, and for typed text
  // the token to put in the URL in its place.
  const [userFilter, setUserFilter] = useState<UserFilter | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [draftQuery, setDraftQuery] = useState(filters.q ?? "");
  const [draftArtifact, setDraftArtifact] = useState(filters.artifact ?? "");
  const [labels, setLabels] = useState<LabelMap>({});
  // Department id to name, for the chip a `department` filter shows (#450). Empty until the
  // policy document loads, and for any id whose name is not unambiguous: then the id shows.
  const [departmentNames, setDepartmentNames] = useState<Record<string, string>>({});
  // Re-runs the fetch when the filters did not move — see `applyPrompt`.
  const [reloadToken, setReloadToken] = useState(0);
  // The Prompt bar's session, which Clear replaces, and whether it has been used since.
  const [promptSession, setPromptSession] = useState(0);
  const [promptUsed, setPromptUsed] = useState(false);
  // The section whose choice just put Change back to Any change, and the URL that choice
  // produced (`chooseSection`). The line saying so shows only while the address is that
  // URL. Every move the page makes itself (another filter, a page, the Prompt bar, Clear)
  // forgets it, so coming back to the same address that way does not bring the line back.
  // Back and Forward are compared rather than cleared, since the router commits a URL in
  // a transition, a render or two after this state is set: Back hides the line, and
  // Forward to the address the choice produced shows it again, because it is again true.
  const [changeReset, setChangeReset] = useState<{ section: string; at: string } | null>(null);
  const pageSize = 50;
  const [historyVisit, setHistoryVisit] = useState(0);
  // Back can cancel a pending router transition before the new query renders. The
  // restored query then equals the old one, so following the URL alone retains edited drafts.
  // Native history visits still reset those drafts to the applied query, without a fetch.
  useEffect(() => {
    const visit = () => { setHistoryVisit(value => value + 1); setFilterDraftDirty(false); };
    window.addEventListener("popstate", visit);
    return () => window.removeEventListener("popstate", visit);
  }, []);

  // The two text boxes are drafts — typed, then applied. They still have to follow the URL
  // when something else moves it: the back button, and a click on an identity in the table
  // below, which sets `artifact` without going through the box. Adjusted during render
  // rather than from an effect (React's own "adjusting state when a prop changes"), so the
  // box never paints a frame still showing the filter that was just replaced.
  const applied = { q: filters.q ?? "", artifact: filters.artifact ?? "", historyVisit };
  const [lastApplied, setLastApplied] = useState(applied);
  if (lastApplied.q !== applied.q || lastApplied.artifact !== applied.artifact || lastApplied.historyVisit !== historyVisit) {
    setLastApplied(applied);
    setDraftQuery(applied.q);
    setDraftArtifact(applied.artifact);
  }

  // The policy supplies field labels and scalar choices without extra permissions.
  // A failed read keeps existing queries usable and offers a visible retry for choices.
  useEffect(() => {
    let cancelled = false;
    getChangePolicy()
      .then((policy) => {
        if (cancelled) return;
        setPolicy(policy);
        setPolicyError(false);
        setLabels(labelsFromPolicy(policy));
        setDepartmentNames(departmentNamesFromPolicy(policy));
      })
      .catch(() => {
        if (!cancelled) setPolicyError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [policyRetry]);

  // A new question — moved filters, or the Prompt bar re-asking the same one — has to
  // read as a question being asked, not as the last answer. Adjusted here, during the
  // render that changed it, for the same reason the draft boxes above are: from an
  // effect it lands a render late, and the table paints one frame of the previous
  // filter's rows as though they were the answer. Keyed on everything the fetch below
  // re-runs for, the locale's error sentence included, or a language switch would re-fetch
  // and clear nothing — the last failure's line left standing over the new rows.
  const asking = { filters, reloadToken, errorLoading: tc.errorLoading };
  const [asked, setAsked] = useState(asking);
  if (asked.filters !== filters || asked.reloadToken !== reloadToken || asked.errorLoading !== asking.errorLoading) {
    setAsked(asking);
    setLoading(true);
    setError(null);
  }

  useEffect(() => {
    let cancelled = false;
    listChanges({ ...filters, pageSize })
      .then((response) => {
        if (cancelled) return;
        setRows(response.items);
        setTotal(response.total);
        setDevicesTotal(response.devicesTotal);
        setUserFilter(response.userFilter ?? null);
        // A typed name that found one person leaves the address bar before anyone copies it.
        const rewritten = userTokenRewrite(filters.user, response.userFilter);
        if (rewritten) setSearchParams(paramsFromFilters({ ...filters, user: rewritten }), { replace: true });
      })
      .catch((failure: unknown) => {
        if (!cancelled) setError(failure instanceof ApiError && failure.detail ? failure.detail : tc.errorLoading);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filters, reloadToken, tc.errorLoading, setSearchParams]);

  function nextParams(next: Partial<ChangeFilters>): URLSearchParams {
    // Picking an exact level drops the range one. Arriving from the Overview feed puts
    // `minLevel` in the URL, and the API refuses both together (#107) — so without this,
    // the first touch of the dropdown would turn a working feed into a 422 the operator
    // did nothing to deserve.
    const cleared = "level" in next && next.level ? { minLevel: undefined } : {};
    return paramsFromFilters({ ...filters, ...next, ...cleared, page: next.page ?? 1 });
  }

  function update(next: Partial<ChangeFilters>) {
    setSearchParams(nextParams(next));
    setChangeReset(null);
  }

  // A list section's entries are added, removed or updated; every other section's values
  // are only ever changed (#437). A section that rules out the Change already set would
  // leave a pair no row can match, so the choice takes Change back to Any change in the
  // same move, and the line under the filters says so rather than let it vanish unseen.
  function chooseSection(section: string | undefined) {
    const reset = !canMatch(section, filters.change);
    const params = nextParams({ section, field: undefined, changedTo: undefined, ...(reset ? { change: undefined } : {}) });
    setSearchParams(params);
    setChangeReset(reset && section ? { section, at: params.toString() } : null);
  }

  // The Prompt bar's answer goes through the same URL as every control. An answer naming
  // the filters already on screen moves no URL, so nothing would re-fetch, and the
  // response box — counted just now — would sit over a table loaded earlier that can
  // disagree with it. Only then does the token re-run the fetch: a moved URL re-fetches on
  // its own, and the router applies it in a transition, so bumping the token as well would
  // fetch twice.
  function applyPrompt(next: Partial<ChangeFilters>) {
    const params = nextParams(next);
    if (params.toString() === searchParams.toString()) setReloadToken((token) => token + 1);
    else setSearchParams(params);
    setChangeReset(null);
  }

  // Back to the unfiltered feed's first page in one press: every key the URL can carry
  // goes, the ones only a link sets (`since`, `minLevel`, the device chip) with the rest.
  // The drafts empty, and the Prompt bar starts a new session — its box and answer gone,
  // a question still in flight dropped with the old session. A URL already empty is left
  // alone, so Clear adds no history entry then.
  function clearAll() {
    if (searchParams.toString() !== "") setSearchParams(new URLSearchParams());
    setDraftQuery("");
    setDraftArtifact("");
    setFilterDraftDirty(false);
    setPromptSession((session) => session + 1);
    setPromptUsed(false);
    setChangeReset(null);
  }

  const canClear = filterDraftDirty || hasSomethingToClear(filters, { q: draftQuery, artifact: draftArtifact }, promptUsed);

  // One chip per filter with no control of its own, in the order they were added to the page.
  // `since` keeps the table's own time format; a dimension is shown as the value it matched,
  // because that is what a reader has to compare against the rows (#447).
  const hiddenChips = useMemo(() => {
    const words = tc.hiddenChips;
    const of: Partial<Record<keyof ChangeFilters, (value: string) => string>> = {
      since: (value) => tc.sinceChip(new Date(value).toLocaleString()),
      until: (value) => `${tc.historical.end}: ${new Date(value).toLocaleString()}`,
      trigger: (value) => words.trigger(tc.triggers[value] ?? value),
      spanId: () => words.span,
      version: words.version,
      model: words.model,
      osVersion: words.osVersion,
      fileVault: (value) => words.fileVault(tc.fileVaultStates[value] ?? value),
      site: words.site,
      department: (value) => (departmentNames[value] ? words.departmentNamed(departmentNames[value]) : words.department(value)),
      managed: (value) => (value === "false" ? words.unmanaged : words.managed),
      // Never the token itself, which names nobody a reader can recognise.
      user: (value) => userChipLabel(value, userFilter, words.person)
    };
    const chips: { key: keyof ChangeFilters; label: string }[] = [];
    for (const key of ["since", "until", ...HIDDEN_KEYS] as const) {
      const value = filters[key];
      if (value) chips.push({ key, label: of[key]?.(value) ?? value });
    }
    if (filters.subjectKind && !filters.subjectId) {
      chips.push({ key: "subjectKind", label: `${tc.historical.subjectKind}: ${tc.historical.subjectKinds[filters.subjectKind] ?? filters.subjectKind}` });
    }
    return chips;
  }, [filters, tc, departmentNames, userFilter]);

  const sectionLabels = useMemo(
    () => ({
      section: (name: string) => tc.sections[name] ?? name,
      entryKind: (kind: string) => tc.entryKinds[kind] ?? kind
    }),
    [tc]
  );

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = filters.page ?? 1;
  // With a section chosen, the kinds it records; with Any section, all four.
  const recorded = kindsRecordedBy(filters.section);
  const resetLine = changeReset && changeReset.at === searchParams.toString() ? changeResetLine(changeReset.section, tc) : null;
  const empty = emptyTable(filters, total, tc);

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
          <input data-page-search="" className={inputClasses} value={draftQuery} onChange={(e) => setDraftQuery(e.target.value)} placeholder={tc.searchPlaceholder} />
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
        {/* Added, removed, updated or changed, labelled as the Change column labels a row.
            "New application installs" is Applications and Added; without this the pair
            was every application change there is, updates included. A kind the chosen
            section never records is greyed out rather than offered to match nothing
            (#437); with Any section, all four are there. */}
        <label className="space-y-1 text-sm">
          <span className="block text-muted-foreground">{tc.change}</span>
          <select
            className={inputClasses}
            value={filters.change ?? ""}
            onChange={(e) => update({ change: asChange(e.target.value) })}
          >
            <option value="">{tc.anyChange}</option>
            {CHANGE_KINDS.map((kind) => (
              <option key={kind} value={kind} disabled={!recorded.includes(kind)}>
                {tc.changeKinds[kind] ?? kind}
              </option>
            ))}
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
            onChange={(e) => chooseSection(e.target.value || undefined)}
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
        {/* Quieter than Apply, which it undoes. Disabled with nothing to clear
            (`hasSomethingToClear`), so the page never offers a press that does nothing. */}
        <Button type="button" variant="ghost" size="sm" className="mt-6" disabled={!canClear} title={tc.clearAllTitle} onClick={clearAll}>
          {tc.clearAll}
        </Button>
        {/* Under the controls, on a row of its own: the Change filter the operator set
            just went back to Any change, and this is the only place that says so. */}
        {resetLine && (
          <p className="basis-full text-sm text-muted-foreground" role="status">
            {resetLine}
          </p>
        )}
      </form>

      <HistoricalFilters key={`${promptSession}:${historyVisit}`} filters={filters} policy={policy}
        policyError={policyError} userFilter={userFilter} onApply={update} onDirtyChange={setFilterDraftDirty}
        onRetry={() => setPolicyRetry(value => value + 1)} />
      <p className="text-sm text-muted-foreground">{tc.historical.observationHint}</p>
      <PromptBar filters={filters} onApply={applyPrompt} onUse={setPromptUsed} session={promptSession} />

      {/* Every filter this page has no control for, named while it is applied and removable:
          the window the Overview's feed links here with (#107, #443), and the ten dimensions a
          link, a click on a row or the Prompt bar can set (#447). Before them, such a filter
          narrowed the table with nothing on screen to say so. */}
      {hiddenChips.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {hiddenChips.map((chip) => (
            <button
              key={chip.key}
              type="button"
              className="inline-flex items-center gap-2 rounded-full border bg-muted px-3 py-1 text-xs"
              onClick={() => update({ [chip.key]: undefined })}
            >
              {chip.label}
              <span aria-hidden="true">×</span>
              <span className="sr-only">{tc.clearFilter}</span>
            </button>
          ))}
        </div>
      )}

      {/* A subject the form has no control for (the device page's "all changes on this
          Mac" link, #300) shows as a removable chip, so a filter the page applies is never
          one the page hides. Named by the rows' own label when there is one. */}
      {filters.subjectId && (
        <button
          type="button"
          className="inline-flex items-center gap-2 rounded-full border bg-muted px-3 py-1 text-xs"
          onClick={() => update({ subjectId: undefined, subjectKind: undefined, connectionId: undefined })}
        >
          {tc.subjectChip(rows[0]?.subjectLabel ?? filters.subjectId)}
          <span aria-hidden="true">×</span>
          <span className="sr-only">{tc.clearFilter}</span>
        </button>
      )}

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
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}><LoonLoading label={tc.loading} /></td>
              </tr>
            )}
            {/* Which empty this is, never one sentence for all of them (`emptyTable`): a
                filtered page with no rows is not an empty log, and a pair that can never
                match says why. Not shown under a failed load, which is not empty either —
                the error line above says what it is. */}
            {!loading && !error && rows.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  <p>{empty.lead}</p>
                  {empty.reason && <p className="mt-1">{empty.reason}</p>}
                </td>
              </tr>
            )}
            {!loading && !error && rows.map((row) => {
              const detail = detailText(row, tc);
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
                    {/* The one stamped dimension the row shows (#447), and it is shown because it
                        is how the rest are discovered: a filter nobody can find is a filter
                        nobody uses, and the identity above already works this way. */}
                    {typeof row.deviceMeta?.model === "string" && (
                      <button
                        type="button"
                        className="text-left text-xs text-muted-foreground underline decoration-dotted underline-offset-4 hover:decoration-solid"
                        title={tc.filterTo(row.deviceMeta.model)}
                        onClick={() => update({ model: String(row.deviceMeta?.model) })}
                      >
                        {row.deviceMeta.model}
                      </button>
                    )}
                    {/* Reads as a name, filters as a token (#446): the URL gets `rowUserToken`. */}
                    {rowUserToken(row) && rowUserName(row) && (
                      <button
                        type="button"
                        className="block text-left text-xs text-muted-foreground underline decoration-dotted underline-offset-4 hover:decoration-solid"
                        title={tc.filterTo(rowUserName(row) as string)}
                        onClick={() => update({ user: rowUserToken(row) })}
                      >
                        {rowUserName(row)}
                      </button>
                    )}
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
        <span role="status">{loading ? tc.loading : error ? "—" : tc.matching(total, devicesTotal)}</span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={loading || !!error || page <= 1} onClick={() => update({ page: page - 1 })}>
            {tc.previous}
          </Button>
          <span className="self-center">{!loading && !error && tc.pageOf(page, totalPages)}</span>
          <Button variant="outline" size="sm" disabled={loading || !!error || page >= totalPages} onClick={() => update({ page: page + 1 })}>
            {tc.next}
          </Button>
        </div>
      </div>
    </section>
  );
}
