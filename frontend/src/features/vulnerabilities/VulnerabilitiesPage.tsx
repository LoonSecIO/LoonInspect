import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { ApiError, apiRequest } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import { listCatalog } from "@/features/catalog/api";
import { LatestCell, PatchAnswerCell, Subject } from "@/features/catalog/PatchAnswerCell";
import type { CatalogBand, CatalogEntry, CatalogListResponse, CatalogVulnFilter } from "@/features/catalog/types";
import { AssessmentCell, CorpusBanner } from "@/features/vulnerabilities/AppAssessment";
import { closesCell, describeUpdate } from "@/features/vulnerabilities/appUpdate";
import { leverParams, type VulnPromptFilters } from "@/features/vulnerabilities/prompt";
import { SearchBox } from "@/features/vulnerabilities/SearchBox";
import type { AppChip, NumbersRead, PostureRow } from "@/features/vulnerabilities/pageBands";
import { NUMBER_KEYS, VULN_KEYS, agedList, emptySays, exploreByApp, listQuery, payoffList, planNumbers, readNumbers } from "@/features/vulnerabilities/pageBands";
import { pageView, type Load } from "@/features/vulnerabilities/pageView";
import { useLocale } from "@/i18n/LocaleContext";
import type { Translations } from "@/i18n/en";

/**
 * Posture › Vulnerabilities — the fleet ranking the Catalog tab cannot show (#529), in the
 * format Kyle drew from Wiz's Vulnerability Database (#538) — three reads, each with words.
 *
 * The Catalog sorts its vulnerability column client-side over the page in hand; this list is
 * filtered and ordered by the server over every build the tenant has. One row is one BUILD
 * and never one CVE: that is the grain the container holds and the grain a Mac admin acts
 * on, since you push an app update.
 *
 * Three states before a row is drawn, in this order: nothing answers (the `409` — the banner
 * and its *why* block alone, because an empty table under a filter reads as *nothing found*,
 * §4a); loaded but nothing judged against it yet (`vulnJudged` false — one sentence, no
 * list); judged — which is `pageView`, beside this file. Then three ranked bands: most exposed,
 * easily patchable (#532 — what an update would close, times the Macs it reaches) and longest
 * exposed. The search box and its **AI** lever are `SearchBox.tsx` (#533, #534): with the lever
 * on the box holds a question, and the `q` below comes from the answer it applied rather than
 * from what is typed. Nothing counts the fleet per request and nothing sums a band (§4g).
 */

const TOP = 10;
const PAGE = 50;
/** One request per pause, not one per keystroke: the search is a server read. */
const TYPING_MS = 300;

/** *Popular filters*: each chip is one whole URL state, so a filtered list is a link somebody can
 *  send. `band` narrows inside `findings`, never beside it. */
const POPULAR = [{ vuln: "kev", band: null, jamf: null, label: "filterKev" }, { vuln: "findings", band: "critical", jamf: null, label: "filterCritical" },
  { vuln: "unknown_app", band: null, jamf: null, label: "stateUnknownApp" }, { vuln: "clean", band: null, jamf: null, label: "stateCoveredClean" },
  // #532: the ranked section as a chip, and its opposite. The fix path is the column a Mac
  // fleet has, so its ABSENCE is the fact worth a chip of its own — findings with no managed
  // remediation, which is the Catalog's own `jamf=unmatched` narrowing `findings`.
  { vuln: "patchable", band: null, jamf: null, label: "filterPatchable" },
  { vuln: "findings", band: null, jamf: "unmatched", label: "filterNoFixPath" }] as const;

const FILTERS: CatalogVulnFilter[] = ["findings", "kev", "unknown_app", "clean", "patchable"];
const BANDS: CatalogBand[] = ["critical", "high", "medium", "low"];
/** Stable across renders, so the permission selector does not re-run on every store write. */
const NO_PERMISSIONS: string[] = [];

const chip = (on: boolean) =>
  `rounded-full border px-3 py-1 text-sm ${on ? "border-foreground bg-foreground text-background" : "hover:bg-muted"}`;
const recordHref = (entry: CatalogEntry) => `/devices/applications/${encodeURIComponent(entry.appHash)}`;
const exposedDays = (entry: CatalogEntry, t: Translations) =>
  entry.vuln.assessment === "covered" && entry.vuln.daysOldestPublished.total !== null ? t.vulnerabilities.days(entry.vuln.daysOldestPublished.total) : "—";
/** *Seen here* (#591) — the other clock: days since this pod's oldest OPEN ledger row on the build, counted on the
 *  server; a dash where there is none, which is not 0 and is § 18's own step. NOT narrowed to `covered` as `exposedDays`
 *  is — the server answers from the ledger, not from the block on the row. */
const seenHere = (entry: CatalogEntry, t: Translations) =>
  entry.seenHereDays == null ? "—" : t.vulnerabilities.days(entry.seenHereDays);

/** The four bands as small counts, reachable only inside the `covered` narrowing — there is
 *  no branch here in which an unassessed build contributes a zero (§4a). */
function Bands({ entry, t }: { entry: CatalogEntry; t: Translations }) {
  if (entry.vuln.assessment !== "covered" || entry.vuln.counts.total === 0) return null;
  const { severity } = entry.vuln.counts;
  const copy = t.vulnerabilities;
  const named: [string, number][] = [
    [copy.bandCritical, severity.critical],
    [copy.bandHigh, severity.high],
    [copy.bandMedium, severity.medium],
    [copy.bandLow, severity.low]
  ];
  const shown = named.filter(([, count]) => count > 0).map(([label, count]) => `${label} ${count}`);
  return <span className="block text-xs text-muted-foreground">{shown.join(" · ")}</span>;
}

/** One row of *Most exposed* and *Longest exposed*: the count, the Macs, the age and the fix path.
 *  Lifted out of the table body unchanged so the ranked list can put its own row in the same
 *  `<tbody>` — both are six columns, and which one is drawn is `payoffList`'s single decision. */
function ExposedRow({ entry, t }: { entry: CatalogEntry; t: Translations }) {
  return (
    <tr className="border-b align-top last:border-0">
      <td className="px-4 py-2">
        <Link to={recordHref(entry)} className="font-medium hover:underline">{entry.name} {entry.version}</Link>
        <span className="block font-mono text-xs text-muted-foreground">{entry.bundleId}</span></td>
      <td className="px-4 py-2">
        {/* The ONE rendering of the three states here, handed the row so #482's update line
            prints beside the count it is about. */}
        <AssessmentCell vuln={entry.vuln} row={entry} t={t} />
        <Bands entry={entry} t={t} /></td>
      <td className="px-4 py-2 tabular-nums">{entry.vuln.assessment === "covered" && entry.vuln.counts.kev > 0 ? entry.vuln.counts.kev : "—"}</td>
      <td className="px-4 py-2 tabular-nums">
        <Link to={`/devices?versionHash=${entry.versionHash}`} className="hover:underline">{entry.deviceCount}</Link></td>
      <td className="px-4 py-2 tabular-nums">{exposedDays(entry, t)}</td>
      <td className="px-4 py-2 tabular-nums">{seenHere(entry, t)}</td>
      <td className="px-4 py-2">
        <LatestCell answer={entry} t={t} />
        <PatchAnswerCell answer={entry} t={t} /></td>
    </tr>
  );
}

/** One ranked row of *Easily patchable* (#532): what it carries, what it would become, and
 *  what that closes. The update line is the REFERENCE title's target and only it — the
 *  in-branch second line is #482's open cut, and `appUpdate.ts` says whose ruling it waits on.
 *
 *  Nothing here sums anything (§4g): the section prints each row's own difference, and the
 *  fleet's closure figure is a posture key to rule rather than an aggregate to compute. */
function PatchableRow({ entry, t }: { entry: CatalogEntry; t: Translations }) {
  const [line] = describeUpdate(entry.vuln, entry.vulnUpdate, entry);
  const closes = closesCell(line, t.vulnerabilities);
  return (
    <tr className="border-b align-top last:border-0">
      <td className="px-4 py-2">
        <Link to={recordHref(entry)} className="font-medium hover:underline">{entry.name} {entry.version}</Link>
        <span className="block font-mono text-xs text-muted-foreground">{entry.bundleId}</span></td>
      {/* Reachable inside the `covered` narrowing alone: the filter serves no other state, and
          the type still refuses to let one print a count (§4a). */}
      <td className="px-4 py-2 tabular-nums">{entry.vuln.assessment === "covered" ? entry.vuln.counts.total : "—"}</td>
      <td className="px-4 py-2 tabular-nums">
        <Link to={`/devices?versionHash=${entry.versionHash}`} className="hover:underline">{entry.deviceCount}</Link></td>
      <td className="px-4 py-2">{line ? line.version : "—"}
        <Subject title={line?.subject ?? null} hint={t.catalog.latestSubjectHint} t={t} /></td>
      <td className="px-4 py-2 tabular-nums" title={closes?.hint ?? undefined}>{closes ? closes.text : "—"}</td>
      <td className="px-4 py-2 tabular-nums">{exposedDays(entry, t)}</td>
      <td className="px-4 py-2 tabular-nums">{seenHere(entry, t)}</td>
    </tr>
  );
}

export function VulnerabilitiesPage() {
  const { t } = useLocale();
  const copy = t.vulnerabilities;
  // A plain text box over the catalog's own `q` (name, bundle id, version). An id-shaped
  // query is routed to the by-id page by #533 and the AI lever is #534 — said here rather
  // than drawn as a control with nothing behind it.
  const [term, setTerm] = useState("");
  // What the box IS, and what the lever applied. With the lever on the typed text is a
  // question, so it must never reach the lists as a search: `search` is the one `q` they read.
  const [asks, setAsks] = useState(false);
  const [askedFor, setAskedFor] = useState("");
  const search = listQuery(asks, term, askedFor);
  const [expanded, setExpanded] = useState(false);
  const [order, setOrder] = useState<"exposure" | "age">("exposure");
  const [page, setPage] = useState(1);
  const [answer, setAnswer] = useState<CatalogListResponse | null>(null);
  const [load, setLoad] = useState<Load>("loading");
  const [oldest, setOldest] = useState<CatalogListResponse | null>(null);
  const [oldestFailed, setOldestFailed] = useState(false);
  const [patchable, setPatchable] = useState<CatalogListResponse | null>(null);
  const [patchableFailed, setPatchableFailed] = useState(false);
  const [chips, setChips] = useState<AppChip[]>([]);
  const [params, setParams] = useSearchParams();
  const vuln = FILTERS.find((value) => value === params.get("vuln")) ?? "findings";
  const band = BANDS.find((value) => value === params.get("band")) ?? null;
  const byAge = agedList(expanded, order, vuln, band);
  // #532's two chips, in the URL beside the other two so a ranked or unmatched list is a link
  // somebody can send. The chip writes `order=payoff` and the filter carries its own ranking, so
  // an address that lost the order on the way is still this list and not *Most exposed* twice.
  const jamf = params.get("jamf") === "unmatched" ? "unmatched" : null;
  const byPayoff = payoffList(vuln);
  const permissions = useAuthStore((state) => state.user?.permissions ?? NO_PERMISSIONS);
  const plansNumbers = useMemo(() => planNumbers(permissions), [permissions]);
  const [numbers, setNumbers] = useState<NumbersRead | null>(null);
  const [numbersFailed, setNumbersFailed] = useState(false);

  // A moved input re-reads, and the page has to read as asking rather than leave the last
  // term's rows standing as this one's. Adjusted during the render that moved it, keyed on
  // the effect's whole dependency array — the frontend rule in CONTRIBUTING.md, and the
  // reason it is there (#479). From inside the effect's timer it would land a debounce late,
  // so the previous answer would paint as settled under the new term for all 300ms.
  const [asked, setAsked] = useState({ term: search, vuln, band, byAge, byPayoff, jamf, expanded, page });
  if (asked.term !== search || asked.vuln !== vuln || asked.band !== band || asked.byAge !== byAge || asked.byPayoff !== byPayoff || asked.jamf !== jamf || asked.expanded !== expanded || asked.page !== page) {
    setAsked({ term: search, vuln, band, byAge, byPayoff, jamf, expanded, page });
    setLoad("loading");
    // The two bands below re-read with it, so their rows and their error lines go too.
    setOldest(null); setOldestFailed(false);
    setPatchable(null); setPatchableFailed(false);
  }

  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      // `search` is already the `q` a request may run with — `listQuery` drops an id, which was
      // never a filter — so this is the blank-to-absent step and nothing else.
      const q = search.trim() || undefined;
      listCatalog({ vuln, band: band ?? undefined, jamf: jamf ?? undefined, order: byPayoff ? "payoff" : byAge ? "age" : "exposure", q, page: expanded ? page : 1, pageSize: expanded ? PAGE : TOP })
        .then((response) => {
          if (cancelled) return;
          setAnswer(response);
          setLoad("ready");
          // From the rows in hand, and only while nothing is typed, so pressing one chip does not
          // dissolve the row it came from (§4g: no tenant-wide aggregate).
          if (!q) setChips(exploreByApp(response.items));
        })
        .catch((error: unknown) => {
          // The 409 is a STATE, never an error message: nothing is answering for this
          // organization, which the banner below says in words and names both causes for.
          if (!cancelled) setLoad(error instanceof ApiError && error.status === 409 ? "silent" : "failed");
        });
      // Always `findings`: a build with no finding has no publication date to be oldest of.
      if (expanded) return;
      listCatalog({ vuln: "findings", order: "age", q, pageSize: TOP })
        .then((response) => { if (!cancelled) { setOldest(response); setOldestFailed(false); } })
        // Its own request, so its own failure — in words, because a blank box is three answers.
        .catch(() => { if (!cancelled) { setOldest(null); setOldestFailed(true); } });
      // And the ranked fix path (#532), always under its own order: the filter and the order
      // are one answer, since *easily patchable* in exposure order is a list nobody asked for.
      listCatalog({ vuln: "patchable", order: "payoff", q, pageSize: TOP })
        .then((response) => { if (!cancelled) { setPatchable(response); setPatchableFailed(false); } })
        .catch(() => { if (!cancelled) { setPatchable(null); setPatchableFailed(true); } });
    }, TYPING_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [search, vuln, band, byAge, byPayoff, jamf, expanded, page]);

  useEffect(() => {
    if (!plansNumbers) return;
    let cancelled = false;
    apiRequest<{ items: PostureRow[] }>(`/posture?keys=${NUMBER_KEYS.join(",")}`)
      .then((tape) => !cancelled && setNumbers(readNumbers(tape.items)))
      .catch(() => !cancelled && setNumbersFailed(true));
    return () => { cancelled = true; };
  }, [plansNumbers]);

  const shown = pageView(load, answer);
  const rows = shown.rows && answer !== null ? answer.items : [];
  const total = answer?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));
  // One line for what is happening, written once and placed where the reader is looking: in
  // the table's body while the table is up, on its own while there is no table yet.
  const status = load === "loading" ? copy.loading : load === "failed" ? copy.errorLoading : null;
  const statusClass = load === "failed" ? "text-destructive" : "text-muted-foreground";
  const oldestTotal = oldest?.total ?? 0;
  // The band's three answers told apart — its own read failed, it has not come back, it came back
  // with nothing — because one blank box standing for all three is three different things.
  const oldestSays = load === "loading" ? copy.loading : oldestFailed ? copy.longestExposedFailed : oldest === null ? copy.loading : oldestTotal === 0 ? copy.longestExposedNone : null;
  const patchableTotal = patchable?.total ?? 0;
  // The same three answers told apart for the ranked band, and the empty one is a statement:
  // nothing here has an update that closes more than it opens (§18 says what to check).
  const patchableSays = load === "loading" ? copy.loading : patchableFailed ? copy.easilyPatchableFailed : patchable === null ? copy.loading : patchableTotal === 0 ? copy.easilyPatchableNone : null;
  // Parallel to `NUMBER_KEYS`, a fixed tuple in the order the foot prints.
  const labels = [copy.numAppsAffected, copy.numAppsKev, copy.numAppsUnknown, copy.numDevicesAffected, copy.numFindingsOpen, copy.numFindingsNew, copy.numFindingsResolved];

  // The lever's own two moves, stable across renders because `SearchBox` announces its mode
  // from an effect. An answer is one whole URL state, as a Popular filter chip is: it replaces
  // the filters rather than merging into them, and the ranked bands close so the one list the
  // answer counted is the one on screen.
  const onMode = useCallback((next: boolean) => { setAsks(next); setAskedFor(""); setPage(1); }, []);
  const onApply = useCallback((filters: VulnPromptFilters) => {
    setAskedFor(filters.q ?? "");
    setParams(leverParams(filters));
    // `age` is this page's expanded list of builds with findings and nothing else
    // (`agedList`) — where its own *See all* sends it; set anywhere else it is ignored.
    const aged = filters.order === "age";
    setOrder(aged ? "age" : "exposure");
    setExpanded(aged);
    setPage(1);
  }, [setParams]);

  function filterTo(next: CatalogVulnFilter | null, nextBand: CatalogBand | null, nextJamf: string | null = null) {
    // One chip is one whole URL state: pressing another replaces it rather than adding to it.
    // `patchable` carries its order, because the ranking is the half that makes it an answer.
    setParams(new URLSearchParams([...(next ? [["vuln", next]] : []), ...(nextBand ? [["band", nextBand]] : []),
      ...(nextJamf ? [["jamf", nextJamf]] : []), ...(next === "patchable" ? [["order", "payoff"]] : [])])); setPage(1);
  }

  return (
    <section className="space-y-4">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{copy.eyebrow}</p>
      <h1 className="text-2xl font-semibold">{copy.pageTitle}</h1>
      <p className="text-sm text-muted-foreground">{copy.pageDescription}</p>

      {/* One date governs the page; `silent` has none to give, and until a read comes back
          there is none to claim either — a banner drawn on `null` says *nothing is answering
          for this organization*, which is not what a request in flight knows. */}
      {shown.banner && <CorpusBanner corpusAsOf={load === "silent" ? null : (answer?.corpusAsOf ?? null)} t={t} />}

      {shown.notJudged && <p className="text-sm text-muted-foreground">{copy.notYetJudged}</p>}
      {!shown.controls && status !== null && <p className={`text-sm ${statusClass}`}>{status}</p>}

      {shown.controls && (
        <>
          <SearchBox term={term} onTerm={(next) => { setTerm(next); setPage(1); }} onMode={onMode} onApply={onApply}
            shown={{ vuln, band, jamf, order: byPayoff ? "payoff" : byAge ? "age" : "exposure" }} />

          {/* Heading and chips stand or fall together: no bordered empty row where a band was.
              Hidden while the box holds a question: a chip sets the search, and the search is
              then the answer's, so pressing one would light a chip and filter nothing. */}
          {chips.length > 0 && !asks && <><h2 className="text-lg font-medium">{copy.exploreByApp}</h2>
            <div className="flex flex-wrap gap-2">{chips.map(({ name }) => <button key={name} type="button" className={chip(term === name)} onClick={() => { setTerm(term === name ? "" : name); setPage(1); }}>{name}</button>)}</div></>}

          <h2 className="text-lg font-medium">{copy.popularFilters}</h2>
          <div className="flex flex-wrap gap-2">
            {POPULAR.map((filter) => {
              // All three dimensions, so *findings* and *findings with no fix path* are two
              // chips and pressing one never lights the other.
              const on = filter.vuln === vuln && filter.band === band && filter.jamf === jamf;
              return <button key={filter.label} type="button" className={chip(on)} onClick={() => filterTo(on ? null : filter.vuln, on ? null : filter.band, on ? null : filter.jamf)}>{copy[filter.label]}</button>;
            })}
          </div>

          <div className="flex items-baseline justify-between">
            <h2 className="text-lg font-medium">{byPayoff ? copy.easilyPatchable : byAge ? copy.longestExposed : copy.mostExposed}</h2>
            {/* Offered off a settled count only: mid-read the total belongs to the term
                before this one, and a button is no place to print it. */}
            {!expanded && shown.rows && total > rows.length && (
              <button type="button" className="text-sm underline underline-offset-4" onClick={() => setExpanded(true)}>
                {copy.seeAll(total)}
              </button>
            )}
          </div>
          <p className="text-sm text-muted-foreground">{byPayoff ? copy.easilyPatchableHint : byAge ? copy.longestExposedHint : copy.mostExposedHint}</p>

          <div className="overflow-x-auto rounded-lg border bg-card">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                <tr>
                  {/* The ranked list keeps the two columns that make it an answer — what to
                      update to, and what that closes — expanded exactly as in its section. Seven
                      either way since #591, so the sentences below still span the table. */}
                  {(byPayoff
                    ? [copy.colBuild, copy.colFindings, copy.colMacs, copy.colUpdateTo, copy.colCloses, copy.colOldest, copy.colSeenHere]
                    : [copy.colBuild, copy.colFindings, copy.colKev, copy.colMacs, copy.colOldest, copy.colSeenHere, copy.colFix]
                  ).map((label) => (
                    <th key={label} className="px-4 py-2 font-medium">
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {status !== null && (
                  <tr>
                    <td className={`px-4 py-4 ${statusClass}`} colSpan={7}>
                      {status}
                    </td>
                  </tr>
                )}
                {shown.rows && rows.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-muted-foreground" colSpan={7}>
                      {/* Every narrowing in the address decides this sentence, not `vuln` and
                          `band` alone: the list that speaks for the fleet is the unnarrowed one.
                          `search` and never `term` — `listQuery` says why, and `AppliedSearch`
                          is why the box's own string no longer typechecks here. */}
                      {copy[emptySays(vuln, band, jamf, search)]}
                    </td>
                  </tr>
                )}
                {rows.map((entry) =>
                  byPayoff ? <PatchableRow key={entry.id} entry={entry} t={t} /> : <ExposedRow key={entry.id} entry={entry} t={t} />
                )}
              </tbody>
            </table>
          </div>

          {expanded && (
            <div className="flex items-center gap-3 text-sm">
              <button
                type="button"
                className="rounded-md border px-3 py-1 disabled:opacity-50"
                disabled={page <= 1}
                onClick={() => setPage((current) => current - 1)}
              >
                {copy.previous}
              </button>
              <span className="text-muted-foreground">{copy.pageOf(page, pages)}</span>
              <button
                type="button"
                className="rounded-md border px-3 py-1 disabled:opacity-50"
                disabled={page >= pages}
                onClick={() => setPage((current) => current + 1)}
              >
                {copy.next}
              </button>
            </div>
          )}

          {!expanded && (
            <>
              {/* Hidden while the chip above IS this list: the same ten rows under one heading twice
                  reads as a fault. */}
              {!byPayoff && (<>
              <div className="flex items-baseline justify-between"><h2 className="text-lg font-medium">{copy.easilyPatchable}</h2>
                {patchableSays === null && patchableTotal > TOP && <button type="button" className="text-sm underline underline-offset-4" onClick={() => { filterTo("patchable", null); setExpanded(true); }}>{copy.seeAll(patchableTotal)}</button>}</div>
              <p className="text-sm text-muted-foreground">{copy.easilyPatchableHint}</p>
              <div className="overflow-x-auto rounded-lg border bg-card">
                <table className="w-full text-sm">
                  <thead className="border-b bg-muted/30 text-left text-muted-foreground"><tr>
                    {[copy.colBuild, copy.colFindings, copy.colMacs, copy.colUpdateTo, copy.colCloses, copy.colOldest, copy.colSeenHere].map((label) => (
                      <th key={label} className="px-4 py-2 font-medium">{label}</th>))}
                  </tr></thead>
                  <tbody>
                    {patchableSays !== null && <tr><td className="px-4 py-4 text-muted-foreground" colSpan={7}>{patchableSays}</td></tr>}
                    {(patchableSays === null ? (patchable?.items ?? []) : []).map((entry) => (
                      <PatchableRow key={entry.id} entry={entry} t={t} />))}
                  </tbody>
                </table>
              </div></>)}

              <div className="flex items-baseline justify-between"><h2 className="text-lg font-medium">{copy.longestExposed}</h2>
                {oldestSays === null && oldestTotal > TOP && <button type="button" className="text-sm underline underline-offset-4" onClick={() => { filterTo(null, null); setOrder("age"); setExpanded(true); }}>{copy.seeAll(oldestTotal)}</button>}</div>
              <p className="text-sm text-muted-foreground">{copy.longestExposedHint}</p>
              <ul className="divide-y rounded-lg border bg-card text-sm">
                {oldestSays !== null && <li className="px-4 py-4 text-muted-foreground">{oldestSays}</li>}
                {(oldestSays === null ? (oldest?.items ?? []) : []).map((entry) => (
                  <li key={entry.id} className="flex items-baseline justify-between gap-4 px-4 py-2">
                    <Link to={recordHref(entry)} className="font-medium hover:underline">{entry.name} {entry.version}</Link>
                    <span className="shrink-0 tabular-nums text-muted-foreground">{exposedDays(entry, t)}</span></li>))}
              </ul>
            </>
          )}

          {/* Planned against the permission its own source demands: a viewer sees no tile, not a 403.
              Its own read, so its own word for being in flight — a heading over nothing is not one. */}
          {plansNumbers && (
            <section className="space-y-3 rounded-lg border bg-card p-4">
              <h2 className="text-lg font-medium">{copy.byTheNumbers}</h2>
              {numbersFailed && <p className="text-sm text-muted-foreground">{copy.numbersFailed}</p>}
              {numbers === null && !numbersFailed && <p className="text-sm text-muted-foreground">{copy.loading}</p>}
              {numbers?.capturedAt && <p className="text-sm text-muted-foreground">{copy.numbersAsOf(new Date(numbers.capturedAt).toLocaleDateString())}{numbers.runId ? ` · ${copy.numbersRun(numbers.runId)}` : ""}</p>}
              {/* Four columns, seven keys: the ledger's three are absent for their own reason, so they open a row. */}
              {numbers && (
                <dl className="grid gap-4 sm:grid-cols-4">
                  {NUMBER_KEYS.map((key, index) => (
                    <div key={key} className={index === VULN_KEYS.length ? "sm:col-start-1" : undefined}>
                      <dt className="text-xs text-muted-foreground">{labels[index]}</dt>
                      {/* A key with no row prints a dash, never a zero (§4a, §7). */}
                      <dd className="text-2xl font-semibold tabular-nums">{numbers.present.find((row) => row.key === key)?.value.toLocaleString() ?? "—"}</dd>
                    </div>))}
                </dl>)}
              {numbers?.absent.length ? <p className="text-sm text-muted-foreground">{copy.numbersAbsence}</p> : null}
            </section>
          )}
        </>
      )}
    </section>
  );
}
