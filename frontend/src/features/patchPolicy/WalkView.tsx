import { Fragment } from "react";
import type { PatchPolicyCopy } from "@/features/patchPolicy/copy";
import { DayGraph } from "@/features/patchPolicy/DayGraph";
import { KeepDates } from "@/features/patchPolicy/KeepDates";
import { PolicySlider } from "@/features/patchPolicy/PolicySlider";
import { SLIDER_STOPS, type SliderStop } from "@/features/patchPolicy/replay";
import { channelsSetAside, fixBelowNamedBuild, type PatchPolicyWalk, type WalkFixDating, type WalkOutcome, type WalkSource } from "@/features/patchPolicy/walk";
import { reasonWords, type WalkCopy } from "@/features/patchPolicy/walkCopy";

/**
 * One day-walk, drawn (#614): what the walk covers and where its dates come from, the policy slider,
 * the day graph for the selected stop, the headline and the counts reported apart from it, every
 * stop side by side, the page of per-CVE rows with each row's clock, the exclusions, and Evidence.
 * Presentational, like `ReplayView`: it is handed a walk the instance computed, its words and the
 * selected stop and page, and loads nothing. Every number is a field of the walk.
 */
export interface WalkViewProps {
  walk: PatchPolicyWalk;
  stop: SliderStop;
  onStop: (stop: SliderStop) => void;
  onPage: (page: number) => void;
  copy: PatchPolicyCopy;
  words: WalkCopy;
}

const card = "rounded-lg border bg-card p-4";
const heading = "text-xs font-medium uppercase tracking-wide text-muted-foreground";
const cell = "px-3 py-2";
// Every stop side by side: eight columns beside the app list at a 1280 px window fit only with less padding.
const tight = "px-2 py-2";
// The list of CVEs: six columns, the outcome's sentence among them, beside the app list at 1280 px.
const ledger = "px-1.5 py-2";
// Headings wrap at their spaces (and a hyphen of their own), never inside a word: smaller than the
// cells, so a German compound ("Expositionstage", "Mitgebracht") fits its column whole at 1280 px.
const head = "text-xs font-medium hyphens-manual";
// The ledger's narrow columns shrink to their widest word or date, so the outcome takes the room.
const fit = "w-[1%]";
const mono = "block break-all font-mono text-xs text-muted-foreground";

/** One CVE's outcome under one stop, as a sentence. A value this build does not know is printed as the walk spells it. */
function outcomeWords(outcome: WalkOutcome | undefined, copy: PatchPolicyCopy, words: WalkCopy): string {
  if (!outcome) return "—";
  if (outcome.outcome === "not_open_in_window") return words.notOpen;
  if (outcome.outcome === "never_seen") {
    if (outcome.why === "fix_installed_first") return copy.outcome.fixFirst;
    return outcome.why === "outside_affected_range" ? copy.outcome.outsideRange : copy.outcome.neverSeen;
  }
  if (outcome.outcome !== "exposed") return String(outcome.outcome);
  if (typeof outcome.exposure_days !== "number") return copy.outcome.exposed;
  if (outcome.cleared_by && outcome.cleared_on) return copy.outcome.cleared(outcome.exposure_days, outcome.cleared_by, outcome.cleared_on);
  return outcome.open_at_window_end ? copy.outcome.open(outcome.exposure_days) : copy.outcome.exposed;
}

/** One of a CVE's fixes as the walk dated it (`fix_dated_by`): the fix and its date when this source
 *  dates it; the version that dated it, and when, when it is counted from a later one; or why the CVE
 *  is walked by its ranges on that line. A `how` this build does not know is printed as the walk spells it. */
function fixDatedWords(entry: WalkFixDating, copy: PatchPolicyCopy, words: WalkCopy): string {
  if (entry.fix === null) return words.fixNone(entry.line);
  if (entry.how === "fix") return copy.fix(entry.fix, entry.on);
  if (entry.how === "next_dated" && entry.dated_as && entry.on) return words.fixNextDated(entry.fix, entry.dated_as, entry.on);
  if (entry.how === "undated") return words.fixUndated(entry.fix, entry.line);
  return `${entry.fix} (${String(entry.how)})`;
}

const openAtEnd = (open: { in_window: number; carried_in: number; entered_after_start: number }) => open.in_window + open.carried_in + open.entered_after_start;

export function WalkView({ walk, stop, onStop, onPage, copy, words }: WalkViewProps) {
  const { inputs, window, counts } = walk;
  const policy = walk.policies[stop];
  const timeline = inputs.timeline;
  const app = inputs.name;
  const line = inputs.path.kind === "hold" ? inputs.path.ceiling_line : null;
  const shortened = window.shortened_by ?? [];
  // One reason can cut both ends (align=common cuts the start and the end): each reason, and each of
  // the instance's sentences, is said once.
  const shortenedReasons = [...new Set(shortened.map((each) => each.reason))];
  const shortenedSentences = [...new Set(shortened.map((each) => each.sentence).filter((sentence) => sentence))];
  const aligned = window.aligned;
  const page = walk.cves_page;
  const beforeExcluded = Object.values(walk.exclusions.before_window_by_reason ?? {}).reduce((sum, count) => sum + count, 0);
  const context = (source: WalkSource) => ({ app, track: inputs.label, source: words.sourceWords[source], sourceId: source });
  // Versions of a channel LoonSec's data names and does not walk (Firefox ESR beside Firefox's release
  // track), set aside before the walk: said per channel with the join, never counted as unmatched.
  const setAside = channelsSetAside(timeline.other_channels);
  const setAsideStep = timeline.source === "fleet" ? 5 : 4;
  const tiles: [string, number, string][] = [
    [copy.exposed, policy.exposed, words.exposedHint],
    [copy.exposureDays, policy.exposure_days, copy.exposureDaysHint],
    [copy.updateEvents, policy.update_events, copy.updateEventsHint],
    [copy.openAtEnd, openAtEnd(policy.open_at_window_end), words.openAtEndHint]
  ];
  // An address can name a page the list does not have (a link saved before the data changed): that
  // is said, with a way to the last page, never drawn as an empty table.
  const pastEnd = page.page > page.pages;
  // The one check an app's views share is the public walk of the window asked for, unaligned: only
  // that view is the walk that was checked, and every other view says it was not checked itself.
  const checkedHere = timeline.source === "public" && !aligned;
  const checkWords = walk.check.state === "matched" && !checkedHere ? words.checkedByPublic : (words.checks[walk.check.state] ?? walk.check.state);
  const pager = page.pages > 1 && !pastEnd && (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <button type="button" disabled={page.page <= 1} onClick={() => onPage(page.page - 1)} className="rounded-md border px-2 py-1 disabled:opacity-50">{words.previous}</button>
      <span className="tabular-nums text-muted-foreground">{words.pageOf(page.page, page.pages, page.total)}</span>
      <button type="button" disabled={page.page >= page.pages} onClick={() => onPage(page.page + 1)} className="rounded-md border px-2 py-1 disabled:opacity-50">{words.next}</button>
    </div>
  );

  return (
    <div className="min-w-0 space-y-4">
      <div className="space-y-1 rounded-lg border border-foreground/30 p-3 text-sm">
        <b className="block">{copy.referenceTitle}</b>
        <span className="block"><KeepDates text={words.reference(inputs.label, line, window.since, window.until)} /></span>
        <span className="block">{words.dates(timeline.name)}</span>
        {timeline.source !== "public" && <span className="block text-muted-foreground">{words.readHere}</span>}
        {timeline.source === "fleet" && <span className="block">{words.fleetNote}</span>}
        <span className="block">{words.clockLine}</span>
        {shortened.length > 0 && (
          <span className="block">
            <KeepDates text={words.shortened(window.requested.years, window.since, window.until, shortenedReasons.map((reason) => words.windowReasons[reason] ?? reason))} />
          </span>
        )}
        {aligned && (
          <span className="block">
            <KeepDates text={words.aligned(aligned.since, aligned.until, aligned.sources.map((each) => words.sources[each] ?? each).join(` ${words.and} `))} />
            {aligned.left_out.map((each) => (
              <span key={each.source} className="block text-muted-foreground">
                {words.leftOut(words.sources[each.source] ?? each.source)} {reasonWords(words, each.reason, context(each.source), each.sentence)}
              </span>
            ))}
          </span>
        )}
        {walk.check.state === "unchecked_window" && <span className="block">{words.uncheckedWindow(window.requested.years, app)}</span>}
      </div>

      <PolicySlider stop={stop} onStop={onStop} copy={copy}>
        {inputs.path.waits_for_promotion && stop !== "never" && <p className="pt-1 text-sm text-muted-foreground">{copy.waitsForPromotion}</p>}
      </PolicySlider>

      <div className={`${card} space-y-2`}>
        <h2 className={heading}>{words.graphHeading(copy.stops[stop])}</h2>
        <DayGraph policy={policy} since={window.since} until={window.until} stopName={copy.stops[stop]} words={words} num={copy.num} />
      </div>

      <div className={card}>
        <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className="text-5xl font-bold sm:text-6xl">{copy.num(policy.never_seen)}</span>
          <span className="text-xl text-muted-foreground tabular-nums">{copy.of} {copy.num(counts.replayed)}</span>
          <span className="text-xl font-semibold">{copy.neverSeenLabel}</span>
        </p>
        {/* The never stop's device keeps its first version, so its never-seen count is split by why:
            already fixed in that version, or outside every range NVD names, which can be a line NVD
            stopped listing at its end of life. `outside` would say the second kind never affects
            this Mac, which is the conclusion that split warns against. */}
        <p className="pt-3 text-sm">
          {stop === "never"
            ? copy.neverStays(policy.initial_version, policy.never_seen, policy.never_seen_outside_affected_range)
            : copy.outside(policy.never_seen_outside_affected_range, policy.never_seen, line)}
        </p>
        <p className="pt-1 text-sm">{words.denominators(counts.replayed, counts.in_window, counts.excluded)}</p>
        {counts.before_window > 0 && (
          <p className="pt-1 text-sm">
            {words.apart(policy.carried_in, policy.exposure_days_carried_in, policy.entered_after_start, policy.exposure_days_entered_after_start, policy.pre_window_closed)}
          </p>
        )}
        {(counts.after_window > 0 || counts.not_detectable > 0) && <p className="pt-1 text-sm text-muted-foreground">{words.notCounted(counts.after_window, counts.not_detectable)}</p>}
        <p className="pt-1 text-sm text-muted-foreground">{words.neverSeenSaid}</p>
      </div>

      {/* Four abreast only from 1280 px: beside the app list at 1024 px a tile is narrower than a
          six-digit German figure ("134.587"), which then ran under the next tile. */}
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        {tiles.map(([label, value, hint]) => (
          <div key={label} className="min-w-0 rounded-lg border bg-card p-3">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="break-words text-2xl font-semibold tabular-nums">{copy.num(value)}</p>
            <p className="text-xs text-muted-foreground">{hint}</p>
          </div>
        ))}
      </div>

      <div className="space-y-1 text-sm text-muted-foreground">
        {policy.initial_version && policy.final_version && <p>{copy.versions(policy.initial_version, policy.final_version)}</p>}
        {policy.installs.length > 0 && (
          <details>
            <summary className="cursor-pointer">{copy.installs(policy.installs.length)}</summary>
            {/* As many columns as fit one update a line ("152.0.7977.100 · 2026-09-01": two beside the
                app list at 1024 px, three at 1280), and a date never wraps at its hyphens. */}
            <ul className="grid grid-cols-[repeat(auto-fill,minmax(12rem,1fr))] gap-x-3 pt-1 font-mono text-xs">
              {policy.installs.map((install) => (
                <li key={`${install.version} ${install.date}`}>
                  {install.version ?? "—"} · <span className="whitespace-nowrap">{install.date}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>

      <div className="space-y-1">
        <h2 className={heading}>{copy.compareHeading}</h2>
        {/* 38rem, not more: beside the app list at a 1280 px window the view is about 41rem wide, and a
            floor above that clipped the last column (Carried in) behind a sideways scroll. The headings
            are smaller than the cells and the padding tighter, so each German heading's longest word
            fits whole and the headings wrap at their spaces, never mid-word ("Richtli-nie"). */}
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full min-w-[38rem] text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                {[copy.colPolicy, copy.colNeverSeen, copy.colOutside, copy.exposed, copy.exposureDays, copy.updateEvents, copy.openAtEnd, words.colCarried].map((label) => (
                  <th key={label} className={`${tight} ${head}`}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SLIDER_STOPS.map((each) => {
                const totals = walk.policies[each];
                return (
                  <tr key={each} aria-current={each === stop || undefined} className={`border-b last:border-0 ${each === stop ? "bg-muted font-medium" : ""}`}>
                    <td className={`${tight} whitespace-nowrap`}>
                      <button type="button" className="underline-offset-2 hover:underline" onClick={() => onStop(each)}>{copy.stops[each]}</button>
                    </td>
                    {[totals.never_seen, totals.never_seen_outside_affected_range, totals.exposed, totals.exposure_days, totals.update_events, openAtEnd(totals.open_at_window_end), totals.carried_in].map(
                      (value, index) => <td key={index} className={`${tight} tabular-nums`}>{copy.num(value)}</td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="space-y-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className={heading}>{words.ledgerHeading}</h2>
          {pager}
        </div>
        {pastEnd ? (
          <div className="space-y-2 rounded-lg border bg-card p-4 text-sm">
            <p>{words.pastEnd(page.page, page.pages, page.total)}</p>
            <button type="button" onClick={() => onPage(page.pages)} className="rounded-md border px-2 py-1">{words.toPage(page.pages)}</button>
          </div>
        ) : (
          <div className="max-h-[32rem] overflow-auto rounded-lg border bg-card">
            {/* How the source dated each fix is a full-width line under its CVE, not a seventh column:
                a column of sentences ran past the visible width of this box at 1280 to 1440 px. Every
                column but the outcome shrinks to its widest word or date (the CVE id, "Zeitfenster,",
                "Veröffentlichung", "Schweregrad", KEV's date or its dash), so the outcome's sentence
                takes the room and a row is two lines in either language rather than "Das / Zeit- /
                fens- / ter" beside a wide dash. Words wrap at their spaces, never inside a word. */}
            <table className="w-full min-w-[38rem] text-sm">
              <thead className="sticky top-0 border-b bg-card text-left text-muted-foreground">
                <tr>
                  {[copy.colCve, copy.colOutcome(copy.stops[stop]), words.colFrom, words.colClock, copy.colSeverity, words.colKev].map((label, index) => (
                    <th key={label} className={`${ledger} ${head} ${index === 1 ? "" : fit}`}>{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {walk.cves.map((row) => {
                  const outcome = row.outcomes[stop];
                  const fixes = row.fix_dated_by ?? [];
                  return (
                    <Fragment key={row.cve_id}>
                      <tr className={`align-top ${fixes.length > 0 ? "" : "border-b last:border-0"}`}>
                        <td className={`${ledger} whitespace-nowrap font-mono text-xs`}>{row.cve_id}</td>
                        <td className={ledger}><KeepDates text={outcomeWords(outcome, copy, words)} /></td>
                        <td className={ledger}>{words.classes[outcome?.class ?? row.class] ?? outcome?.class ?? row.class}</td>
                        <td className={`${ledger} tabular-nums`}>
                          <span className="whitespace-nowrap">{row.clock_date ?? "—"}</span>
                          {row.clock && <span className="block text-xs text-muted-foreground">{words.clocked[row.clock] ?? row.clock}</span>}
                        </td>
                        <td className={ledger}>{row.severity ? (copy.severity[row.severity] ?? row.severity) : copy.unscored}</td>
                        <td className={`${ledger} tabular-nums`}>{row.kev_date_added ? <KeepDates text={words.kevListed(row.kev_date_added)} /> : "—"}</td>
                      </tr>
                      {fixes.length > 0 && (
                        <tr className="border-b last:border-0">
                          <td colSpan={6} className="px-1.5 pb-2">
                            <span className="block text-xs text-muted-foreground">{words.fixDatedLead(row.cve_id, fixes.length)}</span>
                            {/* One item per entry: two entries at one version (the fix, then a bound of NVD's
                                that lands there, with `named`) are two fixes, not a repeated line. */}
                            <ul className="list-disc space-y-0.5 pl-5">
                              {fixes.map((entry, index) => (
                                <li key={index}>
                                  <KeepDates text={fixDatedWords(entry, copy, words)} />
                                  {/* NVD's own version where it differs; where LoonSec's fix is an earlier build of
                                      the release NVD names, why: the Mac's build, corrected from the release post. */}
                                  {entry.named && (
                                    <span className="text-muted-foreground"> ({fixBelowNamedBuild(entry) ? words.nvdNamedMacBuild(entry.named) : words.nvdNamed(entry.named)})</span>
                                  )}
                                  {/* Dated by the first version the source dates at all: the fix is older than the source's history. */}
                                  {entry.how === "next_dated" && entry.on !== null && entry.on === timeline.first && (
                                    <span className="block text-xs text-muted-foreground">{words.historyBegins[timeline.source]}</span>
                                  )}
                                </li>
                              ))}
                            </ul>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {pager}
      </div>

      <div className="space-y-1">
        <h2 className={heading}>{copy.exclusionsHeading(counts.excluded)}</h2>
        <p className="text-sm text-muted-foreground">{words.exclusionsSaid}</p>
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                <th className={`${cell} ${head}`}>{copy.colReason}</th>
                <th className={`${cell} ${head}`}>{copy.colCount}</th>
              </tr>
            </thead>
            <tbody>
              {/* Every reason the walk counts, zeros included: a zero is an answer. */}
              {Object.entries(walk.exclusions.by_reason)
                .sort(([, a], [, b]) => b - a)
                .map(([reason, count]) => (
                  <tr key={reason} className={`border-b last:border-0 ${count === 0 ? "text-muted-foreground" : ""}`}>
                    <td className={cell}>{words.exclusionReasons[reason] ?? copy.reasons[reason] ?? reason}</td>
                    <td className={`${cell} tabular-nums`}>{copy.num(count)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
        {beforeExcluded > 0 && <p className="text-sm text-muted-foreground">{words.beforeExcluded(beforeExcluded)}</p>}
        {walk.exclusions.cves.length > 0 && (
          <details className="text-sm">
            <summary className="cursor-pointer text-muted-foreground">{copy.excludedList(counts.excluded)}</summary>
            <div className="mt-1 overflow-x-auto rounded-lg border bg-card">
              <table className="w-full min-w-[36rem] text-sm">
                <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                  <tr>
                    {/* The CVE id shrinks to fit; the clock's word wraps under its whole date. */}
                    {[copy.colCve, words.colClock, copy.colReason, copy.colDetail].map((label, index) => (
                      <th key={label} className={`${cell} ${head} ${index === 0 ? fit : ""}`}>{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {walk.exclusions.cves.map((row) => (
                    <tr key={row.cve_id} className="border-b align-top last:border-0">
                      <td className={`${cell} whitespace-nowrap font-mono text-xs`}>{row.cve_id}</td>
                      <td className={`${cell} tabular-nums`}>
                        <span className="whitespace-nowrap">{row.clock_date ?? "—"}</span>
                        {row.clock && <span className="block text-xs text-muted-foreground">{words.clocked[row.clock] ?? row.clock}</span>}
                      </td>
                      <td className={cell}>{words.exclusionReasons[row.reason] ?? copy.reasons[row.reason] ?? row.reason}</td>
                      {/* LoonSec's own words (the header says so in German), except a branch ambiguity: the
                          walk's own reason (LoonSec's data never excludes for it), worded on this instance. */}
                      <td className={`${cell} text-muted-foreground [overflow-wrap:anywhere]`}>
                        {row.detail ? <KeepDates text={row.reason === "branch_ambiguity" ? words.serverSaid(row.detail) : row.detail} /> : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        )}
      </div>

      <details className="text-sm">
        <summary className="cursor-pointer text-muted-foreground">{words.definitionsHeading}</summary>
        <div className="space-y-3 pt-2">
          {([[copy.definitions, walk.definitions], [copy.clocks, walk.clocks]] as const).map(([label, entries]) => (
            <div key={label} className="space-y-1">
              <h3 className={heading}>{label}</h3>
              <dl className="space-y-1">
                {Object.entries(entries)
                  .filter(([, text]) => typeof text === "string")
                  .map(([key, text]) => (
                    <Fragment key={key}>
                      <dt className="font-mono text-xs text-muted-foreground">{key}</dt>
                      {/* A long address (a timeline's URL) breaks rather than push the page sideways at 1024 px. */}
                      <dd className="break-words"><KeepDates text={String(text)} /></dd>
                    </Fragment>
                  ))}
              </dl>
            </div>
          ))}
        </div>
      </details>

      <div className={`${card} space-y-2 text-sm`}>
        <h2 className={heading}>{copy.evidenceHeading}</h2>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted-foreground">{words.evidenceDocument}</dt>
          <dd>
            <span className="block"><KeepDates text={words.dated(inputs.doc_as_of)} /></span>
            <span className={mono}>{inputs.doc_id}</span>
          </dd>
          <dt className="text-muted-foreground">{copy.evidenceTimeline}</dt>
          <dd className="space-y-0.5">
            <span className="block">{words.sources[timeline.source] ?? timeline.source} · {timeline.name}</span>
            <span className="block text-muted-foreground">
              <KeepDates text={words.readOn(timeline.as_of) + (timeline.first && timeline.last ? ` · ${words.datesRange(timeline.first, timeline.last)}` : "")} />
            </span>
            {timeline.ids.length > 0 && <span className={mono}>{timeline.ids.join(", ")}</span>}
            <span className={mono}>{timeline.digest}</span>
            {timeline.note && <span className="block text-muted-foreground">{words.serverSaid(timeline.note)}</span>}
          </dd>
          <dt className="text-muted-foreground">{words.evidenceJoin}</dt>
          <dd className="space-y-0.5">
            <span className="block">{words.join(timeline.matched, timeline.unmatched.length, timeline.other_track, timeline.undated, timeline.conflicts)}</span>
            <span className="block text-muted-foreground">{words.inReach(timeline.in_reach.share)}</span>
            {timeline.unmatched.length > 0 && <span className={mono}>{words.unmatchedListed(timeline.unmatched)}</span>}
            {timeline.other_track_versions.length > 0 && <span className={mono}>{words.otherTrackListed(timeline.other_track_versions)}</span>}
            {setAside.map((each) => (
              <Fragment key={each.channel}>
                <span className="block">{words.channelSetAside(each.count, each.label, setAsideStep)}</span>
                {each.versions.length > 0 && <span className={mono}>{words.channelListed(each.label, each.versions)}</span>}
              </Fragment>
            ))}
          </dd>
          <dt className="text-muted-foreground">{copy.evidenceWindow}</dt>
          <dd className="space-y-0.5">
            <span className="block tabular-nums">
              <KeepDates
                text={
                  `${window.since} → ${window.until}` +
                  (window.since !== window.requested.since || window.until !== window.requested.until
                    ? ` · ${words.asked(words.years(window.requested.years), window.requested.since, window.requested.until)}`
                    : "")
                }
              />
            </span>
            {/* The instance's own words for each cut: the page names the cut and computes none of it. */}
            {shortenedSentences.map((sentence) => <span key={sentence} className="block text-muted-foreground"><KeepDates text={words.serverSaid(sentence)} /></span>)}
            {aligned?.left_out.map((each) => (
              <span key={each.source} className="block text-muted-foreground">
                <KeepDates text={`${words.leftOut(words.sources[each.source] ?? each.source)} ${words.serverSaid(each.sentence)}`} />
              </span>
            ))}
          </dd>
          <dt className="text-muted-foreground">{copy.evidenceClock}</dt>
          <dd className="space-y-0.5">
            <span className="block">{words.clockTotals(counts.replayed_by_clock.detectable_at, counts.replayed_by_clock.published)}</span>
            <span className="block text-muted-foreground">{words.placedTotals(counts.placed_by_clock.detectable_at, counts.placed_by_clock.published)}</span>
            {counts.uncertain_over_1d > 0 && <span className="block text-muted-foreground">{words.uncertain(counts.uncertain_over_1d)}</span>}
          </dd>
          {counts.fix_dating && (
            <>
              <dt className="text-muted-foreground">{words.evidenceFixDating}</dt>
              <dd>{words.fixDating(counts.fix_dating.fix, counts.fix_dating.next_dated, counts.fix_dating.undated)}</dd>
            </>
          )}
          <dt className="text-muted-foreground">{words.evidenceCheck}</dt>
          <dd className="space-y-0.5">
            <span className="block">{checkWords}</span>
            {walk.check.detail && <span className="block text-muted-foreground">{words.serverSaid(walk.check.detail)}</span>}
          </dd>
          <dt className="text-muted-foreground">{words.evidenceInput}</dt>
          <dd className="break-all font-mono text-xs">{walk.input_id}</dd>
          <dt className="text-muted-foreground">{words.evidenceRun}</dt>
          <dd className="break-all font-mono text-xs">{walk.run_id}</dd>
        </dl>
      </div>
    </div>
  );
}
