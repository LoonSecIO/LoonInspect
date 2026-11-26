import { Fragment, useState } from "react";
import type { PatchPolicyCopy } from "@/features/patchPolicy/copy";
import { KeepDates } from "@/features/patchPolicy/KeepDates";
import { PolicySlider } from "@/features/patchPolicy/PolicySlider";
import {
  SLIDER_STOPS,
  TABLED_POLICY,
  affectedBounds,
  heldFixes,
  replayedRows,
  windowCut,
  type LedgerOutcome,
  type NamedFix,
  type PatchPolicyReplay,
  type SliderStop
} from "@/features/patchPolicy/replay";

/**
 * One reference replay, drawn (#614, first slice): the policy slider, the headline, the per-CVE table,
 * the exclusions and the evidence line. Presentational on purpose, so it can be lifted to another site:
 * it is handed a replay that was already read and checked, its words, and the selected stop, and it
 * loads nothing, routes nowhere and reads no dictionary. Every number is a field of the file.
 */
export interface ReplayViewProps {
  replay: PatchPolicyReplay;
  appName: string;
  stop: SliderStop;
  onStop: (stop: SliderStop) => void;
  copy: PatchPolicyCopy;
}

type Shown = "all" | "never_seen" | "exposed";

const card = "rounded-lg border bg-card p-4";
const heading = "text-xs font-medium uppercase tracking-wide text-muted-foreground";
const cell = "px-3 py-2";
// Every stop side by side: tighter, as on the walk view, so the German headings fit whole.
const tight = "px-2 py-2";
// Headings wrap at their spaces (and a hyphen of their own), never inside a word ("Re-lease-Datum").
const head = "text-xs font-medium hyphens-manual";
// The list of CVEs, as on the walk view: tighter cells, and the CVE id, the publication day and the
// severity shrink to their widest word or date, so the outcome and the fixes take the room.
const ledger = "px-1.5 py-2";
const fit = "w-[1%]";
/** To the minute, with its clock spelled out. */
const when = (value: string) => `${value.slice(0, 16).replace("T", " ")} UTC`;
/** A link only for an https address: the file ships with the build, and still names no other scheme here. */
const linkable = (url: string | undefined): url is string => typeof url === "string" && url.startsWith("https://");

/** One CVE's outcome as a sentence. A value this build does not know is printed as the file spells it. */
function outcomeWords(outcome: LedgerOutcome | undefined, copy: PatchPolicyCopy): string {
  if (!outcome) return "—";
  if (outcome.outcome === "never_seen") {
    if (outcome.why === "fix_installed_first") return copy.outcome.fixFirst;
    return outcome.why === "outside_affected_range" ? copy.outcome.outsideRange : copy.outcome.neverSeen;
  }
  if (outcome.outcome !== "exposed") return outcome.outcome;
  if (typeof outcome.exposure_days !== "number") return copy.outcome.exposed;
  if (outcome.cleared_by && outcome.cleared_on) return copy.outcome.cleared(outcome.exposure_days, outcome.cleared_by, outcome.cleared_on);
  return outcome.open_at_window_end ? copy.outcome.open(outcome.exposure_days) : copy.outcome.exposed;
}

/** One fix as the Fix column prints it. Beside others on the same line it carries NVD's statement it
 *  closes, so a reader can tell the fix for the ESR range from the one for the release channel. */
function fixWords(fix: NamedFix, copy: PatchPolicyCopy, withRange: boolean): string {
  const said = copy.fix(fix.fixed_version, fix.release_date);
  const range = withRange ? affectedBounds(fix) : null;
  return range ? `${said}, ${copy.affected(range)}` : said;
}

export function ReplayView({ replay, appName, stop, onStop, copy }: ReplayViewProps) {
  const [shown, setShown] = useState<Shown>("all");
  const policy = replay.policies[stop];
  const { cves_in_window: inWindow, cves_replayed: replayed, cves_excluded: excluded } = replay.counts;
  // `null` is an app replayed as one release line: no line to name, and no other line to choose.
  const line = replay.branch_choice.held_at_branch;
  const changed = line === null ? undefined : replay.branch_choice.cves_where_the_choice_changes_the_answer?.by_policy?.[stop];
  const { timeline } = replay;
  const cut = windowCut(replay);
  const waits = replay.early_stable_choice?.device === "skip";
  // Once the file has cut its window at the promotion table, the major the table lacks is past the
  // window's end, so it limits nothing shown: the shortened sentence and Evidence › Window give that cause.
  const cutAtPromotionTable = (Array.isArray(replay.window.shortened_by) ? replay.window.shortened_by : []).some(
    (each: unknown) => typeof each === "object" && each !== null && (each as { reason?: unknown }).reason === "promotion_table"
  );
  const behind = replay.early_stable_choice?.promotion_table_behind_timeline === true && !cutAtPromotionTable;
  // NVD's status per CVE, for the excluded list: the exclusion rows do not carry it, their ledger rows do.
  const statusOf = new Map(replay.ledger.map((row) => [row.cve_id, typeof row.status === "string" && row.status !== "" ? row.status : null]));
  const rows = replayedRows(replay).filter((row) => shown === "all" || row.outcomes?.[stop]?.outcome === shown);
  const filters: [Shown, string, number][] = [
    ["all", copy.filterAll, replayed],
    ["never_seen", copy.filterNeverSeen, policy.never_seen],
    ["exposed", copy.filterExposed, policy.exposed]
  ];
  const tiles: [string, number, string][] = [
    [copy.exposed, policy.exposed, copy.exposedHint],
    [copy.exposureDays, policy.exposure_days, copy.exposureDaysHint],
    [copy.updateEvents, policy.update_events, copy.updateEventsHint],
    [copy.openAtEnd, policy.open_at_window_end, copy.openAtEndHint]
  ];
  const tabled = replay.definitions[TABLED_POLICY];

  return (
    <div className="min-w-0 space-y-4">
      <div className="rounded-lg border border-foreground/30 p-3 text-sm">
        <b className="block">{copy.referenceTitle}</b>
        <KeepDates text={copy.reference(appName, line, replay.window.since, replay.window.until)} />
        <span className="block pt-1">{copy.sources(timeline.name)}</span>
        {timeline.edition === "release" && <span className="block pt-1">{copy.releaseChannelOnly(appName)}</span>}
        {cut && <span className="block pt-1"><KeepDates text={copy.shortened(replay.window.until, cut.requested)} /></span>}
      </div>

      <PolicySlider stop={stop} onStop={onStop} copy={copy}>
        {waits && stop !== "never" && <p className="pt-1 text-sm text-muted-foreground">{copy.waitsForPromotion}</p>}
        {waits && behind && <p className="pt-1 text-sm text-muted-foreground">{copy.promotionTableBehind}</p>}
      </PolicySlider>

      <div className={card}>
        <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className="text-5xl font-bold tabular-nums sm:text-6xl">{copy.num(policy.never_seen)}</span>
          <span className="text-xl text-muted-foreground tabular-nums">{copy.of} {copy.num(replayed)}</span>
          <span className="text-xl font-semibold">{copy.neverSeenLabel}</span>
        </p>
        {/* As on the walk view: the never stop's device keeps its first version, so its never seen is split
            by why, already fixed in that version or outside every range NVD names. `outside` would say the
            second kind never affects this Mac, the conclusion the split warns against. */}
        <p className="pt-3 text-sm">
          {stop === "never"
            ? copy.neverStays(policy.initial_version, policy.never_seen, policy.never_seen_outside_affected_range)
            : copy.outside(policy.never_seen_outside_affected_range, policy.never_seen, line)}
        </p>
        <p className="pt-1 text-sm">{copy.denominators(replayed, inWindow, excluded)}</p>
        <p className="pt-1 text-sm text-muted-foreground">{copy.neverSeenSaid}</p>
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
        <p>{copy.versions(policy.initial_version, policy.final_version)}</p>
        {changed !== undefined && <p>{copy.branchChoice(changed)}</p>}
        {policy.installs.length > 0 && (
          <details>
            <summary className="cursor-pointer">{copy.installs(policy.installs.length)}</summary>
            {/* As many columns as fit one update a line, and a date never wraps at its hyphens. */}
            <ul className="grid grid-cols-[repeat(auto-fill,minmax(12rem,1fr))] gap-x-3 pt-1 font-mono text-xs">
              {policy.installs.map((install) => (
                <li key={`${install.version} ${install.date}`}>
                  {install.version} · <span className="whitespace-nowrap">{install.date}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>

      <div className="space-y-1">
        <h2 className={heading}>{copy.compareHeading}</h2>
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full min-w-[38rem] text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                {[copy.colPolicy, copy.colNeverSeen, copy.colOutside, copy.exposed, copy.exposureDays, copy.updateEvents, copy.openAtEnd].map((label) => (
                  <th key={label} className={`${tight} ${head}`}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SLIDER_STOPS.map((each) => {
                const totals = replay.policies[each];
                return (
                  <tr key={each} aria-current={each === stop || undefined} className={`border-b last:border-0 ${each === stop ? "bg-muted font-medium" : ""}`}>
                    <td className={`${tight} whitespace-nowrap`}>
                      <button type="button" className="underline-offset-2 hover:underline" onClick={() => onStop(each)}>{copy.stops[each]}</button>
                    </td>
                    {[totals.never_seen, totals.never_seen_outside_affected_range, totals.exposed, totals.exposure_days, totals.update_events, totals.open_at_window_end].map(
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
          <h2 className={heading}>{copy.ledgerHeading}</h2>
          <div className="flex gap-1">
            {filters.map(([key, label, count]) => (
              <button
                key={key}
                type="button"
                aria-pressed={key === shown}
                onClick={() => setShown(key)}
                className={`rounded-md border px-2 py-1 text-xs ${key === shown ? "border-foreground font-semibold" : "text-muted-foreground hover:text-foreground"}`}
              >
                {label} ({copy.num(count)})
              </button>
            ))}
          </div>
        </div>
        {/* A floor on the width: a phone scrolls the table inside its box and no cell folds to a letter a line.
            Words wrap at their spaces, never inside a word ("(inclu-ding)"), and a date stays whole. */}
        <div className="max-h-[32rem] overflow-auto rounded-lg border bg-card">
          <table className="w-full min-w-[38rem] text-sm">
            <thead className="sticky top-0 border-b text-left text-muted-foreground">
              <tr>
                {/* The outcome sits beside the CVE, so it is the column a phone shows before any sideways scroll. */}
                {[copy.colCve, copy.colOutcome(copy.stops[stop]), copy.colPublished, copy.colSeverity, copy.colFix(line)].map((label, index) => (
                  <th key={label} className={`${ledger} ${head} ${index === 0 || index === 2 || index === 3 ? fit : ""}`}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const fixes = heldFixes(row, line);
                return (
                  <tr key={row.cve_id} className="border-b align-top last:border-0">
                    <td className={`${ledger} whitespace-nowrap font-mono text-xs`}>{row.cve_id}</td>
                    <td className={ledger}><KeepDates text={outcomeWords(row.outcomes?.[stop], copy)} /></td>
                    <td className={`${ledger} whitespace-nowrap tabular-nums`}>{row.published ?? "—"}</td>
                    <td className={ledger}>{row.severity ? (copy.severity[row.severity] ?? row.severity) : copy.unscored}</td>
                    <td className={`${ledger} tabular-nums`}>
                      {fixes.length === 0 ? (
                        <span className="text-muted-foreground">{copy.noFixOnLine}</span>
                      ) : (
                        // Every fix on the line, never the first: which of NVD's ranges this Mac's
                        // versions fell in is the file's judgement, and the outcome beside it gives it.
                        fixes.map((fix, index) => <span key={index} className="block"><KeepDates text={fixWords(fix, copy, fixes.length > 1)} /></span>)
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="space-y-1">
        <h2 className={heading}>{copy.exclusionsHeading(excluded)}</h2>
        <p className="text-sm text-muted-foreground">{copy.exclusionsSaid}</p>
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                <th className={`${cell} ${head}`}>{copy.colReason}</th>
                <th className={`${cell} ${head}`}>{copy.colCount}</th>
              </tr>
            </thead>
            <tbody>
              {/* Every reason the file counts, zeros included: a zero here is an answer, that the
                  replay looked for that reason and excluded nothing for it. */}
              {Object.entries(replay.exclusions.by_reason)
                .sort(([, a], [, b]) => b - a)
                .map(([reason, count]) => (
                  <tr key={reason} className={`border-b last:border-0 ${count === 0 ? "text-muted-foreground" : ""}`}>
                    <td className={cell}>{copy.reasons[reason] ?? reason}</td>
                    <td className={`${cell} tabular-nums`}>{copy.num(count)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
        {replay.exclusions.cves.length > 0 && (
          <details className="text-sm">
            <summary className="cursor-pointer text-muted-foreground">{copy.excludedList(excluded)}</summary>
            <div className="mt-1 overflow-x-auto rounded-lg border bg-card">
              {/* Words wrap at their spaces: hyphenated, the reasons squeezed to syllables beside the detail. */}
              <table className="w-full min-w-[36rem] text-sm">
                <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                  <tr>
                    {/* The CVE id, the day and NVD's status shrink to fit; the reason and the detail take the room. */}
                    {[copy.colCve, copy.colPublished, copy.colReason, copy.colStatus, copy.colDetail].map((label, index) => (
                      <th key={label} className={`${cell} ${head} ${index === 2 || index === 4 ? "" : fit}`}>{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {replay.exclusions.cves.map((row) => (
                    <tr key={row.cve_id} className="border-b align-top last:border-0">
                      <td className={`${cell} whitespace-nowrap font-mono text-xs`}>{row.cve_id}</td>
                      <td className={`${cell} whitespace-nowrap tabular-nums`}>{row.published ?? "—"}</td>
                      <td className={cell}>{row.reason ? (copy.reasons[row.reason] ?? row.reason) : "—"}</td>
                      <td className={`${cell} whitespace-nowrap`}>{statusOf.get(row.cve_id) ?? "—"}</td>
                      <td className={`${cell} text-muted-foreground [overflow-wrap:anywhere]`}>{row.detail ? <KeepDates text={row.detail} /> : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        )}
      </div>

      <details className="text-sm">
        <summary className="cursor-pointer text-muted-foreground">{copy.definitionsHeading}</summary>
        <div className="space-y-3 pt-2">
          {([[copy.definitions, replay.definitions], [copy.clocks, replay.clocks]] as const).map(([label, entries]) => (
            <div key={label} className="space-y-1">
              <h3 className={heading}>{label}</h3>
              <dl className="space-y-1">
                {Object.entries(entries)
                  .filter(([key]) => key !== TABLED_POLICY)
                  .map(([key, text]) => (
                    <Fragment key={key}>
                      <dt className="font-mono text-xs text-muted-foreground">{key}</dt>
                      {/* A long address (a timeline's URL) breaks rather than push the page sideways at 1024 px. */}
                      <dd className="break-words"><KeepDates text={text} /></dd>
                    </Fragment>
                  ))}
              </dl>
            </div>
          ))}
          {/* Apart from the slider and from every table, and without a number: tabled, 2026-10-02. */}
          {tabled && (
            <div className="space-y-1 rounded-lg border border-dashed p-3">
              <h3 className={heading}>{copy.tabledHeading}</h3>
              <p className="text-muted-foreground">{copy.tabledSaid}</p>
              <p><KeepDates text={tabled} /></p>
            </div>
          )}
        </div>
      </details>

      <div className={`${card} space-y-2 text-sm`}>
        <h2 className={heading}>{copy.evidenceHeading}</h2>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted-foreground">{copy.evidenceWindow}</dt>
          <dd className="space-y-0.5">
            <span className="block tabular-nums">
              <KeepDates text={`${replay.window.since} → ${replay.window.until}` + (cut?.requested ? ` · ${copy.asked(cut.requested)}` : "")} />
            </span>
            {/* The file's own reasons, as it words them: the page names the cut and computes none of it. */}
            {cut?.reasons.map((reason) => <span key={reason} className="block text-muted-foreground"><KeepDates text={reason} /></span>)}
          </dd>
          <dt className="text-muted-foreground">{copy.evidenceTimeline}</dt>
          <dd className="space-y-0.5">
            <span className="block">
              {linkable(timeline.url) ? (
                <a href={timeline.url} target="_blank" rel="noreferrer noopener" className="underline underline-offset-2">{timeline.name}</a>
              ) : (
                timeline.name
              )}
              {" · "}
              <KeepDates text={copy.fetched(when(timeline.fetched_at))} />
            </span>
            {timeline.url && !linkable(timeline.url) && <span className="block break-all font-mono text-xs text-muted-foreground">{timeline.url}</span>}
            {timeline.sha256 && <span className="block break-all font-mono text-xs text-muted-foreground">{timeline.sha256}</span>}
            <span className="block text-muted-foreground">{timeline.clock}</span>
          </dd>
          <dt className="text-muted-foreground">{copy.evidenceClock}</dt>
          <dd className="space-y-0.5">
            <span className="block">{copy.cveClock}</span>
            <span className="block text-muted-foreground">{replay.clocks.published}</span>
          </dd>
          <dt className="text-muted-foreground">{copy.evidenceRun}</dt>
          <dd className="break-all font-mono text-xs">{replay.run_id}</dd>
        </dl>
        <p className="text-muted-foreground">{copy.releaseDatesSaid}</p>
      </div>
    </div>
  );
}
