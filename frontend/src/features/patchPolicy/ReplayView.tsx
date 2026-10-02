import { Fragment, useState } from "react";
import type { PatchPolicyCopy } from "@/features/patchPolicy/copy";
import {
  SLIDER_STOPS,
  TABLED_POLICY,
  heldFix,
  replayedRows,
  type LedgerOutcome,
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
/** To the minute, with its clock spelled out. */
const when = (value: string) => `${value.slice(0, 16).replace("T", " ")} UTC`;

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

export function ReplayView({ replay, appName, stop, onStop, copy }: ReplayViewProps) {
  const [shown, setShown] = useState<Shown>("all");
  const policy = replay.policies[stop];
  const { cves_in_window: inWindow, cves_replayed: replayed, cves_excluded: excluded } = replay.counts;
  const line = replay.branch_choice?.held_at_branch;
  const changed = replay.branch_choice?.cves_where_the_choice_changes_the_answer?.by_policy?.[stop];
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
        {copy.reference(line ? `${appName} ${line}` : appName, replay.window.since, replay.window.until)}
      </div>

      <div className={card}>
        <label htmlFor="patch-policy-stop" className={heading}>{copy.policyHeading}</label>
        {/* Inset by half a column so the thumb sits over the stop it names. */}
        <div className="px-[calc(100%/12_-_8px)] pt-3">
          <input
            id="patch-policy-stop"
            type="range"
            className="block w-full"
            min={0}
            max={SLIDER_STOPS.length - 1}
            step={1}
            value={SLIDER_STOPS.indexOf(stop)}
            aria-valuetext={copy.stops[stop]}
            onChange={(event) => onStop(SLIDER_STOPS[Number(event.target.value)])}
          />
        </div>
        <div className="grid grid-cols-6 pt-1">
          {SLIDER_STOPS.map((each) => (
            <button
              key={each}
              type="button"
              aria-pressed={each === stop}
              onClick={() => onStop(each)}
              className={`rounded-md px-0.5 py-1 text-xs sm:text-sm ${each === stop ? "font-semibold text-foreground" : "text-muted-foreground hover:text-foreground"}`}
            >
              {copy.stops[each]}
            </button>
          ))}
        </div>
        <p className="pt-2 text-sm text-muted-foreground">{copy.policySaid(stop)}</p>
      </div>

      <div className={card}>
        <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className="text-5xl font-bold tabular-nums sm:text-6xl">{copy.num(policy.never_seen)}</span>
          <span className="text-xl text-muted-foreground tabular-nums">{copy.of} {copy.num(replayed)}</span>
          <span className="text-xl font-semibold">{copy.neverSeenLabel}</span>
        </p>
        <p className="pt-3 text-sm">{copy.outside(policy.never_seen_outside_affected_range, policy.never_seen, line)}</p>
        <p className="pt-1 text-sm">{copy.denominators(replayed, inWindow, excluded)}</p>
        <p className="pt-1 text-sm text-muted-foreground">{copy.neverSeenSaid}</p>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {tiles.map(([label, value, hint]) => (
          <div key={label} className="rounded-lg border bg-card p-3">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-2xl font-semibold tabular-nums">{copy.num(value)}</p>
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
            <ul className="grid grid-cols-2 gap-x-4 pt-1 font-mono text-xs sm:grid-cols-3 lg:grid-cols-4">
              {policy.installs.map((install) => <li key={`${install.version} ${install.date}`}>{install.version} · {install.date}</li>)}
            </ul>
          </details>
        )}
      </div>

      <div className="space-y-1">
        <h2 className={heading}>{copy.compareHeading}</h2>
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full min-w-[40rem] text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                {[copy.colPolicy, copy.colNeverSeen, copy.colOutside, copy.exposed, copy.exposureDays, copy.updateEvents, copy.openAtEnd].map((label) => (
                  <th key={label} className={`${cell} font-medium`}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SLIDER_STOPS.map((each) => {
                const totals = replay.policies[each];
                return (
                  <tr key={each} aria-current={each === stop || undefined} className={`border-b last:border-0 ${each === stop ? "bg-muted font-medium" : ""}`}>
                    <td className={`${cell} whitespace-nowrap`}>
                      <button type="button" className="underline-offset-2 hover:underline" onClick={() => onStop(each)}>{copy.stops[each]}</button>
                    </td>
                    {[totals.never_seen, totals.never_seen_outside_affected_range, totals.exposed, totals.exposure_days, totals.update_events, totals.open_at_window_end].map(
                      (value, index) => <td key={index} className={`${cell} tabular-nums`}>{copy.num(value)}</td>
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
        {/* A floor on the width: a phone scrolls the table inside its box and no cell folds to a letter a line. */}
        <div className="max-h-[32rem] overflow-auto rounded-lg border bg-card">
          <table className="w-full min-w-[44rem] text-sm">
            <thead className="sticky top-0 border-b text-left text-muted-foreground">
              <tr>
                {/* The outcome sits beside the CVE, so it is the column a phone shows before any sideways scroll. */}
                {[copy.colCve, copy.colOutcome(copy.stops[stop]), copy.colPublished, copy.colSeverity, copy.colFix(line)].map((label) => (
                  <th key={label} className={`${cell} font-medium`}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const fix = heldFix(row, line);
                return (
                  <tr key={row.cve_id} className="border-b align-top last:border-0">
                    <td className={`${cell} whitespace-nowrap font-mono text-xs`}>{row.cve_id}</td>
                    <td className={cell}>{outcomeWords(row.outcomes?.[stop], copy)}</td>
                    <td className={`${cell} whitespace-nowrap tabular-nums`}>{row.published ?? "—"}</td>
                    <td className={cell}>{row.severity ? (copy.severity[row.severity] ?? row.severity) : copy.unscored}</td>
                    <td className={`${cell} tabular-nums`}>
                      {fix?.fixed_version ? copy.fix(fix.fixed_version, fix.release_date_reported_by_jamf) : <span className="text-muted-foreground">{copy.noFixOnLine}</span>}
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
                <th className={`${cell} font-medium`}>{copy.colReason}</th>
                <th className={`${cell} font-medium`}>{copy.colCount}</th>
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
              <table className="w-full min-w-[36rem] text-sm">
                <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                  <tr>
                    {[copy.colCve, copy.colPublished, copy.colReason, copy.colDetail].map((label) => <th key={label} className={`${cell} font-medium`}>{label}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {replay.exclusions.cves.map((row) => (
                    <tr key={row.cve_id} className="border-b align-top last:border-0">
                      <td className={`${cell} whitespace-nowrap font-mono text-xs`}>{row.cve_id}</td>
                      <td className={`${cell} whitespace-nowrap tabular-nums`}>{row.published ?? "—"}</td>
                      <td className={cell}>{row.reason ? (copy.reasons[row.reason] ?? row.reason) : "—"}</td>
                      <td className={`${cell} text-muted-foreground`}>{row.detail ?? "—"}</td>
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
                      <dd>{text}</dd>
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
              <p>{tabled}</p>
            </div>
          )}
        </div>
      </details>

      <div className={`${card} space-y-2 text-sm`}>
        <h2 className={heading}>{copy.evidenceHeading}</h2>
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted-foreground">{copy.evidenceWindow}</dt>
          <dd className="tabular-nums">{replay.window.since} → {replay.window.until}</dd>
          <dt className="text-muted-foreground">{copy.evidenceCatalog}</dt>
          <dd>
            {copy.fetched(when(replay.evidence.catalog_fetched_at))}
            {replay.evidence.catalog_snapshot_id && <span className="block break-all font-mono text-xs text-muted-foreground">{replay.evidence.catalog_snapshot_id}</span>}
          </dd>
          <dt className="text-muted-foreground">{copy.evidenceRun}</dt>
          <dd className="break-all font-mono text-xs">{replay.run_id}</dd>
        </dl>
        <p className="text-muted-foreground">{copy.releaseDates}</p>
      </div>
    </div>
  );
}
