import type { WalkSource } from "@/features/patchPolicy/walk";

/**
 * The words of Posture › Patch policy's day-walk (#614), in English and German, beside the feature
 * as `copy.ts` is for the reference replays. `copy.ts` keeps the words both views share (the stops,
 * the outcomes, the exclusion reasons, the severity names); these are the walk's own.
 *
 * Four things these words must keep saying. The walk is a reference analysis of a hypothetical Mac,
 * never this organization's exposure. The release dates are named by where they come from: LoonSec's
 * published dates, this instance's own copy of Jamf's public patch catalog, or this instance's own
 * Fleet history, each read on this instance and sent nowhere. The CVE clock is said: the first day a
 * CVE was detectable where LoonSec's data holds it, NVD's publication date where it does not, and
 * every row says which. And a state that is not a walk names itself: every `reasons` entry is one
 * word the instance answers with (docs/troubleshooting.md §33), said in the reader's language, with
 * the instance's own sentence printed beneath it for a report. A word this build does not know is
 * still printed, as the instance spells it.
 */

/** What a reason's sentence may name: the app, the track's label, and the source as a sentence names
 *  it (`sourceWords`). `sourceId` is the source itself, for a sentence whose step depends on it. */
export interface ReasonContext {
  app: string;
  track: string;
  source: string;
  sourceId: WalkSource;
}

const plural = (count: number, one: string, many: string) => (count === 1 ? one : many);
/** A source's words at the start of a sentence. */
const opening = (words: string) => words.charAt(0).toUpperCase() + words.slice(1);
const answered = (status: number | null) => (status === null ? "no answer" : `HTTP ${status}`);
/** The walk's own refusals over a timeline's versions read in the Jamf or the Fleet step of §33. */
const joinStep = (sourceId: WalkSource) => (sourceId === "fleet" ? 5 : 4);

export const walkEnglish = {
  appsLoading: "Reading LoonSec's patch-policy data on this instance…",
  appsFailed: (status: number | null) =>
    `The state of LoonSec's patch-policy data could not be read from this instance (${answered(status)}), so this page shows the reference replays that ship with this build. That is a failed read, not missing data: reload, and if it holds, see troubleshooting.md §22 step 11.`,
  /** The page without LoonSec's data (ruled 2026-11-24): the feed's own sentence, then what is shown instead. */
  fallback: (feedSentence: string) =>
    `${feedSentence} Until this instance holds LoonSec's data, this page shows the reference replays that ship with this build instead: each names the public release record its dates come from, and counts each CVE from NVD's publication date (troubleshooting.md §22 step 11).`,

  noApps: "LoonSec's patch-policy data on this instance references no app yet. That is not a count of zero (troubleshooting.md §33 step 2).",
  appInData: "In LoonSec's data",
  appNoReference: "No reference yet",
  /** The picker's other rows are Jamf's patch titles; without them only the data's apps are listed. */
  catalogEmpty:
    "Jamf's patch catalog holds no titles on this instance yet, so only the apps in LoonSec's data are listed. This instance refreshes it at the top of every hour without a Jamf Pro connection; if it stays empty, see troubleshooting.md §6.",
  catalogFailed:
    "Jamf's patch catalog could not be read, so only the apps in LoonSec's data are listed. That is a failed read, not an empty catalog. Reload the page; if it holds, report it with the build from Settings › Support.",
  unknownApp: (id: string) => `No reference yet for "${id}". That is not a count of zero. Pick an app from the list.`,
  /** True whether or not the data names the ESR channel under `other_channels`: named or not, it is not walked. */
  esrNotInData: (app: string) =>
    `LoonSec's patch-policy data does not walk ${app} ESR yet; it walks ${app}. The app list may show Jamf's ${app} ESR title under this row, because the two share a bundle ID.`,
  unknownTrack: (app: string, track: string, tracks: string) =>
    `${app} has no ${track} track in LoonSec's patch-policy data yet; it has ${tracks}. Pick one above.`,

  trackHeading: "Track",
  defaultTrack: "default",
  sourceHeading: "Release dates from",
  sources: { public: "Public", jamf: "Jamf", fleet: "Fleet" } satisfies Record<WalkSource, string>,
  sourceHints: {
    public: "LoonSec's published dates, each from the public release record it names",
    jamf: "This instance's copy of Jamf's public patch catalog",
    fleet: "This instance's Fleet history"
  } satisfies Record<WalkSource, string>,
  /** A source as a sentence names it, mid-sentence. */
  sourceWords: {
    public: "LoonSec's published release dates",
    jamf: "this instance's copy of Jamf's public patch catalog",
    fleet: "this instance's Fleet history"
  } satisfies Record<WalkSource, string>,
  sourceUnavailable: "Not available",
  windowHeading: "Window",
  years: (years: number) => `${years} years`,
  alignLabel: "Compare sources on the days they all cover",
  alignHint:
    "Sources differ in their dates and in the days each covers. Compare two sources' numbers only with this on, and read each view's own counts.",

  /** One sentence per word the instance answers with when a source cannot date a track or a walk is
   *  refused, each ending in its step of docs/troubleshooting.md §33. */
  reasons: {
    tier_off: () =>
      "This organization does not share data with LoonSec, so it does not receive LoonSec's patch-policy data. Settings › Data Sharing (troubleshooting.md §32 step 1).",
    never: () => "LoonSec's patch-policy data has not arrived on this instance yet (troubleshooting.md §32 step 2).",
    not_published: () => "LoonSec's last exchange carried no patch-policy data (troubleshooting.md §32 step 3).",
    download_failed: () => "LoonSec's patch-policy data could not be downloaded, and no copy is held (troubleshooting.md §32 step 5).",
    invalid: () => "LoonSec's patch-policy data failed its check, and no copy is held (troubleshooting.md §32 step 6).",
    algorithm_unknown: () => "LoonSec's patch-policy data is in a form this build does not read. Update LoonInspect (troubleshooting.md §32 step 4).",
    app_unknown: ({ app }: ReasonContext) => `No reference yet for ${app}. That is not a count of zero (troubleshooting.md §33 step 2).`,
    track_unknown: ({ app, track }: ReasonContext) =>
      `${app} has no ${track} track in LoonSec's patch-policy data yet (troubleshooting.md §33 step 2).`,
    no_public_dates: ({ app }: ReasonContext) =>
      `LoonSec holds no public release dates for ${app} yet, so it has none of its own to walk. Jamf or Fleet can date it only while another window of the app matches LoonSec's published totals; when none does, no view of ${app} is shown from any source (troubleshooting.md §33 step 3).`,
    no_public_timeline: ({ app }: ReasonContext) =>
      `LoonSec holds no public release dates for ${app} yet, so it has none of its own to walk. Jamf or Fleet can date it only while another window of the app matches LoonSec's published totals; when none does, no view of ${app} is shown from any source (troubleshooting.md §33 step 3).`,
    never_synced: () =>
      "This instance has not finished a sync of Jamf's public patch catalog yet. The sync runs at the top of every hour and needs no Jamf Pro connection (troubleshooting.md §6, §33 step 4).",
    no_title: ({ app }: ReasonContext) =>
      `This instance's copy of Jamf's public patch catalog has no title for ${app}. Choose another source (troubleshooting.md §33 step 4).`,
    no_versions: ({ app, source }: ReasonContext) =>
      `${opening(source)} names no ${app} version, so there is nothing to walk. Choose another source (troubleshooting.md §33 step 4).`,
    channel_empty: ({ track, source }: ReasonContext) =>
      `${opening(source)} lists no release of ${track}: none of the versions it names is that track's alone. They are on another track's list, numbers it shares with another list, versions LoonSec's data does not list, or builds of a channel LoonSec's data does not walk yet. Choose another track or source (troubleshooting.md §33 step 4).`,
    flag_off: () =>
      "Fleet's catalog is not read while the Fleet catalog flag is off for this organization. Turn on “Fleet catalog (maintained apps)” under Settings › Feature Flags, then check again.",
    catalog_unread: () =>
      "Fleet's catalog has not been read on this instance yet. Check now on the Fleet catalog tab reads it (troubleshooting.md §27, §33 step 5).",
    not_held: ({ app }: ReasonContext) =>
      `Fleet's catalog, as this instance last read it, holds no Mac title for ${app}. Choose another source (troubleshooting.md §33 step 5).`,
    catalog_partial: ({ app }: ReasonContext) =>
      `Fleet's catalog has been read only in part on this instance, and the part read holds no Mac title for ${app}: it may be among the titles not read yet. The instance's words below name the cause. Choose another source until a check reads the whole catalog (troubleshooting.md §33 step 5).`,
    history_unread: ({ app }: ReasonContext) =>
      `Fleet's version history for a title of ${app} has not been read on this instance yet (the instance's words name the title); an administrator with patch:catalog-sync can read it now with Read history on the Fleet catalog tab (troubleshooting.md §27, §33 step 5).`,
    history_failed: ({ app }: ReasonContext) =>
      `The last read of Fleet's version history for a title of ${app} did not get an answer. It is tried again within the hour; Read history on the Fleet catalog tab tries at once (troubleshooting.md §27, §33 step 5).`,
    esr_missing: ({ app }: ReasonContext) =>
      `The Fleet history read for ${app} names no ESR release: none of the versions in it is the ESR track's alone. Choose another source (troubleshooting.md §33 step 5).`,
    line_not_followed: ({ app, track, source }: ReasonContext) =>
      `${opening(source)} follows only ${app}'s newer lines, so ${track} has nothing to install from it. Choose the newest-line track or another source (troubleshooting.md §33 step 5).`,
    ceiling_line_undated: ({ app, track, source }: ReasonContext) =>
      `${opening(source)} dates no release of the line ${track} is held on, so ${app} has nothing to hold there. Choose the newest-line track or another source (troubleshooting.md §33 step 5).`,
    no_matched_versions: ({ track, source, sourceId }: ReasonContext) =>
      `None of the versions ${source} names is one LoonSec's data lists for ${track}. Choose another source (troubleshooting.md §33 step ${joinStep(sourceId)}).`,
    too_many_unmatched: ({ track, source, sourceId }: ReasonContext) =>
      `More than 5% of the versions ${source} dates in this window match nothing LoonSec's data lists for ${track}, so the walk would skip installs and is refused. Choose Public (troubleshooting.md §33 step ${joinStep(sourceId)}).`,
    nothing_to_install: ({ track, source }: ReasonContext) =>
      `${opening(source)} dates no release the ${track} Mac could install. Choose another source (troubleshooting.md §33 step 6).`,
    window_empty: ({ source }: ReasonContext) =>
      `Nothing is left to walk in the window asked for, once the days the source covers (${source}) are taken into account. Choose a longer window or another source (troubleshooting.md §33 step 6).`,
    parity: ({ app }: ReasonContext) =>
      `The walk of LoonSec's own dates for ${app} does not match the totals LoonSec published with the data, so no view of ${app} is shown. Nothing on this instance can fix it (troubleshooting.md §33 step 7, state AD).`,
    unchecked: ({ app }: ReasonContext) =>
      `LoonSec has published no totals this build could match for any window of ${app}, so no view of ${app} is shown (troubleshooting.md §33 step 7, state AD).`,
    document_invalid: ({ app }: ReasonContext) =>
      `LoonSec's patch-policy data for ${app} failed this build's check, so nothing was walked. The data is the same on every instance (troubleshooting.md §33 step 7, state AD).`,
    document_kind: () =>
      "What this instance holds as LoonSec's patch-policy data is not that data. Settings › Support shows its state (troubleshooting.md §32).",
    invariant: () =>
      "LoonInspect refused its own walk because its totals disagree. That is a defect in this build, not in this instance's data (troubleshooting.md §33 step 8, state AE).",
    timeline_invalid: () =>
      "LoonInspect refused the release timeline it built for the walk. That is a defect in this build (troubleshooting.md §33 step 8, state AE).",
    request_invalid: () =>
      "LoonInspect refused the walk this page asked for. That is a defect in this build (troubleshooting.md §33 step 8, state AE)."
  } as Record<string, (context: ReasonContext) => string>,
  reasonUnknown: (reason: string) => `The walk is not shown (${reason}). Report the instance's words below with the build from Settings › Support (troubleshooting.md §33).`,
  serverSaid: (sentence: string) => `This instance's words: ${sentence}`,
  unmatchedListed: (versions: string[]) => `Unmatched: ${versions.join(", ")}`,
  /** A channel LoonSec's data names beside the app's tracks and does not walk: its versions a timeline named are set aside. */
  channelSetAside: (count: number, label: string, step: number) =>
    `${count} ${plural(count, "version", "versions")} of ${label} set aside: LoonSec's data does not walk that channel yet, so ${plural(count, "it is", "they are")} neither walked nor counted as unmatched (troubleshooting.md §33 step ${step}).`,
  channelListed: (label: string, versions: string[]) => `${label}, set aside: ${versions.join(", ")}`,
  /** A parity refusal's facts: the stop, the total, and the two values that disagree. */
  parityFacts: (stop: string, key: string, walked: number, published: number) =>
    `At ${stop}, ${key}: the walk of LoonSec's dates counts ${walked}, and LoonSec published ${published}.`,
  /** Each window of the app and why it was not matched, as the instance words it. */
  windowsFacts: (entries: string[]) => `Each window: ${entries.join("; ")}`,

  notWalked: (source: string) =>
    `Nothing is walked over ${source} for this track: the reason is under the toggle above. Choose another source or track.`,
  /** `track` is the track's label, which already begins with the app's name. */
  walkLoading: (track: string, source: string) => `Walking ${track} over ${source}…`,
  walkFailed: (status: number | null) =>
    `The walk could not be read from this instance (${answered(status)}). That is a failed read, not a refusal: reload, and if it holds, report it with the build from Settings › Support (troubleshooting.md §33 step 10).`,
  walkUnreadable: (what: string) =>
    `This instance answered with a walk this page cannot draw (${what}). Reload once: a page left open across an update reads an answer its build no longer serves. If it reads the same, report it with the build (troubleshooting.md §33 step 10, state AE).`,

  reference: (label: string, line: string | null, since: string, until: string) =>
    `One hypothetical Mac that runs ${label}${line ? `, held on its ${line} line` : ""}, walked day by day from ${since} to ${until} against LoonSec's patch-policy data. No inventory from this instance is read to draw it, nothing is sent anywhere, and no number here is stored.`,
  // The timeline's name is the instance's, printed as a label and never inside a sentence.
  dates: (name: string) => `Release dates: ${name}.`,
  readHere: "Read on this instance from its own copy; nothing of it leaves the instance.",
  fleetNote: "These are Fleet's dates, not the vendor's: Fleet builds its catalog from Homebrew and commits it some hours later.",
  clockLine:
    "Each CVE counts from the first day it was detectable in NVD's record, where LoonSec's data holds that day, and from NVD's publication date where it does not. Each row says which, and Evidence counts both.",
  shortened: (years: number, since: string, until: string, reasons: string[]) =>
    `You asked for ${years} years; this view covers ${since} to ${until} because ${reasons.join("; ")}. Evidence › Window gives each reason in the instance's words.`,
  windowReasons: {
    clock_coverage: "LoonSec's record of the day each CVE became detectable begins later",
    timeline_coverage: "the release dates begin later, and the 60-day stop needs 59 days of them",
    line_start: "the held line begins later, and the 60-day stop needs 59 days of it",
    channel_start: "the channel begins later, and the 60-day stop needs 59 days of it",
    common_window: "it is aligned to the days every compared source covers",
    ledger_as_of: "LoonSec's data ends the day before its date",
    timeline_as_of: "the release dates were read earlier",
    promotion_table: "the promotion table has no row yet for a newer major version"
  } as Record<string, string>,
  aligned: (since: string, until: string, sources: string) => `Aligned to ${since} to ${until}, the days ${sources} all cover.`,
  leftOut: (source: string) => `${source} is left out:`,
  uncheckedWindow: (years: number, app: string) =>
    `LoonSec has no check for a ${years}-year window of ${app}; it is shown because another window of ${app} matched LoonSec's published totals.`,
  and: "and",

  graphHeading: (stop: string) => `Open CVEs per day, at ${stop}`,
  legendOpen: "Open that day",
  legendNew: "Opened",
  legendResolved: "Resolved by an update",
  graphSummary: (stop: string, since: string, until: string, first: number, last: number, peak: number, peakDate: string, opened: number, resolved: number) =>
    `Open CVEs per day from ${since} to ${until} at ${stop}: ${first} on the first day and ${last} on the last, at most ${peak} (first on ${peakDate}); ${opened} opened after the first day and ${resolved} were resolved by an update.`,
  graphKeys: "Read the graph day by day: arrow keys move a day, Page Up and Page Down thirty, Home and End to the ends.",
  graphEmpty: (stop: string) => `No listed CVE was open on any day of this window at ${stop}.`,
  openWord: "open",
  tipOpen: (count: number) => `${count} open`,
  tipNew: (count: number, became: number, entered: number) =>
    `${count} opened${count > 0 ? ` (${became} became detectable, ${entered} entered by an install)` : ""}`,
  tipResolved: (count: number) => `${count} resolved`,
  tipInstalled: (version: string) => `installed ${version}`,
  graphTable: "The days the count moved, as a table",
  colDay: "Day",
  colOpen: "Open",
  colOpened: "Opened",
  colResolved: "Resolved",
  colInstalled: "Installed",

  neverSeenSaid: "Never seen: from the CVE's clock day to the window's last day, this Mac ran no version the CVE affects.",
  denominators: (counted: number, inWindow: number, excluded: number) =>
    `${counted} ${plural(counted, "CVE is", "CVEs are")} counted, of ${inWindow} whose clock day falls in the window. The other ${excluded} ${plural(excluded, "is", "are")} excluded and counted below; excluded is not safe.`,
  apart: (carried: number, carriedDays: number, entered: number, enteredDays: number, closed: number) =>
    `Reported apart, from before the window: ${carried} open on its first day (${carriedDays} exposure days) and ${entered} this Mac moved into later (${enteredDays} exposure days). ${closed} more were never open in it.`,
  notCounted: (after: number, notDetectable: number) =>
    `Not counted: ${after} whose clock day falls after the window, and ${notDetectable} LoonSec's data lists as not yet detectable.`,
  exposedHint: "CVEs this Mac ran an affected version for, on or after their clock day",
  openAtEndHint: "counted, carried in and entered later, together",
  colCarried: "Carried in",

  ledgerHeading: "Each listed CVE",
  colFrom: "From",
  classes: {
    in_window: "The window",
    before_window: "Before the window",
    carried_in: "Before the window, open on its first day",
    entered_after_start: "Before the window, entered later",
    pre_window_closed: "Before the window, never open in it"
  } as Record<string, string>,
  colClock: "Clock day",
  clocked: { detectable_at: "first detectable", published: "NVD publication" } as Record<string, string>,
  colKev: "KEV",
  kevListed: (date: string) => `listed ${date}`,
  notOpen: "Not open in the window",
  /** Above the line under each CVE that gives each fix as `fix_dated_by` says this source dated it (troubleshooting.md §33 step 12). */
  fixDatedLead: (cve: string, count: number) => `${plural(count, "Fix", "Fixes")} of ${cve}, as this source dates ${plural(count, "it", "them")}:`,
  /** A fix the source does not date, counted from the first version at or above the fix, on its line,
   *  that the source dates and the CVE's affected range does not cover (a dated version still in range
   *  is passed over, so it is not merely "the next version it dates"). */
  fixNextDated: (fix: string, datedAs: string, on: string) =>
    `${fix}: not dated by this source, so counted from ${datedAs}, the first version at or above the fix that it dates outside the CVE's affected range, on ${on}`,
  /** Beside `fixNextDated` when that version is the first the source dates at all: the fix is older than its history. */
  historyBegins: {
    public: "LoonSec's published dates begin here",
    jamf: "Jamf's history begins here",
    fleet: "Fleet's history begins here"
  } satisfies Record<WalkSource, string>,
  fixUndated: (fix: string, line: string) =>
    `${fix}: this source dates no version at or above it ${line ? `on the ${line} line` : "on its line"} outside the CVE's affected range, so this CVE is walked by its affected ranges there`,
  fixNone: (line: string) =>
    `No fix version ${line ? `on the ${line} line` : "on its line"} in LoonSec's data, so this CVE is walked by its affected ranges there`,
  /** NVD's own fix version, where LoonSec's data points at another. */
  nvdNamed: (named: string) => `NVD names ${named}`,
  /** `nvdNamed` where LoonSec's fix is an earlier build of the release NVD names (`fixBelowNamedBuild`):
   *  the Mac's own build, which LoonSec read from the vendor's release post (troubleshooting.md §33 step 12). */
  nvdNamedMacBuild: (named: string) =>
    `NVD names ${named}, another platform's build of the same release; the vendor's release post gives the Mac's build; troubleshooting.md §33 step 12`,
  pageOf: (page: number, pages: number, total: number) => `Page ${page} of ${pages} · ${total} ${plural(total, "CVE", "CVEs")}`,
  previous: "Previous",
  next: "Next",
  pastEnd: (page: number, pages: number, total: number) =>
    `Page ${page} is past the end of this list: it holds ${total} ${plural(total, "CVE", "CVEs")} on ${pages} ${plural(pages, "page", "pages")}. The address asks for a page the list does not have, as a link saved before LoonSec's data changed can (troubleshooting.md §33 step 10).`,
  toPage: (page: number) => `Show page ${page}`,

  /** The two exclusion reasons whose replay wording would misname a walk's: the rest are `copy.ts`'s.
   *  `fixed_version_not_in_timeline` is no reason of the walk's since 2026-11-25; a copy of LoonSec's
   *  data from before then still names it, and the walk counts it 0. No replay carries it. Nor does
   *  LoonSec's data exclude for `fixed_version_not_in_catalog` since that day (it lists such a fix at
   *  the next version at or above it, with `named`), though an older copy can still count some. */
  exclusionReasons: {
    fixed_version_not_in_catalog:
      "No longer a reason since 2026-11-25: LoonSec's data lists a fix the track's version list does not hold at the next version at or above it, with NVD's own version beside it. A copy built since counts 0 here; an older copy can still count some",
    fixed_version_not_in_timeline:
      "No longer a reason: a fix this source does not date is counted from the next version it dates at or above the fix. An older copy of LoonSec's data still names it, always at 0"
  } as Record<string, string>,
  exclusionsSaid:
    "Their clock day falls in the window, and each is left out of every number above for one reason. They were not walked, which is not the same as not affecting this Mac.",
  beforeExcluded: (count: number) => `${count} more from before the window are excluded for the same reasons.`,

  asked: (years: string, since: string, until: string) => `asked for ${years}, ${since} → ${until}`,
  evidenceDocument: "LoonSec's data",
  dated: (asOf: string) => `dated ${asOf}`,
  readOn: (asOf: string) => `read ${asOf}`,
  datesRange: (first: string, last: string) => `dates ${first} to ${last}`,
  evidenceJoin: "Versions joined",
  join: (matched: number, unmatched: number, other: number, undated: number, conflicts: number) =>
    `${matched} matched the track's versions; ${unmatched} unmatched (never installed); ${other} set aside as another track's; ${undated} undated; ${conflicts} dated more than once.`,
  inReach: (share: number) => `${(share * 100).toFixed(1)}% of the versions in reach are unmatched; above 5% the walk is refused.`,
  otherTrackListed: (versions: string[]) => `Another track's: ${versions.join(", ")}`,
  clockTotals: (detectable: number, published: number) =>
    `${detectable} counted from the first day they were detectable, ${published} from NVD publication.`,
  placedTotals: (detectable: number, published: number) =>
    `Every CVE placed against the window: ${detectable} by the first detectable day, ${published} by NVD publication.`,
  uncertain: (count: number) => `${count} counted ${plural(count, "CVE has", "CVEs have")} a first detectable day uncertain by more than a day.`,
  evidenceFixDating: "Fixes dated",
  /** Over the lines a device under any stop runs in the window (the lines the walk's paths visit), not
   *  one device's: `counts.fix_dating` counts the entries of every listed CVE on those lines. */
  fixDating: (fix: number, next: number, undated: number) =>
    `Of the fixes the listed CVEs name on the lines a device under any stop runs: ${fix} dated by the fix itself, ${next} by the first version at or above the fix that this source dates outside the CVE's affected range, ${undated} by none${undated > 0 ? plural(undated, ", so that CVE is walked by its affected ranges there", ", so those CVEs are walked by their affected ranges there") : ""} (troubleshooting.md §33 step 12).`,
  evidenceCheck: "Check",
  checks: {
    matched: "Matches the totals LoonSec published for this window.",
    unchecked_window: "Shown without a check of its own: another window of the app matched."
  } as Record<string, string>,
  /** `matched` on a Jamf, Fleet or aligned view: the check is the public walk's, not this view's. The
   *  instance's `check.detail`, printed beneath, names that walk, so this does not name it again. */
  checkedByPublic:
    "Not checked itself: LoonSec publishes totals only for its own release dates, over the window asked for without alignment. This view is shown because that walk, below, matched them.",
  evidenceInput: "Input",
  evidenceRun: "Run",
  definitionsHeading: "Definitions and clocks, in the walk's own words"
};

export type WalkCopy = typeof walkEnglish;

const mehrzahl = (count: number, one: string, many: string) => (count === 1 ? one : many);
const beantwortet = (status: number | null) => (status === null ? "keine Antwort" : `HTTP ${status}`);

export const walkGerman: WalkCopy = {
  appsLoading: "Die Patch-Policy-Daten von LoonSec auf dieser Instanz werden gelesen…",
  appsFailed: (status: number | null) =>
    `Der Stand der Patch-Policy-Daten von LoonSec konnte von dieser Instanz nicht gelesen werden (${beantwortet(status)}); diese Seite zeigt daher die Referenz-Replays, die mit diesem Build ausgeliefert werden. Das ist ein fehlgeschlagener Lesevorgang, kein Fehlen von Daten: Laden Sie neu; bleibt es dabei, siehe troubleshooting.md §22 Schritt 11.`,
  fallback: (feedSentence: string) =>
    `${feedSentence} Solange diese Instanz die Daten von LoonSec nicht hält, zeigt diese Seite stattdessen die Referenz-Replays, die mit diesem Build ausgeliefert werden: Jedes nennt die öffentliche Release-Quelle seiner Daten und zählt jede CVE ab ihrem Veröffentlichungsdatum bei NVD (troubleshooting.md §22 Schritt 11).`,

  noApps: "Die Patch-Policy-Daten von LoonSec auf dieser Instanz verweisen noch auf keine App. Das ist keine Zählung von null (troubleshooting.md §33 Schritt 2).",
  appInData: "In den Daten von LoonSec",
  appNoReference: "Noch keine Referenz",
  catalogEmpty:
    "Jamfs Patch-Katalog enthält auf dieser Instanz noch keine Titel; aufgeführt sind daher nur die Apps in den Daten von LoonSec. Diese Instanz aktualisiert ihn zu jeder vollen Stunde, ohne Jamf-Pro-Verbindung; bleibt er leer, siehe troubleshooting.md §6.",
  catalogFailed:
    "Jamfs Patch-Katalog konnte nicht gelesen werden; aufgeführt sind daher nur die Apps in den Daten von LoonSec. Das ist ein fehlgeschlagener Lesevorgang, kein leerer Katalog. Laden Sie die Seite neu; bleibt es dabei, melden Sie es mit dem Build aus Einstellungen › Support.",
  unknownApp: (id: string) => `Für „${id}“ gibt es noch keine Referenz. Das ist keine Zählung von null. Wählen Sie eine App aus der Liste.`,
  esrNotInData: (app: string) =>
    `Die Patch-Policy-Daten von LoonSec spielen ${app} ESR noch nicht nach; ${app} schon. Die App-Liste kann Jamfs Titel ${app} ESR unter dieser Zeile führen, weil beide dieselbe Bundle-ID haben.`,
  unknownTrack: (app: string, track: string, tracks: string) =>
    `${app} hat in den Patch-Policy-Daten von LoonSec noch keinen Track ${track}; es hat ${tracks}. Wählen Sie oben einen.`,

  trackHeading: "Track",
  defaultTrack: "Standard",
  sourceHeading: "Release-Daten aus",
  sources: { public: "Öffentlich", jamf: "Jamf", fleet: "Fleet" },
  sourceHints: {
    public: "Die von LoonSec veröffentlichten Daten, jeweils aus der öffentlichen Release-Quelle, die sie nennen",
    jamf: "Die Kopie dieser Instanz von Jamfs öffentlichem Patch-Katalog",
    fleet: "Die Fleet-Historie dieser Instanz"
  },
  sourceWords: {
    public: "die von LoonSec veröffentlichten Release-Daten",
    jamf: "die Kopie dieser Instanz von Jamfs öffentlichem Patch-Katalog",
    fleet: "die Fleet-Historie dieser Instanz"
  },
  sourceUnavailable: "Nicht verfügbar",
  windowHeading: "Zeitfenster",
  years: (years: number) => `${years} Jahre`,
  alignLabel: "Quellen auf den Tagen vergleichen, die alle abdecken",
  alignHint:
    "Quellen unterscheiden sich in ihren Daten und in den Tagen, die jede abdeckt. Vergleichen Sie die Zahlen zweier Quellen nur mit dieser Einstellung, und lesen Sie die eigenen Zählungen jeder Ansicht.",

  reasons: {
    tier_off: () =>
      "Diese Organisation teilt keine Daten mit LoonSec und erhält daher keine Patch-Policy-Daten von LoonSec. Einstellungen › Datenfreigabe (troubleshooting.md §32 Schritt 1).",
    never: () => "Die Patch-Policy-Daten von LoonSec sind auf dieser Instanz noch nicht angekommen (troubleshooting.md §32 Schritt 2).",
    not_published: () => "Der letzte Austausch mit LoonSec enthielt keine Patch-Policy-Daten (troubleshooting.md §32 Schritt 3).",
    download_failed: () =>
      "Die Patch-Policy-Daten von LoonSec konnten nicht heruntergeladen werden, und es wird keine Kopie gehalten (troubleshooting.md §32 Schritt 5).",
    invalid: () =>
      "Die Patch-Policy-Daten von LoonSec haben ihre Prüfung nicht bestanden, und es wird keine Kopie gehalten (troubleshooting.md §32 Schritt 6).",
    algorithm_unknown: () =>
      "Die Patch-Policy-Daten von LoonSec liegen in einer Form vor, die dieser Build nicht liest. Aktualisieren Sie LoonInspect (troubleshooting.md §32 Schritt 4).",
    app_unknown: ({ app }: ReasonContext) => `Für ${app} gibt es noch keine Referenz. Das ist keine Zählung von null (troubleshooting.md §33 Schritt 2).`,
    track_unknown: ({ app, track }: ReasonContext) =>
      `${app} hat in den Patch-Policy-Daten von LoonSec noch keinen Track ${track} (troubleshooting.md §33 Schritt 2).`,
    no_public_dates: ({ app }: ReasonContext) =>
      `LoonSec hält für ${app} noch keine öffentlichen Release-Daten und hat daher keine eigenen zum Nachspielen. Jamf oder Fleet können es nur datieren, solange ein anderes Zeitfenster der App mit den veröffentlichten Summen von LoonSec übereinstimmt; stimmt keines überein, wird aus keiner Quelle eine Ansicht von ${app} gezeigt (troubleshooting.md §33 Schritt 3).`,
    no_public_timeline: ({ app }: ReasonContext) =>
      `LoonSec hält für ${app} noch keine öffentlichen Release-Daten und hat daher keine eigenen zum Nachspielen. Jamf oder Fleet können es nur datieren, solange ein anderes Zeitfenster der App mit den veröffentlichten Summen von LoonSec übereinstimmt; stimmt keines überein, wird aus keiner Quelle eine Ansicht von ${app} gezeigt (troubleshooting.md §33 Schritt 3).`,
    never_synced: () =>
      "Diese Instanz hat noch keine Synchronisierung von Jamfs öffentlichem Patch-Katalog abgeschlossen. Sie läuft zu jeder vollen Stunde und braucht keine Jamf-Pro-Verbindung (troubleshooting.md §6, §33 Schritt 4).",
    no_title: ({ app }: ReasonContext) =>
      `Die Kopie dieser Instanz von Jamfs öffentlichem Patch-Katalog hat keinen Titel für ${app}. Wählen Sie eine andere Quelle (troubleshooting.md §33 Schritt 4).`,
    no_versions: ({ app, source }: ReasonContext) =>
      `${opening(source)} nennt keine Version von ${app}; es gibt also nichts nachzuspielen. Wählen Sie eine andere Quelle (troubleshooting.md §33 Schritt 4).`,
    channel_empty: ({ track, source }: ReasonContext) =>
      `${opening(source)} führt kein Release von ${track}: Keine der Versionen darin gehört allein zu diesem Track. Sie stehen auf der Liste eines anderen Tracks, teilen ihre Nummer mit einer anderen Liste, fehlen in den Daten von LoonSec oder sind Builds eines Kanals, den die Daten von LoonSec noch nicht nachspielen. Wählen Sie einen anderen Track oder eine andere Quelle (troubleshooting.md §33 Schritt 4).`,
    flag_off: () =>
      "Fleets Katalog wird nicht gelesen, solange das Flag „Fleet catalog (maintained apps)“ für diese Organisation aus ist. Schalten Sie es unter Einstellungen › Feature-Flags ein und prüfen Sie erneut.",
    catalog_unread: () =>
      "Fleets Katalog wurde auf dieser Instanz noch nicht gelesen. Jetzt prüfen auf dem Tab Fleet-Katalog liest ihn (troubleshooting.md §27, §33 Schritt 5).",
    not_held: ({ app }: ReasonContext) =>
      `Fleets Katalog, wie diese Instanz ihn zuletzt gelesen hat, hat keinen Mac-Titel für ${app}. Wählen Sie eine andere Quelle (troubleshooting.md §33 Schritt 5).`,
    catalog_partial: ({ app }: ReasonContext) =>
      `Fleets Katalog wurde auf dieser Instanz nur teilweise gelesen, und der gelesene Teil hat keinen Mac-Titel für ${app}: Er kann unter den noch nicht gelesenen Titeln sein. Der Wortlaut der Instanz darunter nennt die Ursache. Wählen Sie eine andere Quelle, bis eine Prüfung den ganzen Katalog liest (troubleshooting.md §33 Schritt 5).`,
    history_unread: ({ app }: ReasonContext) =>
      `Fleets Versionshistorie für einen Titel von ${app} wurde auf dieser Instanz noch nicht gelesen (der Wortlaut der Instanz nennt den Titel); eine Administratorin oder ein Administrator mit patch:catalog-sync kann sie jetzt mit Historie lesen auf dem Tab Fleet-Katalog lesen (troubleshooting.md §27, §33 Schritt 5).`,
    history_failed: ({ app }: ReasonContext) =>
      `Das letzte Lesen von Fleets Versionshistorie für einen Titel von ${app} bekam keine Antwort. Es wird innerhalb der Stunde erneut versucht; Historie lesen auf dem Tab Fleet-Katalog versucht es sofort (troubleshooting.md §27, §33 Schritt 5).`,
    esr_missing: ({ app }: ReasonContext) =>
      `Die gelesene Fleet-Historie für ${app} nennt kein ESR-Release: Keine der Versionen darin gehört allein zum ESR-Track. Wählen Sie eine andere Quelle (troubleshooting.md §33 Schritt 5).`,
    line_not_followed: ({ app, track, source }: ReasonContext) =>
      `${opening(source)} folgt nur den neueren Linien von ${app}; für ${track} gibt es daraus nichts zu installieren. Wählen Sie den Track der neuesten Linie oder eine andere Quelle (troubleshooting.md §33 Schritt 5).`,
    ceiling_line_undated: ({ app, track, source }: ReasonContext) =>
      `${opening(source)} datiert kein Release der Linie, auf der ${track} gehalten wird; ${app} hat dort nichts zu halten. Wählen Sie den Track der neuesten Linie oder eine andere Quelle (troubleshooting.md §33 Schritt 5).`,
    no_matched_versions: ({ track, source, sourceId }: ReasonContext) =>
      `Keine der Versionen, die ${source} nennt, führen die Daten von LoonSec für ${track}. Wählen Sie eine andere Quelle (troubleshooting.md §33 Schritt ${joinStep(sourceId)}).`,
    too_many_unmatched: ({ track, source, sourceId }: ReasonContext) =>
      `Mehr als 5 % der Versionen, die ${source} in diesem Zeitfenster datiert, passen zu nichts, was die Daten von LoonSec für ${track} führen; der Durchlauf würde Installationen überspringen und wird abgelehnt. Wählen Sie Öffentlich (troubleshooting.md §33 Schritt ${joinStep(sourceId)}).`,
    nothing_to_install: ({ track, source }: ReasonContext) =>
      `${opening(source)} datiert kein Release, das der Mac auf ${track} installieren könnte. Wählen Sie eine andere Quelle (troubleshooting.md §33 Schritt 6).`,
    window_empty: ({ source }: ReasonContext) =>
      `Im angefragten Zeitfenster bleibt nichts nachzuspielen, sobald die Tage berücksichtigt sind, die die Quelle (${source}) abdeckt. Wählen Sie ein längeres Zeitfenster oder eine andere Quelle (troubleshooting.md §33 Schritt 6).`,
    parity: ({ app }: ReasonContext) =>
      `Der Durchlauf über die eigenen Daten von LoonSec für ${app} stimmt nicht mit den Summen überein, die LoonSec mit den Daten veröffentlicht hat; daher wird keine Ansicht von ${app} gezeigt. Auf dieser Instanz lässt sich das nicht beheben (troubleshooting.md §33 Schritt 7, Zustand AD).`,
    unchecked: ({ app }: ReasonContext) =>
      `LoonSec hat für kein Zeitfenster von ${app} Summen veröffentlicht, die dieser Build abgleichen konnte; daher wird keine Ansicht von ${app} gezeigt (troubleshooting.md §33 Schritt 7, Zustand AD).`,
    document_invalid: ({ app }: ReasonContext) =>
      `Die Patch-Policy-Daten von LoonSec für ${app} haben die Prüfung dieses Builds nicht bestanden; nichts wurde nachgespielt. Die Daten sind auf jeder Instanz gleich (troubleshooting.md §33 Schritt 7, Zustand AD).`,
    document_kind: () =>
      "Was diese Instanz als Patch-Policy-Daten von LoonSec hält, sind nicht diese Daten. Einstellungen › Support zeigt ihren Stand (troubleshooting.md §32).",
    invariant: () =>
      "LoonInspect hat seinen eigenen Durchlauf abgelehnt, weil seine Summen nicht übereinstimmen. Das ist ein Fehler dieses Builds, nicht der Daten dieser Instanz (troubleshooting.md §33 Schritt 8, Zustand AE).",
    timeline_invalid: () =>
      "LoonInspect hat die Release-Zeitleiste abgelehnt, die es für den Durchlauf gebaut hat. Das ist ein Fehler dieses Builds (troubleshooting.md §33 Schritt 8, Zustand AE).",
    request_invalid: () =>
      "LoonInspect hat den Durchlauf abgelehnt, den diese Seite angefragt hat. Das ist ein Fehler dieses Builds (troubleshooting.md §33 Schritt 8, Zustand AE)."
  },
  reasonUnknown: (reason: string) =>
    `Der Durchlauf wird nicht angezeigt (${reason}). Melden Sie den Wortlaut der Instanz unten mit dem Build aus Einstellungen › Support (troubleshooting.md §33).`,
  serverSaid: (sentence: string) => `Im Wortlaut dieser Instanz (englisch): ${sentence}`,
  unmatchedListed: (versions: string[]) => `Ohne Treffer: ${versions.join(", ")}`,
  channelSetAside: (count: number, label: string, step: number) =>
    `${count} ${mehrzahl(count, "Version", "Versionen")} von ${label} beiseitegelegt: Die Daten von LoonSec spielen diesen Kanal noch nicht nach; ${mehrzahl(count, "sie wird", "sie werden")} daher weder nachgespielt noch als ohne Treffer gezählt (troubleshooting.md §33 Schritt ${step}).`,
  channelListed: (label: string, versions: string[]) => `${label}, beiseitegelegt: ${versions.join(", ")}`,
  parityFacts: (stop: string, key: string, walked: number, published: number) =>
    `Bei ${stop}, ${key}: Der Durchlauf über die Daten von LoonSec zählt ${walked}, LoonSec hat ${published} veröffentlicht.`,
  windowsFacts: (entries: string[]) => `Jedes Zeitfenster: ${entries.join("; ")}`,

  notWalked: (source: string) =>
    `Über ${source} wird für diesen Track nichts nachgespielt: Der Grund steht oben unter der Auswahl. Wählen Sie eine andere Quelle oder einen anderen Track.`,
  walkLoading: (track: string, source: string) => `${track} wird über ${source} nachgespielt…`,
  walkFailed: (status: number | null) =>
    `Der Durchlauf konnte von dieser Instanz nicht gelesen werden (${beantwortet(status)}). Das ist ein fehlgeschlagener Lesevorgang, keine Ablehnung: Laden Sie neu; bleibt es dabei, melden Sie es mit dem Build aus Einstellungen › Support (troubleshooting.md §33 Schritt 10).`,
  walkUnreadable: (what: string) =>
    `Diese Instanz hat mit einem Durchlauf geantwortet, den diese Seite nicht darstellen kann (${what}). Laden Sie einmal neu: Eine Seite, die über ein Update hinweg offen blieb, liest eine Antwort, die ihr Build nicht mehr liefert. Lautet es gleich, melden Sie es mit dem Build (troubleshooting.md §33 Schritt 10, Zustand AE).`,

  reference: (label: string, line: string | null, since: string, until: string) =>
    `Ein hypothetischer Mac, auf dem ${label} läuft${line ? `, gehalten auf der Linie ${line}` : ""}, Tag für Tag nachgespielt von ${since} bis ${until} gegen die Patch-Policy-Daten von LoonSec. Dafür wird kein Inventar dieser Instanz gelesen, nichts wird irgendwohin gesendet, und keine Zahl hier wird gespeichert.`,
  dates: (name: string) => `Release-Daten: ${name}.`,
  readHere: "Auf dieser Instanz aus ihrer eigenen Kopie gelesen; nichts davon verlässt die Instanz.",
  fleetNote: "Das sind Fleets Daten, nicht die des Herstellers: Fleet baut seinen Katalog aus Homebrew und übernimmt ihn einige Stunden später.",
  clockLine:
    "Jede CVE zählt ab dem ersten Tag, an dem sie im Eintrag bei NVD erkennbar war, sofern die Daten von LoonSec diesen Tag enthalten, und sonst ab ihrem Veröffentlichungsdatum bei NVD. Jede Zeile sagt, welche Uhr gilt, und die Belege zählen beide.",
  shortened: (years: number, since: string, until: string, reasons: string[]) =>
    `Angefragt waren ${years} Jahre; diese Ansicht umfasst ${since} bis ${until}, weil ${reasons.join("; ")}. Belege › Zeitfenster nennt jeden Grund im Wortlaut der Instanz.`,
  windowReasons: {
    clock_coverage: "die Aufzeichnung von LoonSec, ab wann jede CVE erkennbar war, später beginnt",
    timeline_coverage: "die Release-Daten später beginnen und die 60-Tage-Stufe 59 Tage davon braucht",
    line_start: "die gehaltene Linie später beginnt und die 60-Tage-Stufe 59 Tage davon braucht",
    channel_start: "der Kanal später beginnt und die 60-Tage-Stufe 59 Tage davon braucht",
    common_window: "sie auf die Tage ausgerichtet ist, die jede verglichene Quelle abdeckt",
    ledger_as_of: "die Daten von LoonSec am Tag vor ihrem Datum enden",
    timeline_as_of: "die Release-Daten früher gelesen wurden",
    promotion_table: "die Beförderungstabelle noch keine Zeile für eine neuere Hauptversion hat"
  },
  aligned: (since: string, until: string, sources: string) => `Ausgerichtet auf ${since} bis ${until}, die Tage, die ${sources} gemeinsam abdecken.`,
  leftOut: (source: string) => `${source} bleibt außen vor:`,
  uncheckedWindow: (years: number, app: string) =>
    `LoonSec hat für ein Zeitfenster von ${years} Jahren von ${app} keine Prüfung; es wird angezeigt, weil ein anderes Zeitfenster von ${app} mit den veröffentlichten Summen von LoonSec übereinstimmte.`,
  and: "und",

  graphHeading: (stop: string) => `Offene CVEs pro Tag, bei ${stop}`,
  legendOpen: "An dem Tag offen",
  legendNew: "Geöffnet",
  legendResolved: "Durch ein Update behoben",
  graphSummary: (stop: string, since: string, until: string, first: number, last: number, peak: number, peakDate: string, opened: number, resolved: number) =>
    `Offene CVEs pro Tag von ${since} bis ${until} bei ${stop}: ${first} am ersten Tag und ${last} am letzten, höchstens ${peak} (zuerst am ${peakDate}); ${opened} nach dem ersten Tag geöffnet und ${resolved} durch ein Update behoben.`,
  graphKeys: "Die Grafik Tag für Tag lesen: Pfeiltasten gehen einen Tag, Bild auf und Bild ab dreißig, Pos1 und Ende an die Enden.",
  graphEmpty: (stop: string) => `Bei ${stop} war an keinem Tag dieses Zeitfensters eine aufgeführte CVE offen.`,
  openWord: "offen",
  tipOpen: (count: number) => `${count} offen`,
  tipNew: (count: number, became: number, entered: number) =>
    `${count} geöffnet${count > 0 ? ` (${became} wurden erkennbar, ${entered} kamen durch eine Installation hinzu)` : ""}`,
  tipResolved: (count: number) => `${count} behoben`,
  tipInstalled: (version: string) => `${version} installiert`,
  graphTable: "Die Tage, an denen sich die Zahl bewegte, als Tabelle",
  colDay: "Tag",
  colOpen: "Offen",
  colOpened: "Geöffnet",
  colResolved: "Behoben",
  colInstalled: "Installiert",

  neverSeenSaid:
    "Nie gesehen: Vom Uhrtag der CVE bis zum letzten Tag des Zeitfensters lief auf diesem Mac keine Version, die sie betrifft.",
  denominators: (counted: number, inWindow: number, excluded: number) =>
    `${counted} ${mehrzahl(counted, "CVE wird", "CVEs werden")} gezählt, von ${inWindow}, deren Uhrtag im Zeitfenster liegt. ${mehrzahl(excluded, "Die übrige ist", `Die übrigen ${excluded} sind`)} ausgeschlossen und unten gezählt; ausgeschlossen heißt nicht sicher.`,
  apart: (carried: number, carriedDays: number, entered: number, enteredDays: number, closed: number) =>
    `Gesondert ausgewiesen, aus der Zeit vor dem Zeitfenster: ${carried} am ersten Tag offen (${carriedDays} Expositionstage) und ${entered}, in die dieser Mac später geriet (${enteredDays} Expositionstage). ${closed} weitere waren darin nie offen.`,
  notCounted: (after: number, notDetectable: number) =>
    `Nicht gezählt: ${after}, deren Uhrtag nach dem Zeitfenster liegt, und ${notDetectable}, die die Daten von LoonSec als noch nicht erkennbar führen.`,
  exposedHint: "CVEs, für die dieser Mac ab ihrem Uhrtag eine betroffene Version ausführte",
  openAtEndHint: "gezählte, mitgebrachte und später hinzugekommene zusammen",
  colCarried: "Mitgebracht",

  ledgerHeading: "Jede aufgeführte CVE",
  colFrom: "Herkunft",
  classes: {
    in_window: "Das Zeitfenster",
    before_window: "Vor dem Zeitfenster",
    carried_in: "Vor dem Zeitfenster, am ersten Tag offen",
    entered_after_start: "Vor dem Zeitfenster, später hinzugekommen",
    pre_window_closed: "Vor dem Zeitfenster, darin nie offen"
  },
  colClock: "Uhrtag",
  clocked: { detectable_at: "zuerst erkennbar", published: "Veröffentlichung bei NVD" },
  colKev: "KEV",
  kevListed: (date: string) => `gelistet ${date}`,
  notOpen: "Im Zeitfenster nicht offen",
  fixDatedLead: (cve: string, count: number) => `${mehrzahl(count, "Fix", "Fixes")} von ${cve}, wie diese Quelle ${mehrzahl(count, "ihn", "sie")} datiert:`,
  fixNextDated: (fix: string, datedAs: string, on: string) =>
    `${fix}: von dieser Quelle nicht datiert, daher gezählt ab ${datedAs}, der ersten Version an oder über dem Fix, die sie datiert und die außerhalb des betroffenen Bereichs der CVE liegt, am ${on}`,
  historyBegins: {
    public: "Hier beginnen die veröffentlichten Daten von LoonSec",
    jamf: "Hier beginnt Jamfs Historie",
    fleet: "Hier beginnt Fleets Historie"
  },
  fixUndated: (fix: string, line: string) =>
    `${fix}: Diese Quelle datiert keine Version an oder über ihm ${line ? `auf der Linie ${line}` : "auf seiner Linie"} außerhalb des betroffenen Bereichs der CVE; diese CVE wird dort nach ihren betroffenen Bereichen nachgespielt`,
  fixNone: (line: string) =>
    `Keine Fix-Version ${line ? `auf der Linie ${line}` : "auf ihrer Linie"} in den Daten von LoonSec; diese CVE wird dort nach ihren betroffenen Bereichen nachgespielt`,
  nvdNamed: (named: string) => `NVD nennt ${named}`,
  nvdNamedMacBuild: (named: string) =>
    `NVD nennt ${named}, den Build einer anderen Plattform aus demselben Release; die Release-Mitteilung des Herstellers nennt den Build für den Mac; troubleshooting.md §33 Schritt 12`,
  pageOf: (page: number, pages: number, total: number) => `Seite ${page} von ${pages} · ${total} ${mehrzahl(total, "CVE", "CVEs")}`,
  previous: "Zurück",
  next: "Weiter",
  pastEnd: (page: number, pages: number, total: number) =>
    `Seite ${page} liegt hinter dem Ende dieser Liste: Sie umfasst ${total} ${mehrzahl(total, "CVE", "CVEs")} auf ${pages} ${mehrzahl(pages, "Seite", "Seiten")}. Die Adresse fragt nach einer Seite, die die Liste nicht hat, wie es ein Link kann, der gespeichert wurde, bevor sich die Daten von LoonSec änderten (troubleshooting.md §33 Schritt 10).`,
  toPage: (page: number) => `Seite ${page} zeigen`,

  exclusionReasons: {
    fixed_version_not_in_catalog:
      "Seit dem 2026-11-25 kein Grund mehr: Die Daten von LoonSec führen einen Fix, den die Versionsliste des Tracks nicht enthält, bei der nächsten Version an oder über ihm, mit der eigenen Version von NVD daneben. Eine seither erstellte Kopie zählt hier 0; eine ältere Kopie kann noch welche zählen",
    fixed_version_not_in_timeline:
      "Kein Grund mehr: Ein Fix, den diese Quelle nicht datiert, wird ab der nächsten Version an oder über ihm gezählt, die sie datiert. Eine ältere Kopie der Daten von LoonSec nennt den Grund noch, stets mit 0"
  },
  exclusionsSaid:
    "Ihr Uhrtag liegt im Zeitfenster, und jede ist aus einem Grund aus jeder Zahl oben herausgelassen. Sie wurden nicht nachgespielt; das ist nicht dasselbe wie: Sie betreffen diesen Mac nicht.",
  beforeExcluded: (count: number) => `${count} weitere aus der Zeit vor dem Zeitfenster sind aus denselben Gründen ausgeschlossen.`,

  asked: (years: string, since: string, until: string) => `angefragt ${years}, ${since} → ${until}`,
  evidenceDocument: "Daten von LoonSec",
  dated: (asOf: string) => `datiert ${asOf}`,
  readOn: (asOf: string) => `gelesen ${asOf}`,
  datesRange: (first: string, last: string) => `datiert ${first} bis ${last}`,
  evidenceJoin: "Zugeordnete Versionen",
  join: (matched: number, unmatched: number, other: number, undated: number, conflicts: number) =>
    `${matched} passten zu den Versionen des Tracks; ${unmatched} ohne Treffer (nie installiert); ${other} als die eines anderen Tracks beiseitegelegt; ${undated} undatiert; ${conflicts} mehrfach datiert.`,
  inReach: (share: number) =>
    `${(share * 100).toFixed(1).replace(".", ",")} % der erreichbaren Versionen sind ohne Treffer; über 5 % wird der Durchlauf abgelehnt.`,
  otherTrackListed: (versions: string[]) => `Eines anderen Tracks: ${versions.join(", ")}`,
  clockTotals: (detectable: number, published: number) =>
    `${detectable} gezählt ab dem ersten Tag, an dem sie erkennbar waren, ${published} ab der Veröffentlichung bei NVD.`,
  placedTotals: (detectable: number, published: number) =>
    `Jede gegen das Zeitfenster eingeordnete CVE: ${detectable} nach dem ersten erkennbaren Tag, ${published} nach der Veröffentlichung bei NVD.`,
  uncertain: (count: number) =>
    `${mehrzahl(count, "Eine gezählte CVE hat", `${count} gezählte CVEs haben`)} einen ersten erkennbaren Tag, der um mehr als einen Tag unsicher ist.`,
  evidenceFixDating: "Datierte Fixes",
  fixDating: (fix: number, next: number, undated: number) =>
    `Von den Fixes, die die aufgeführten CVEs auf den Linien nennen, die ein Gerät unter irgendeiner Stufe ausführt: ${fix} durch den Fix selbst datiert, ${next} durch die erste Version an oder über dem Fix, die diese Quelle datiert und die außerhalb des betroffenen Bereichs der CVE liegt, ${undated} durch keine${undated > 0 ? mehrzahl(undated, "; diese CVE wird dort nach ihren betroffenen Bereichen nachgespielt", "; diese CVEs werden dort nach ihren betroffenen Bereichen nachgespielt") : ""} (troubleshooting.md §33 Schritt 12).`,
  evidenceCheck: "Prüfung",
  checks: {
    matched: "Stimmt mit den Summen überein, die LoonSec für dieses Zeitfenster veröffentlicht hat.",
    unchecked_window: "Ohne eigene Prüfung angezeigt: Ein anderes Zeitfenster der App stimmte überein."
  },
  checkedByPublic:
    "Nicht selbst geprüft: LoonSec veröffentlicht Summen nur für die eigenen Release-Daten, über das angefragte Zeitfenster ohne Ausrichtung. Diese Ansicht wird gezeigt, weil dieser Durchlauf, unten genannt, mit ihnen übereinstimmte.",
  evidenceInput: "Eingabe",
  evidenceRun: "Lauf",
  definitionsHeading: "Definitionen und Uhren, im Wortlaut des Durchlaufs"
};

/** A state word's sentence in the reader's language. A word this build has no sentence for is the
 *  instance's own sentence, or, with none, a sentence that names the word. */
export function reasonWords(words: WalkCopy, reason: string, context: ReasonContext, fallback: string): string {
  const said = words.reasons[reason];
  return said ? said(context) : fallback || words.reasonUnknown(reason);
}
