import { apiRequest } from "@/config/api";
import type { Translations } from "@/i18n/en";

/**
 * LoonSec's patch-policy document on this instance (#614): `GET /api/patch-policy/apps`, and the
 * one sentence its feed state says. Pure apart from the fetch, so the sentence can be held to the
 * backend's own (`app.core.patch_policy_feed.sentence_for`) in a test.
 */

export type PatchPolicyFeedState =
  | "tier_off"
  | "never"
  | "current"
  | "stale"
  | "not_published"
  | "algorithm_unknown"
  | "download_failed"
  | "invalid";

export interface PatchPolicyFeed {
  state: PatchPolicyFeedState;
  /** The backend's sentence, in English. The page says its own, in the reader's language. */
  sentence: string;
  algorithm: string;
  docId: string | null;
  asOf: string | null;
  fetchedAt: string | null;
  coverageSince: string | null;
  until: string | null;
  attemptedAt: string | null;
  source: "exchange" | "file" | null;
  outcome: string | null;
  host: string | null;
  httpStatus: number | null;
  detail: string | null;
  fromFile: boolean;
  /** When LoonSec's publisher last finished a build, as the exchange said; null when it did not say.
   *  It never decides `stale` (the copy's own `asOf` does): it names the cause, the publisher still
   *  running over NVD data that has not advanced, or the publisher stopped (`publisherRunning`). */
  builtAt: string | null;
  /** Which of those two causes the instance judged, by its own clock: true while `builtAt` is within
   *  three days of its now, false once older, null when `builtAt` is. The page names the cause from
   *  it, so the page's sentence and `sentence` never name different causes. */
  publisherRunning: boolean | null;
}

/** One source against one track: whether a walk of it can be shown at the default two-year window,
 *  and if not, why (`state` and `sentence`, docs/troubleshooting.md §33). */
export interface PatchPolicySourceTrack {
  track: string;
  available: boolean;
  state: string;
  sentence: string | null;
  first: string | null;
  last: string | null;
  matched: number;
  otherTrack: number;
  /** Versions of a channel LoonSec's data names and does not walk, set aside; absent from an older instance. */
  otherChannel?: number;
  unmatched: number;
  since: string | null;
  until: string | null;
}

export interface PatchPolicySource {
  available: boolean;
  state: string;
  first: string | null;
  last: string | null;
  sentence: string | null;
  ids: string[];
  matched: number;
  asOf: string | null;
  /** Shown with every view of the source (Fleet's dates trail Homebrew's by hours). */
  note: string | null;
  tracks: PatchPolicySourceTrack[];
}

export interface PatchPolicyTrack {
  track: string;
  label: string;
  default: boolean;
  channel: string | null;
  edition: string | null;
  timeline: string | null;
  versions: number;
  versionsDated: number;
  candidates: number;
  listed: number;
  excluded: number;
  notDetectable: number;
  clock: { detectableAt: number; published: number };
}

export interface PatchPolicyApp {
  app: string;
  name: string;
  bundleIds: string[];
  tracks: PatchPolicyTrack[];
  sources: { public: PatchPolicySource; jamf: PatchPolicySource; fleet: PatchPolicySource };
}

export interface PatchPolicyAppsResponse {
  feed: PatchPolicyFeed;
  /** Null, never empty, when no copy answers for this organization: `feed.state` says why. */
  apps: PatchPolicyApp[] | null;
}

export function getPatchPolicyApps(): Promise<PatchPolicyAppsResponse> {
  return apiRequest<PatchPolicyAppsResponse>("/patch-policy/apps");
}

export type FeedWords = Translations["support"]["patchPolicyFeed"];

/** The day a timestamp names, in UTC, as the backend writes it into its sentences. */
const day = (value: string | null): string | null => (value ? value.slice(0, 10) : null);

/** The backend's `STALE_AFTER`: a copy older than this is stale, and a publisher whose last build is
 *  older than this has stopped. */
export const STALE_AFTER_MS = 3 * 24 * 60 * 60 * 1000;

/** Whether LoonSec's publisher is still running: its last build (`builtAt`) no more than three days
 *  before `now`, the backend's `held_freshness` rule. Read against this browser's clock, so it is the
 *  fallback only, for an answer that carries no `publisherRunning`: the instance's own judgement is
 *  what its sentence says, and a browser whose clock is off near the three-day boundary would
 *  otherwise name the other cause. */
export function publisherRunning(builtAt: string, now: Date): boolean {
  return now.getTime() - Date.parse(builtAt) <= STALE_AFTER_MS;
}

/** N of a `patch_walk/N` name, or null for any other name: the backend's `algorithm_number`. */
function walkNumber(name: string): number | null {
  const match = /^patch_walk\/([0-9]+)$/.exec(name);
  return match ? Number(match[1]) : null;
}

/** Whether every algorithm the exchange named (`algorithm_unknown`'s detail, joined by commas) is an
 *  older `patch_walk` than the one this build reads: the backend's `only_older`, so the page names
 *  the same case. Then no update can reach the data, and the sentence says so. */
export function onlyOlder(named: string | null, reads: string): boolean {
  const ours = walkNumber(reads);
  const names = (named ?? "").split(",").map((each) => each.trim()).filter((each) => each !== "");
  return (
    ours !== null &&
    names.length > 0 &&
    names.every((name) => {
      const number = walkNumber(name);
      return number !== null && number < ours;
    })
  );
}

/** The state's sentence, the way `sentence_for` builds it: the state's words, then the copy that
 *  still answers (or that there is none) after a failure. A stale copy's cause is the instance's
 *  `feed.publisherRunning`; `now` is read only when that is missing (`publisherRunning`). */
export function describeFeed(feed: PatchPolicyFeed, words: FeedWords, now: Date = new Date()): string {
  const s = words.states;
  const asOf = day(feed.asOf);
  const copy = (stillUsed = false) => (asOf === null ? words.noCopy : stillUsed ? words.stillUsed(asOf) : words.showingCopy(asOf));
  const detail = feed.detail ?? "";
  switch (feed.state) {
    case "tier_off":
      return s.tier_off;
    case "never":
      return feed.fromFile ? s.neverFile : s.never;
    case "current":
      return s.current(asOf ?? "—");
    case "stale":
      if (!feed.builtAt) return s.stale(asOf ?? "—", feed.until ?? "—");
      return ((feed.publisherRunning ?? publisherRunning(feed.builtAt, now)) ? s.staleRunning : s.staleStopped)(
        asOf ?? "—",
        day(feed.builtAt) ?? "—",
        feed.until ?? "—"
      );
    case "not_published":
      return `${s.not_published} ${copy()}`;
    case "algorithm_unknown":
      return onlyOlder(feed.detail, feed.algorithm)
        ? `${s.algorithmOlder(feed.algorithm, feed.detail ?? "")} ${copy()}`
        : `${s.algorithm_unknown(feed.algorithm, feed.detail || words.anotherAlgorithm)} ${copy()}`;
    case "download_failed":
      return feed.source === "file"
        ? `${s.readFailed(feed.host ?? words.fromFile, detail)} ${copy()}`
        : `${s.downloadFailed(feed.host ?? words.exchangeLink, detail)} ${copy()}`;
    case "invalid":
      return `${s.invalid(detail)} ${copy(true)}`;
  }
}
