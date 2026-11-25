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
}

export interface PatchPolicySource {
  available: boolean;
  first: string | null;
  last: string | null;
  sentence: string | null;
  ids: string[];
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

/** The state's sentence, the way `sentence_for` builds it: the state's words, then the copy that
 *  still answers (or that there is none) after a failure. */
export function describeFeed(feed: PatchPolicyFeed, words: FeedWords): string {
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
      return s.stale(asOf ?? "—", feed.until ?? "—");
    case "not_published":
      return `${s.not_published} ${copy()}`;
    case "algorithm_unknown":
      return `${s.algorithm_unknown(feed.algorithm, feed.detail || words.anotherAlgorithm)} ${copy()}`;
    case "download_failed":
      return feed.source === "file"
        ? `${s.readFailed(feed.host ?? words.fromFile, detail)} ${copy()}`
        : `${s.downloadFailed(feed.host ?? words.exchangeLink, detail)} ${copy()}`;
    case "invalid":
      return `${s.invalid(detail)} ${copy(true)}`;
  }
}
