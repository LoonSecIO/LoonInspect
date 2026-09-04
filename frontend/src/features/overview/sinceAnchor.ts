import type { DeviceChange } from "@/features/changes/types";

/**
 * "Since you last looked" — the anchor the Overview feed measures from (#107).
 *
 * Pure on purpose, and separate from the component for the reason `heroRun.ts` is: every
 * rule here is a decision that can be wrong in a way a screenshot will not reveal, and
 * none of it needs React to be checked. This module has no test today because the
 * frontend has no test runner at all — that is [#285](https://github.com/LoonSecIO/LoonInspect/issues/285),
 * and this file is the first thing it should aim at.
 */

/** Where the last-visit stamp lives. Per browser, deliberately: "since you last looked"
 *  is a fact about a person at a screen, not about the pod, and putting it in the
 *  database would make one admin's visit reset another's feed. */
export const LAST_VISIT_KEY = "loon.overview.lastVisit";

/** How far back the feed reaches for someone with no stored visit. A first visit, a new
 *  browser, a cleared profile — all the same case, and all better served by a day of
 *  history than by an empty feed that looks like nothing happened. */
export const FALLBACK_HOURS = 24;

/**
 * The instant the feed measures from, as an absolute ISO string.
 *
 * **Absolute, never relative, and that is the whole point of the ruling.** The anchor is
 * discovered from per-browser state, but the moment it is chosen it becomes a fixed
 * timestamp that is printed in the header and baked into every click-through URL. A
 * relative `since=24h` would mean something different every time the link was opened, so
 * a shared link or a screenshot in a ticket would not reproduce what the sender saw.
 *
 * `storedAt` is read by the caller rather than by this function so the module stays pure
 * and `localStorage` — which throws in some privacy modes and is absent in a test — is
 * handled in exactly one place.
 */
export function resolveAnchor(storedAt: string | null, now: Date): string {
  if (storedAt) {
    const parsed = Date.parse(storedAt);
    // A corrupt or hand-edited value falls back rather than propagating `Invalid Date`
    // into a URL, where it would become `since=Invalid%20Date` and 422 the API.
    if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
  }
  return new Date(now.getTime() - FALLBACK_HOURS * 3600_000).toISOString();
}

/** Read the stored visit, surviving a `localStorage` that throws or is absent. Private
 *  browsing and blocked site-data both raise on access rather than returning null. */
export function readLastVisit(): string | null {
  try {
    return window.localStorage.getItem(LAST_VISIT_KEY);
  } catch {
    return null;
  }
}

/** Stamp this visit. Failure is silent and harmless: the next visit falls back to 24h,
 *  which is the same experience a first visit gets. */
export function writeLastVisit(at: Date): void {
  try {
    window.localStorage.setItem(LAST_VISIT_KEY, at.toISOString());
  } catch {
    /* a browser that refuses storage still gets a working feed */
  }
}

/** The click-through target, carrying the anchor so the page a row opens shows the same
 *  window the feed summarised. `minLevel` rides along for the same reason: the feed shows
 *  notable-and-above, and a link that silently widened to every `low` row would not be
 *  the thing that was clicked. */
export function changesHref(anchor: string, minLevel = "normal"): string {
  const params = new URLSearchParams({ since: anchor, minLevel });
  return `/devices/changes?${params.toString()}`;
}

export interface FeedSummary {
  /** Rows the feed is showing — notable and above, newest first. */
  rows: DeviceChange[];
  /** Every change since the anchor, at any level. */
  total: number;
  /** Distinct devices those changes touched. */
  devices: number;
  /** How many of them were notable. */
  notable: number;
}

/**
 * The header's four numbers, counted from the rows the API returned.
 *
 * `total` is the API's own count for the window and is passed in rather than derived,
 * because the feed asks for a page of rows and the header must not say "10 changes"
 * when it means "10 shown". `devices` and `notable` are counted over what was fetched,
 * which is exact whenever the window fits in one page and an undercount beyond it — the
 * page size is chosen so that is rare, and the honest header names the window, not a
 * guarantee about it.
 */
export function summarise(rows: DeviceChange[], total: number): FeedSummary {
  const devices = new Set(rows.map((row) => row.subjectId)).size;
  const notable = rows.filter((row) => row.level === "high" || row.level === "normal").length;
  return { rows, total, devices, notable };
}
