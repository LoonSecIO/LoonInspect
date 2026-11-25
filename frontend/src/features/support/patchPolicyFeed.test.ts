import { describe, expect, it } from "vitest";
import { describeFeed, type PatchPolicyFeed } from "@/features/support/patchPolicyFeed";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const words = en.support.patchPolicyFeed;

function feed(state: PatchPolicyFeed["state"], extra: Partial<PatchPolicyFeed> = {}): PatchPolicyFeed {
  return {
    state,
    sentence: "",
    algorithm: "patch_walk/1",
    docId: null,
    asOf: null,
    fetchedAt: null,
    coverageSince: null,
    until: null,
    attemptedAt: null,
    source: null,
    outcome: null,
    host: null,
    httpStatus: null,
    detail: null,
    fromFile: false,
    builtAt: null,
    ...extra
  };
}

const held = { asOf: "2026-11-23T20:00:00Z", until: "2026-11-22", docId: "a5b281246cafda4b", fetchedAt: "2026-11-24T02:00:00Z" };

// Each expectation is the backend's own sentence for the same state, copied from
// `app.core.patch_policy_feed.sentence_for` (docs/troubleshooting.md §32 quotes them): the page and
// the API must say one thing.
const BACKEND: [string, PatchPolicyFeed, string][] = [
  [
    "tier off",
    feed("tier_off"),
    "This organization does not share data with LoonSec, so it does not receive LoonSec's patch-policy data. Settings › Data Sharing."
  ],
  [
    "never",
    feed("never"),
    "LoonSec's patch-policy data has not arrived on this instance yet. It rides the daily data-sharing exchange; Settings › Data Sharing shows the last exchange."
  ],
  ["current", feed("current", held), "Showing LoonSec's patch-policy data dated 2026-11-23."],
  ["stale", feed("stale", held), "Showing patch-policy data dated 2026-11-23, more than three days old; the walk ends 2026-11-22."],
  [
    "stale, by LoonSec's last confirmation",
    feed("stale", { ...held, builtAt: "2026-11-24T07:12:03Z" }),
    "Showing patch-policy data dated 2026-11-23; LoonSec last confirmed it current on 2026-11-24, more than three days ago, and the walk ends 2026-11-22."
  ],
  [
    "not published, no copy",
    feed("not_published"),
    "LoonSec's last exchange carried no patch-policy data. Nothing on this instance is wrong; report it if it lasts a day. This instance holds no copy yet."
  ],
  [
    "not published, a copy held",
    feed("not_published", held),
    "LoonSec's last exchange carried no patch-policy data. Nothing on this instance is wrong; report it if it lasts a day. Showing the copy dated 2026-11-23."
  ],
  [
    "algorithm unknown",
    feed("algorithm_unknown", { ...held, detail: "patch_walk/2" }),
    "This build reads patch_walk/1; LoonSec's last exchange named only patch_walk/2. If the next exchange names the same, update LoonInspect. Showing the copy dated 2026-11-23."
  ],
  [
    "download failed",
    feed("download_failed", {
      ...held,
      source: "exchange",
      host: "bucket.s3.us-east-1.amazonaws.com",
      detail: "the patch-policy download did not complete (HTTP 403)"
    }),
    "The patch-policy file could not be downloaded from bucket.s3.us-east-1.amazonaws.com: the patch-policy download did not complete (HTTP 403). Showing the copy dated 2026-11-23."
  ],
  [
    "file unreadable",
    feed("download_failed", {
      source: "file",
      host: "/app/data/patch-policy.json.gz",
      detail: "the file could not be read (Permission denied)",
      fromFile: true
    }),
    "The patch-policy file could not be read from /app/data/patch-policy.json.gz: the file could not be read (Permission denied). This instance holds no copy yet."
  ],
  [
    "invalid, a copy held",
    feed("invalid", { ...held, source: "exchange", host: "h", detail: "its schema is 2; this build reads schema 1" }),
    "LoonSec's patch-policy data failed its check (its schema is 2; this build reads schema 1), so it was not stored. The copy dated 2026-11-23 is still used."
  ],
  [
    "invalid, no copy",
    feed("invalid", { detail: "it is not JSON (JSONDecodeError)" }),
    "LoonSec's patch-policy data failed its check (it is not JSON (JSONDecodeError)), so it was not stored. This instance holds no copy yet."
  ]
];

describe("describeFeed", () => {
  it.each(BACKEND)("says what the backend says: %s", (_name, value, sentence) => {
    expect(describeFeed(value, words)).toBe(sentence);
  });

  it("names the file, not the exchange, on an instance that reads PATCH_POLICY_FEED_FILE", () => {
    expect(describeFeed(feed("never", { fromFile: true }), words)).toBe(words.states.neverFile);
  });

  it("has a German sentence for every state", () => {
    for (const [, value] of BACKEND) {
      const german = describeFeed(value, de.support.patchPolicyFeed);
      expect(german).not.toBe("");
      expect(german).not.toBe(describeFeed(value, words));
    }
  });
});
