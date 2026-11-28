import { describe, expect, it, vi } from "vitest";
import { STALE_AFTER_MS, describeFeed, onlyOlder, publisherRunning, type PatchPolicyFeed } from "@/features/support/patchPolicyFeed";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const words = en.support.patchPolicyFeed;

function feed(state: PatchPolicyFeed["state"], extra: Partial<PatchPolicyFeed> = {}): PatchPolicyFeed {
  return {
    state,
    sentence: "",
    algorithm: "patch_walk/2",
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
    publisherRunning: null,
    ...extra
  };
}

const held = { asOf: "2026-11-23T20:00:00Z", until: "2026-11-22", docId: "a5b281246cafda4b", fetchedAt: "2026-11-24T02:00:00Z" };
/** The page's clock for every sentence below: four days and an hour after the copy's `asOf`. */
const NOW = new Date("2026-11-27T21:00:00Z");

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
    "stale, LoonSec's publisher running over NVD data that has not advanced",
    feed("stale", { ...held, builtAt: "2026-11-27T07:12:03Z", publisherRunning: true }),
    "Showing patch-policy data dated 2026-11-23, more than three days old: LoonSec's publisher last ran on 2026-11-27, but its NVD data has not advanced since 2026-11-23, and the walk ends 2026-11-22."
  ],
  [
    "stale, LoonSec's publisher stopped",
    feed("stale", { ...held, builtAt: "2026-11-24T07:12:03Z", publisherRunning: false }),
    "Showing patch-policy data dated 2026-11-23, more than three days old: LoonSec's publisher last ran on 2026-11-24, more than three days ago, and the walk ends 2026-11-22."
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
    feed("algorithm_unknown", { ...held, detail: "patch_walk/3" }),
    "This build reads patch_walk/2; LoonSec's last exchange named only patch_walk/3. If the next exchange names the same, update LoonInspect. Showing the copy dated 2026-11-23."
  ],
  [
    // patch_walk/1 is never published (ruled 2026-11-27): a v1.5 build offered only it is not behind.
    "algorithm unknown, only an older one, no copy",
    feed("algorithm_unknown", { detail: "patch_walk/1" }),
    "This build reads patch_walk/2; LoonSec's last exchange named only patch_walk/1, which older builds read. Nothing on this instance needs updating; report it if it lasts a day. This instance holds no copy yet."
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
    expect(describeFeed(value, words, NOW)).toBe(sentence);
  });

  it("names the cause the instance judged, whatever this browser's clock says", () => {
    // The instance read its clock at 2026-11-25T12:00Z: the build of the 22nd is more than three
    // days old, so its sentence says the publisher stopped. A browser a day behind must say the same.
    const stopped = feed("stale", { ...held, builtAt: "2026-11-22T06:00:00Z", publisherRunning: false });
    const behind = new Date("2026-11-24T12:00:00Z");
    expect(publisherRunning("2026-11-22T06:00:00Z", behind)).toBe(true);
    expect(describeFeed(stopped, words, behind)).toBe(
      "Showing patch-policy data dated 2026-11-23, more than three days old: LoonSec's publisher last ran on 2026-11-22, more than three days ago, and the walk ends 2026-11-22."
    );
    // And the other way: the instance judged it running; a browser days ahead still says running.
    const running = feed("stale", { ...held, builtAt: "2026-11-24T07:12:03Z", publisherRunning: true });
    const ahead = new Date("2026-12-01T00:00:00Z");
    expect(publisherRunning("2026-11-24T07:12:03Z", ahead)).toBe(false);
    expect(describeFeed(running, words, ahead)).toContain("last ran on 2026-11-24, but its NVD data has not advanced since 2026-11-23");
  });

  it("with no judgement from the instance, calls LoonSec's publisher running for three days after its last build, to the millisecond, as the backend does", () => {
    const built = "2026-11-24T07:12:03Z";
    const at = Date.parse(built);
    expect(STALE_AFTER_MS).toBe(3 * 24 * 60 * 60 * 1000);
    expect(publisherRunning(built, new Date(at + 60_000))).toBe(true);
    expect(publisherRunning(built, new Date(at + STALE_AFTER_MS))).toBe(true);
    expect(publisherRunning(built, new Date(at + STALE_AFTER_MS + 1))).toBe(false);
    // The same copy reads either cause, by when the page is read: `builtAt` never makes it current.
    const copy = feed("stale", { ...held, builtAt: built, publisherRunning: null });
    expect(describeFeed(copy, words, new Date(at + STALE_AFTER_MS))).toContain("but its NVD data has not advanced since 2026-11-23");
    expect(describeFeed(copy, words, new Date(at + STALE_AFTER_MS + 1))).toContain("last ran on 2026-11-24, more than three days ago");
  });

  it("reads the page's own clock when it is given none and the instance sent no judgement", () => {
    vi.useFakeTimers();
    try {
      const copy = feed("stale", { ...held, builtAt: "2026-11-24T07:12:03Z" });
      vi.setSystemTime(new Date("2026-11-25T00:00:00Z"));
      expect(describeFeed(copy, words)).toContain("but its NVD data has not advanced since");
      vi.setSystemTime(new Date("2026-11-30T00:00:00Z"));
      expect(describeFeed(copy, words)).toContain("more than three days ago");
    } finally {
      vi.useRealTimers();
    }
  });

  it("names the file, not the exchange, on an instance that reads PATCH_POLICY_FEED_FILE", () => {
    expect(describeFeed(feed("never", { fromFile: true }), words)).toBe(words.states.neverFile);
  });

  it("has a German sentence for every state", () => {
    for (const [, value] of BACKEND) {
      const german = describeFeed(value, de.support.patchPolicyFeed, NOW);
      expect(german).not.toBe("");
      expect(german).not.toBe(describeFeed(value, words, NOW));
    }
  });

  it("tells data only older builds read from data for a newer one, as the backend's only_older does", () => {
    for (const [named, older] of [
      ["patch_walk/1", true],
      ["patch_walk/1, patch_walk/0", true],
      ["patch_walk/3", false],
      ["patch_walk/1, patch_walk/3", false],
      ["other_walk/1", false],
      ["x", false],
      ["", false],
      [null, false]
    ] as const) {
      expect(onlyOlder(named, "patch_walk/2"), String(named)).toBe(older);
    }
    expect(onlyOlder("patch_walk/1", "not_a_walk")).toBe(false);
    const german = de.support.patchPolicyFeed;
    expect(describeFeed(feed("algorithm_unknown", { ...held, detail: "patch_walk/1" }), german, NOW)).toBe(
      "Dieser Build liest patch_walk/2; der letzte Austausch mit LoonSec nannte nur patch_walk/1, was ältere Builds lesen. Auf dieser Instanz muss nichts aktualisiert werden; melden Sie es, wenn es länger als einen Tag anhält. Angezeigt wird die Kopie vom 2026-11-23."
    );
  });

  it("names the stale copy's cause in German too", () => {
    const german = de.support.patchPolicyFeed;
    expect(describeFeed(feed("stale", { ...held, builtAt: "2026-11-27T07:12:03Z", publisherRunning: true }), german, NOW)).toBe(
      "Angezeigt werden Patch-Policy-Daten vom 2026-11-23, mehr als drei Tage alt: Der Veröffentlichungsdienst von LoonSec lief zuletzt am 2026-11-27, aber seine NVD-Daten stehen seit dem 2026-11-23 still, und der Durchlauf endet am 2026-11-22."
    );
    expect(describeFeed(feed("stale", { ...held, builtAt: "2026-11-24T07:12:03Z", publisherRunning: false }), german, NOW)).toBe(
      "Angezeigt werden Patch-Policy-Daten vom 2026-11-23, mehr als drei Tage alt: Der Veröffentlichungsdienst von LoonSec lief zuletzt am 2026-11-24, vor mehr als drei Tagen, und der Durchlauf endet am 2026-11-22."
    );
  });
});
