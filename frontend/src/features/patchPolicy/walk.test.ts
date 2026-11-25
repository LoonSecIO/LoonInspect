/** The day-walk's reader and the few decisions the page makes about its answer (#614): what is asked,
 *  which answers are a walk, a refusal or a failed read, which source can date which track, and what
 *  the day graph reads off a stop's series. Node lane: `fetch` is stubbed, nothing is drawn. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { appFixture, walkFixture } from "@/features/patchPolicy/testing/walkFixtures";
import { patchPolicyEnglish, patchPolicyGerman } from "@/features/patchPolicy/copy";
import { walkEnglish, walkGerman } from "@/features/patchPolicy/walkCopy";
import {
  channelsSetAside,
  dayAfter,
  defaultTrack,
  esrFoldedIn,
  getPatchPolicyWalk,
  movedDays,
  seriesDay,
  sourceTrack,
  summarise,
  unreadable,
  walkQuery,
  yTicks,
  yearTicks
} from "@/features/patchPolicy/walk";

const reply = (status: number, body: unknown) =>
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }))));

afterEach(() => vi.unstubAllGlobals());

describe("what the page asks for", () => {
  it("names the app, track, source and window, and align and page only when they are not the default", () => {
    const base = { app: "chrome", track: "chrome/stable", source: "public" as const, years: 2 as const, align: false, page: 1 };
    expect(walkQuery(base)).toBe("app=chrome&track=chrome%2Fstable&source=public&years=2");
    expect(walkQuery({ ...base, source: "fleet", years: 3, align: true, page: 2 })).toBe(
      "app=chrome&track=chrome%2Fstable&source=fleet&years=3&align=common&page=2"
    );
  });
});

describe("the three answers", () => {
  it("a walk this build can draw is a walk", async () => {
    reply(200, walkFixture());
    const answer = await getPatchPolicyWalk("app=example");
    expect(answer.walk?.run_id).toBe("fixture-run-0001");
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("/api/patch-policy/walk?app=example");
  });

  it("a 409 is a refusal, with its reason, source and facts", async () => {
    reply(409, { detail: "The sentence.", reason: "too_many_unmatched", source: "jamf", facts: { in_reach: { unmatched: ["1.0rc1"] } } });
    expect(await getPatchPolicyWalk("app=example")).toEqual({
      refusal: { detail: "The sentence.", reason: "too_many_unmatched", source: "jamf", facts: { in_reach: { unmatched: ["1.0rc1"] } } }
    });
  });

  it("a 409 without a reason, another status, or no answer at all is a failed read, never a refusal", async () => {
    reply(409, { detail: "A sentence with no reason." });
    expect(await getPatchPolicyWalk("app=example")).toEqual({ failed: { status: 409 } });
    reply(502, "Bad Gateway");
    expect(await getPatchPolicyWalk("app=example")).toEqual({ failed: { status: 502 } });
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))));
    expect(await getPatchPolicyWalk("app=example")).toEqual({ failed: { status: null } });
  });

  it("an answer this build cannot draw is a failed read that names what it could not draw", async () => {
    reply(200, { ...walkFixture(), schema: 2 });
    expect(await getPatchPolicyWalk("app=example")).toEqual({ failed: { status: 200, unreadable: "schema 2" } });
  });

  it("names the first part it cannot draw", () => {
    const walk = walkFixture();
    expect(unreadable(walk)).toBeNull();
    expect(unreadable([])).toBe("not an object");
    expect(unreadable({ ...walk, kind: "patch_policy_reference" })).toBe('kind "patch_policy_reference"');
    expect(unreadable({ ...walk, window: { ...walk.window, days: 11 } })).toBe("policies.1d.series.open");
    const five: Partial<typeof walk.policies> = { ...walk.policies };
    delete five.never;
    expect(unreadable({ ...walk, policies: five })).toBe("policies.never.series");
    expect(unreadable({ ...walk, cves: null })).toBe("cves");
  });
});

describe("what /apps says about a source and a track", () => {
  it("the default track is the one marked default, else the first", () => {
    const app = appFixture();
    expect(defaultTrack(app)).toBe("example/4.4");
    expect(defaultTrack({ tracks: app.tracks.map((track) => ({ ...track, default: false })) })).toBe("example/4.4");
    expect(defaultTrack({ tracks: [] })).toBeNull();
  });

  it("reads one source's answer for one track", () => {
    const app = appFixture();
    expect(sourceTrack(app, "public", "example/newest")?.available).toBe(true);
    expect(sourceTrack(app, "jamf", "example/4.4")?.state).toBe("no_title");
    expect(sourceTrack(app, "fleet", "example/esr")).toBeUndefined();
  });

  it("an ESR title under the app's bundle id is folded in only when the data has no ESR track", () => {
    const app = appFixture();
    const titles = [{ name: "Example ESR", bundleId: "COM.EXAMPLE.APP" }];
    expect(esrFoldedIn(app, titles)).toBe(true);
    expect(esrFoldedIn(app, [{ name: "Example", bundleId: "com.example.app" }, { name: "Other ESR", bundleId: "com.example.other" }])).toBe(false);
    expect(esrFoldedIn({ ...app, tracks: [...app.tracks, { ...app.tracks[0], track: "example/esr", channel: "esr", edition: "esr" }] }, titles)).toBe(false);
  });
});

describe("what the day graph reads", () => {
  const walk = walkFixture();
  const sevenDay = walk.policies["7d"];

  it("counts days in UTC, across a month and a leap day", () => {
    expect(dayAfter("2025-01-01", 0)).toBe("2025-01-01");
    expect(dayAfter("2025-01-31", 1)).toBe("2025-02-01");
    expect(dayAfter("2024-02-28", 1)).toBe("2024-02-29");
  });

  it("reads one day, with what was installed on it", () => {
    expect(seriesDay(sevenDay, walk.window.since, 3)).toEqual({
      offset: 3,
      date: "2025-01-04",
      open: 0,
      new: 0,
      becameDetectable: 0,
      enteredRange: 0,
      resolved: 1,
      installed: "4.4.2"
    });
    expect(seriesDay(sevenDay, walk.window.since, 5)).toMatchObject({ date: "2025-01-06", open: 1, new: 1, becameDetectable: 1 });
  });

  it("lists the first day and every day the count moved, as the graph's table", () => {
    expect(movedDays(sevenDay, walk.window.since).map((day) => [day.date, day.open, day.new, day.resolved])).toEqual([
      ["2025-01-01", 1, 0, 0],
      ["2025-01-04", 0, 0, 1],
      ["2025-01-06", 1, 1, 0],
      ["2025-01-09", 0, 0, 1]
    ]);
  });

  it("summarises where the count starts, ends and peaks, and how many opened and were resolved", () => {
    expect(summarise(sevenDay, walk.window.since)).toEqual({ first: 1, last: 0, peak: 1, peakDate: "2025-01-01", opened: 1, resolved: 2 });
    expect(summarise(walk.policies.never, walk.window.since)).toMatchObject({ first: 1, last: 2, peak: 2, peakDate: "2025-01-06", resolved: 0 });
  });

  it("ends the y-axis on a clean whole number at or above the peak", () => {
    expect(yTicks(0)).toEqual([0, 1]);
    expect(yTicks(1)).toEqual([0, 1]);
    expect(yTicks(2)).toEqual([0, 1, 2]);
    expect(yTicks(7)).toEqual([0, 2, 4, 6, 8]);
    expect(yTicks(43)).toEqual([0, 20, 40, 60]);
    expect(yTicks(130)).toEqual([0, 50, 100, 150]);
  });

  it("ticks the first day of each year inside the window", () => {
    expect(yearTicks("2024-11-23", 731)).toEqual([
      { offset: 39, year: "2025" },
      { offset: 404, year: "2026" }
    ]);
    expect(yearTicks("2025-01-01", 10)).toEqual([]);
  });
});

describe("the channels set aside before a walk", () => {
  it("reads each channel's label, count and versions, and skips a row it cannot read", () => {
    expect(
      channelsSetAside([
        { channel: "esr", label: "Firefox ESR", source: "https://example.test/firefox.json", count: 2, versions: ["128.5.0", "128.5.1", 7] },
        { channel: "beta", label: 7, count: 1 },
        "not a row"
      ])
    ).toEqual([{ channel: "esr", label: "Firefox ESR", source: "https://example.test/firefox.json", count: 2, versions: ["128.5.0", "128.5.1"] }]);
    expect(channelsSetAside(undefined)).toEqual([]);
    expect(channelsSetAside({ esr: 2 })).toEqual([]);
    // A row with no count is skipped too: drawn, it would read "undefined versions" (w3 review, F10).
    expect(channelsSetAside([{ channel: "esr", label: "Firefox ESR", source: "https://example.test/firefox.json", versions: ["128.5.0"] }])).toEqual([]);
    expect(channelsSetAside([{ channel: "esr", label: "Firefox ESR", count: "2", versions: ["128.5.0", "128.5.1"] }])).toEqual([]);
  });

  it("says one version in the singular and several in the plural, in English and German", () => {
    expect(walkEnglish.channelSetAside(1, "Firefox ESR", 4)).toBe(
      "1 version of Firefox ESR set aside: LoonSec's data does not walk that channel yet, so it is neither walked nor counted as unmatched (troubleshooting.md §33 step 4)."
    );
    expect(walkEnglish.channelSetAside(2, "Firefox ESR", 5)).toContain("2 versions of Firefox ESR set aside: LoonSec's data does not walk that channel yet, so they are neither");
    // The German singular (w3 review, F8): "sie wird", not "sie werden".
    expect(walkGerman.channelSetAside(1, "Firefox ESR", 4)).toBe(
      "1 Version von Firefox ESR beiseitegelegt: Die Daten von LoonSec spielen diesen Kanal noch nicht nach; sie wird daher weder nachgespielt noch als ohne Treffer gezählt (troubleshooting.md §33 Schritt 4)."
    );
    expect(walkGerman.channelSetAside(3, "Firefox ESR", 5)).toContain("3 Versionen von Firefox ESR beiseitegelegt: Die Daten von LoonSec spielen diesen Kanal noch nicht nach; sie werden daher");
  });
});

describe("the words for how a fix was dated", () => {
  it("say which version dated a fix and when, why a line has no fix, NVD's own version, and the counts", () => {
    // The walk passes over a dated version the CVE's range still covers (2026-11-25), so the words say
    // "outside the CVE's affected range", never merely "the next version it dates".
    expect(walkEnglish.fixNextDated("2.0", "2.1", "2026-03-02")).toBe(
      "2.0: not dated by this source, so counted from 2.1, the first version at or above the fix that it dates outside the CVE's affected range, on 2026-03-02"
    );
    expect(walkEnglish.fixUndated("4.2.9", "4.2")).toBe(
      "4.2.9: this source dates no version at or above it on the 4.2 line outside the CVE's affected range, so this CVE is walked by its affected ranges there"
    );
    expect(walkEnglish.fixUndated("2.0", "")).toContain("2.0: this source dates no version at or above it on its line outside the CVE's affected range");
    expect(walkEnglish.fixNone("4.2")).toBe("No fix version on the 4.2 line in LoonSec's data, so this CVE is walked by its affected ranges there");
    expect(walkEnglish.historyBegins.fleet).toBe("Fleet's history begins here");
    // Counted over the lines a device under any stop runs, and with no "so those CVEs…" when none is undated.
    expect(walkEnglish.fixDating(5, 3, 0)).toBe(
      "Of the fixes the listed CVEs name on the lines a device under any stop runs: 5 dated by the fix itself, 3 by the first version at or above the fix that this source dates outside the CVE's affected range, 0 by none (troubleshooting.md §33 step 12)."
    );
    expect(walkEnglish.fixDating(3, 2, 1)).toContain(", 1 by none, so that CVE is walked by its affected ranges there (troubleshooting.md §33 step 12).");
    expect(walkEnglish.fixDating(3, 2, 4)).toContain(", 4 by none, so those CVEs are walked by their affected ranges there (troubleshooting.md §33 step 12).");
    // The relative clause belongs to the version, not to the CVE (wave 4b review).
    expect(walkGerman.fixNextDated("1.1", "1.2", "2026-03-02")).toBe(
      "1.1: von dieser Quelle nicht datiert, daher gezählt ab 1.2, der ersten Version an oder über dem Fix, die sie datiert und die außerhalb des betroffenen Bereichs der CVE liegt, am 2026-03-02"
    );
    expect(walkGerman.fixUndated("2.0", "")).toBe(
      "2.0: Diese Quelle datiert keine Version an oder über ihm auf seiner Linie außerhalb des betroffenen Bereichs der CVE; diese CVE wird dort nach ihren betroffenen Bereichen nachgespielt"
    );
    expect(walkGerman.fixUndated("4.2.9", "4.2")).toContain("4.2.9: Diese Quelle datiert keine Version an oder über ihm auf der Linie 4.2 außerhalb des betroffenen Bereichs der CVE;");
    expect(walkGerman.historyBegins.jamf).toBe("Hier beginnt Jamfs Historie");
    expect(walkGerman.fixDating(1, 2, 0)).toBe(
      "Von den Fixes, die die aufgeführten CVEs auf den Linien nennen, die ein Gerät unter irgendeiner Stufe ausführt: 1 durch den Fix selbst datiert, 2 durch die erste Version an oder über dem Fix, die diese Quelle datiert und die außerhalb des betroffenen Bereichs der CVE liegt, 0 durch keine (troubleshooting.md §33 Schritt 12)."
    );
    expect(walkGerman.fixDating(1, 2, 1)).toContain("1 durch keine; diese CVE wird dort nach ihren betroffenen Bereichen nachgespielt (troubleshooting.md §33 Schritt 12).");
    expect(walkGerman.fixDating(1, 2, 3)).toContain("3 durch keine; diese CVEs werden dort nach ihren betroffenen Bereichen nachgespielt (troubleshooting.md §33 Schritt 12).");
    // The line under each CVE that lists its fixes: one fix is singular.
    expect(walkEnglish.fixDatedLead("CVE-2099-0001", 1)).toBe("Fix of CVE-2099-0001, as this source dates it:");
    expect(walkEnglish.fixDatedLead("CVE-2099-0001", 2)).toBe("Fixes of CVE-2099-0001, as this source dates them:");
    expect(walkGerman.fixDatedLead("CVE-2099-0001", 1)).toBe("Fix von CVE-2099-0001, wie diese Quelle ihn datiert:");
    expect(walkGerman.fixDatedLead("CVE-2099-0001", 3)).toBe("Fixes von CVE-2099-0001, wie diese Quelle sie datiert:");
  });

  it("no longer call a fix the source does not date a reason to exclude, and say a channel_empty source names nothing of the track's alone", () => {
    expect(walkEnglish.exclusionReasons.fixed_version_not_in_timeline).toContain("No longer a reason");
    expect(walkGerman.exclusionReasons.fixed_version_not_in_timeline).toContain("Kein Grund mehr");
    // Nor is a fix the version list does not hold a reason since 2026-11-25: LoonSec's data lists it at
    // the next version at or above it, so a copy built since counts 0, and the label says so.
    expect(walkEnglish.exclusionReasons.fixed_version_not_in_catalog).toContain("No longer a reason since 2026-11-25");
    expect(walkEnglish.exclusionReasons.fixed_version_not_in_catalog).toContain("A copy built since counts 0 here");
    expect(walkGerman.exclusionReasons.fixed_version_not_in_catalog).toContain("Seit dem 2026-11-25 kein Grund mehr");
    const context = { app: "Mozilla Firefox", track: "Mozilla Firefox (release)", source: "this instance's copy of Jamf's public patch catalog", sourceId: "jamf" as const };
    expect(walkEnglish.reasons.channel_empty(context)).toContain("none of the versions it names is that track's alone");
    expect(walkEnglish.reasons.channel_empty(context)).not.toContain("every version");
    expect(walkGerman.reasons.channel_empty(context)).toContain("Keine der Versionen darin gehört allein zu diesem Track");
    expect(walkEnglish.reasons.esr_missing(context)).toContain("none of the versions in it is the ESR track's alone");
  });
});

describe("a Fleet catalog read only in part", () => {
  const context = { app: "Example Browser", track: "Example Browser (release)", source: "this instance's Fleet history", sourceId: "fleet" as const };

  it("says the title may be unread, not that Fleet holds none, and leaves the cause to the instance's words", () => {
    // The cause is one of three (a check cut short, titles it could not read, the 1.3.0 upgrade,
    // which leaves the status line without words): the instance's sentence, shown beneath, names it.
    const english = walkEnglish.reasons.catalog_partial(context);
    expect(english).toBe(
      "Fleet's catalog has been read only in part on this instance, and the part read holds no Mac title for Example Browser: it may be among the titles not read yet. The instance's words below name the cause. Choose another source until a check reads the whole catalog (troubleshooting.md §33 step 5)."
    );
    expect(english).not.toContain("status line says why");
    // not_held's conclusion is the one a partial read cannot draw.
    expect(english).not.toContain(walkEnglish.reasons.not_held(context).split(". ")[0]);
  });

  it("says the same in German", () => {
    const german = walkGerman.reasons.catalog_partial(context);
    expect(german).toContain("nur teilweise gelesen");
    expect(german).toContain("keinen Mac-Titel für Example Browser");
    expect(german).toContain("Der Wortlaut der Instanz darunter nennt die Ursache.");
    expect(german).toContain("(troubleshooting.md §33 Schritt 5).");
    expect(german).not.toContain(walkGerman.reasons.not_held(context).split(". ")[0]);
  });
});

describe("the never stop's words", () => {
  it("splits never seen by why, in the singular and the plural, and says only what there is", () => {
    expect(patchPolicyEnglish.neverStays("4.2.5", 120, 113)).toBe(
      "A device that never updates stays on 4.2.5. Of the 120 never seen, 7 were already fixed in 4.2.5, so the device never ran a version they affect. The other 113 fall outside every range NVD names: either they affect only other versions, or NVD names no range for 4.2.5's line, since NVD often stops naming a line once it reaches end of life. They do not show the device was safe (troubleshooting.md §33 step 11)."
    );
    expect(patchPolicyEnglish.neverStays("132.0.2", 2, 1)).toContain("Of the 2 never seen, 1 was already fixed in 132.0.2, so the device never ran a version it affects. The other one falls outside");
    expect(patchPolicyEnglish.neverStays("132.0.2", 2, 1)).toContain("either it affects only other versions");
    expect(patchPolicyEnglish.neverStays("132.0.2", 88, 0)).toBe(
      "A device that never updates stays on 132.0.2. All 88 never seen were already fixed in 132.0.2, so the device never ran a version they affect (troubleshooting.md §33 step 11)."
    );
    expect(patchPolicyEnglish.neverStays("4.2.5", 1, 1)).toContain("The one never seen falls outside every range NVD names");
    expect(patchPolicyEnglish.neverStays(null, 0, 0)).toBe("A device that never updates stays on the version it starts the window on (troubleshooting.md §33 step 11).");
    expect(patchPolicyEnglish.neverStays(null, 3, 3)).toContain("NVD names no range for that version's line");
    expect(patchPolicyGerman.neverStays("4.2.5", 1, 0)).toBe(
      "Ein Gerät, das nie aktualisiert, bleibt auf 4.2.5. Die eine nie gesehene war in 4.2.5 bereits behoben; auf dem Gerät lief also nie eine Version, die sie betrifft (troubleshooting.md §33 Schritt 11)."
    );
    expect(patchPolicyGerman.neverStays(null, 2, 2)).toContain("Alle 2 nie gesehenen liegen außerhalb jedes Bereichs, den NVD nennt: Entweder betreffen sie nur andere Versionen, oder NVD nennt keinen Bereich für die Linie dieser Version");
    // German, one already fixed beside others outside every range: "war 1", not "waren 1" (w4b review, F10).
    expect(patchPolicyGerman.neverStays("4.2.5", 3, 2)).toContain(
      "Von den 3 nie gesehenen war 1 in 4.2.5 bereits behoben; auf dem Gerät lief also nie eine Version, die sie betrifft. Die übrigen 2 liegen außerhalb"
    );
    // The other stops' `outside`, in German: the relative clause takes its comma (wave 4b review), and
    // a held line is named without one.
    expect(patchPolicyGerman.outside(2, 5, null)).toBe(
      "2 der 5 nie gesehenen waren nie im betroffenen Bereich: Sie betreffen nur Versionen, die dieser Mac nie ausführt, sodass ihnen hier keine Patch-Richtlinie begegnet."
    );
    expect(patchPolicyGerman.outside(1, 5, "4.4")).toBe(
      "1 der 5 nie gesehenen war nie im betroffenen Bereich: Sie betrifft nur Versionen außerhalb der Linie 4.4, sodass ihr hier keine Patch-Richtlinie begegnet."
    );
  });
});
