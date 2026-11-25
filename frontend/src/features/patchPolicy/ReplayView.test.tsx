/** The patch-policy reference page as it is drawn (#614, first slice), on hand-made schema-2 replays
 *  whose numbers are invented (`testing/replayFixtures.ts`): the numbers at each stop, the release-date
 *  source and the CVE clock the page names, an app replayed as one release line, and the things the
 *  page must keep saying. Then every shipped file, drawn as a reader sees it. Node lane (#285): the
 *  views are stateless enough to render to markup, and the slider's own movement is the browser's. */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AppPicker } from "@/features/patchPolicy/AppPicker";
import { patchPolicyEnglish, patchPolicyGerman } from "@/features/patchPolicy/copy";
import { SLIDER_STOPS, readReplay, type PatchPolicyReplay, type SliderStop } from "@/features/patchPolicy/replay";
import { REPLAY_INDEX, loadReplay } from "@/features/patchPolicy/replayIndex";
import { ReplayView } from "@/features/patchPolicy/ReplayView";
import { heldLineReplay, singleLineReplay } from "@/features/patchPolicy/testing/replayFixtures";

const held = readReplay(heldLineReplay()).replay as PatchPolicyReplay;
const single = readReplay(singleLineReplay()).replay as PatchPolicyReplay;
const copy = patchPolicyEnglish;
/** The markup with tags dropped, so a sentence can be matched across the spans that style it. */
const text = (markup: string) =>
  markup.replace(/<[^>]+>/g, " ").replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, "&").replace(/\s+/g, " ");
const markupOf = (stop: SliderStop, words = copy, replay = held, appName = "Example App") =>
  renderToStaticMarkup(<ReplayView replay={replay} appName={appName} stop={stop} onStop={() => {}} copy={words} />);
const drawn = (stop: SliderStop, words = copy, replay = held, appName = "Example App") => text(markupOf(stop, words, replay, appName));

describe("ReplayView on an app held on one release line", () => {
  it("at 1 day: 3 of 4 never seen, 1 exposed for 1 day, 3 update events", () => {
    const page = drawn("1d");
    expect(page).toContain("3 of 4 vulnerabilities never seen");
    expect(page).toContain("1 of the 3 never seen were never in range: they affect only versions off the 4.4 line");
    expect(page).toContain("Exposed 1 CVEs this Mac ran");
    expect(page).toContain("Exposure days 1 CVE-days");
    expect(page).toContain("Update events 3 days on which");
    expect(page).toContain("Opens the window on 4.4.1 and ends it on 4.4.4.");
    // The one CVE still seen under a 1-day policy, as its row reads.
    expect(page).toContain("CVE-2099-0004");
    expect(page).toContain("Exposed 1 day, until 4.4.4 on 2025-03-05");
    expect(page).toContain("Never seen: the fix was installed first");
  });

  it("the headline along the whole slider is 3, 2, 1, 1, 1, 1", () => {
    expect(SLIDER_STOPS.map((stop) => /(\d+) of 4 vulnerabilities never seen/.exec(drawn(stop))?.[1])).toEqual(["3", "2", "1", "1", "1", "1"]);
  });

  it("never: no update events, and all 3 exposed are still open at window end", () => {
    const page = drawn("never");
    expect(page).toContain("Update events 0 days on which");
    expect(page).toContain("Still open at window end 3 exposed");
    expect(page).toContain("Exposure days 2,031");
    expect(page).toContain("Exposed 725 days, still open at window end");
    expect(page).not.toContain("this Mac makes");
  });

  it("never presents the replayed count as all the CVEs, and shows the exclusions with their reasons", () => {
    const page = drawn("7d");
    expect(page).toContain("4 CVEs were replayed, of 5 published in the window. The other 1 are excluded and counted below");
    expect(page).toContain("Excluded: 1 CVE");
    expect(page).toContain("NVD has not yet listed which versions are affected 1");
    // A reason nothing was excluded for is still a row: the replay looked.
    expect(page).toContain("Rejected by the CVE program 0");
    expect(page).toContain("The fixed version is not a release on this replay's release timeline 0");
    expect(page).toContain("CVE-2099-0005");
  });

  it("names the release-date source from the file, and never 'released on'", () => {
    const page = drawn("7d");
    expect(page).toContain("Release dates come from Example App's release tags.");
    expect(page).toContain("day one is the release's date in Example App's release tags.");
    expect(page).toContain("Fix on 4.4, with its release date");
    expect(page).toContain("4.4.2, dated 2024-11-27");
    expect(page).toContain("The UTC date of the release's tag. Release-candidate tags are dropped.");
    expect(page).toContain("Every release date on this page is a date from that timeline, and the page computes none.");
    expect(page.toLowerCase()).not.toContain("released on");
    expect(drawn("7d", patchPolicyGerman).toLowerCase()).not.toContain("veröffentlicht am");
  });

  it("states its CVE clock: NVD's publication date, with the file's own words for it", () => {
    const page = drawn("7d");
    expect(page).toContain("The CVE clock is NVD's publication date: each CVE counts from the day NVD published it.");
    expect(page).toContain("CVE clock NVD publication date NVD `published`, truncated to the UTC date.");
  });

  it("names no source the file does not: neither Jamf nor Fleet, in either language", () => {
    // Fleet the product, capitalised; "this fleet" is the organization's Macs and stays.
    for (const replay of [held, single]) {
      for (const stop of SLIDER_STOPS) {
        for (const words of [copy, patchPolicyGerman]) {
          const page = drawn(stop, words, replay);
          expect(page).not.toMatch(/jamf/i);
          expect(page).not.toMatch(/\bFleet\b/);
        }
      }
    }
  });

  it("is labelled a reference analysis of a Mac held on the 4.4 line, not this organization's exposure", () => {
    const page = drawn("1d");
    expect(page).toContain("A reference analysis, not this organization's exposure");
    expect(page).toContain("One hypothetical Mac that runs Example App, held on its 4.4 release line, replayed from 2024-11-23 to 2026-11-23");
    expect(page).toContain("No inventory from this instance is read");
  });

  it("says what following the newest line instead would change, under the stop shown", () => {
    expect(drawn("7d")).toContain("Following the newest release line instead, which crosses to newer lines as they ship, changes the outcome of 1 CVE under this policy.");
    expect(drawn("never")).toContain("changes the outcome of 2 CVEs under this policy.");
  });

  it("carries the evidence: window, release-date source with its link, fetch time and digest, and run id", () => {
    const markup = markupOf("1d");
    const page = text(markup);
    expect(page).toContain("2024-11-23 → 2026-11-23");
    expect(markup).toContain('href="https://example.com/example-app/tags"');
    expect(markup).toContain('rel="noreferrer noopener"');
    expect(page).toContain("Example App's release tags · fetched 2026-11-24 09:15 UTC");
    expect(page).toContain("1111111111111111111111111111111111111111111111111111111111111111");
    expect(page).toContain("fixture-held-line");
  });

  it("prints an address that is not https as text, never as a link", () => {
    const replay = readReplay({ ...heldLineReplay(), timeline: { ...(heldLineReplay().timeline as object), url: "javascript:alert(1)" } }).replay as PatchPolicyReplay;
    const markup = renderToStaticMarkup(<ReplayView replay={replay} appName="Example App" stop="1d" onStop={() => {}} copy={copy} />);
    expect(markup).not.toContain("href=");
    expect(text(markup)).toContain("javascript:alert(1)");
  });

  it("keeps the tabled policy off the slider and out of every table, and quotes none of its numbers", () => {
    for (const stop of SLIDER_STOPS) {
      const markup = markupOf(stop);
      // Six stops and no seventh, on the slider and in the comparison table.
      expect(markup).toContain('max="5"');
      for (const label of Object.values(copy.stops)) expect(markup).toContain(`>${label}</button>`);
      expect(markup.split("<tbody>")[1].split("</tbody>")[0].split("<tr").length - 1).toBe(SLIDER_STOPS.length);
      const page = text(markup);
      // Its definition is shown apart, in the file's own words, which say it is tabled.
      expect(page).toContain("Not on the slider");
      expect(page).toContain("TABLED 2026-10-02, not ruled: do not quote this row.");
      // Its exposure days appear nowhere.
      expect(page).not.toContain("147");
      expect(markup).not.toContain(">critical_or_kev</dt>");
    }
  });

  it("reads in German from the same file", () => {
    const page = drawn("14d", patchPolicyGerman);
    expect(page).toContain("1 von 4 Schwachstellen nie gesehen");
    expect(page).toContain("Eine Referenzanalyse, nicht die Exposition dieser Organisation");
    expect(page).toContain("Ein hypothetischer Mac, auf dem Example App läuft, gehalten auf der Release-Linie 4.4,");
    expect(page).toContain("Die Release-Daten stammen aus Example App's release tags.");
    expect(page).toContain("Die CVE-Uhr ist das Veröffentlichungsdatum bei NVD");
    expect(page).toContain("Fix auf 4.4, mit seinem Release-Datum");
    expect(page).toContain("4.4.2, datiert 2024-11-27");
    expect(page).toContain("Folgt der Mac stattdessen der neuesten Release-Linie");
  });
});

describe("ReplayView on an app replayed as one release line", () => {
  const page = (stop: SliderStop = "7d", words = copy) => drawn(stop, words, single, "Example Browser");

  it("names no line: the Mac runs the app, and the fix column has no line in its heading", () => {
    expect(page()).toContain("One hypothetical Mac that runs Example Browser, replayed from 2024-11-23 to 2026-11-23");
    expect(page()).not.toContain("held on");
    expect(page()).toContain("Fix, with its release date");
    expect(page("7d", patchPolicyGerman)).toContain("Ein hypothetischer Mac, auf dem Example Browser läuft, nachgespielt");
  });

  it("shows each CVE's fix on the one line, not 'none on this line'", () => {
    const shown = page("1d");
    expect(shown).toContain("131.0.5, dated 2024-12-10");
    expect(shown).toContain("132.0.9, dated 2025-02-04");
    expect(shown).not.toContain(copy.noFixOnLine);
  });

  it("hides the sentence about choosing another release line, at every stop", () => {
    for (const stop of SLIDER_STOPS) {
      expect(page(stop)).not.toContain("Following the newest release line instead");
      expect(page(stop, patchPolicyGerman)).not.toContain("neuesten Release-Linie");
    }
  });

  it("says its device waits for a major's promotion day, and not under Never", () => {
    expect(page("7d")).toContain("A build served before its major version is promoted to stable is installed no earlier than the promotion day");
    expect(page("never")).not.toContain("promoted to stable");
    expect(page("7d")).not.toContain("The promotion table has no row yet");
  });

  it("says so when the promotion table is behind the timeline", () => {
    const behind = readReplay({ ...singleLineReplay(), early_stable_choice: { device: "skip", promotion_table_behind_timeline: true } }).replay as PatchPolicyReplay;
    expect(drawn("7d", copy, behind, "Example Browser")).toContain(
      "The promotion table has no row yet for the newest major version in Example Browser's version history (stable channel), so this Mac never installs that major here."
    );
  });

  it("counts what it replayed: 1 of 2 never seen at a day, none from a week on", () => {
    expect(SLIDER_STOPS.map((stop) => /(\d+) of 2 vulnerabilities never seen/.exec(page(stop))?.[1])).toEqual(["1", "0", "0", "0", "0", "0"]);
    expect(page("1d")).toContain("0 of the 1 never seen were never in range: they affect only versions this Mac never runs");
  });
});

describe("ReplayView on every shipped replay", () => {
  for (const entry of REPLAY_INDEX) {
    it(`${entry.name}: names its release-date source and its CVE clock from the file, in both languages, and neither Jamf nor Fleet`, async () => {
      const { replay } = await loadReplay(entry);
      expect(replay, entry.file).toBeDefined();
      const { timeline } = replay!;
      const cut = replay!.window.shortened_by ?? [];
      for (const words of [copy, patchPolicyGerman]) {
        for (const stop of ["1d", "never"] as const) {
          const markup = markupOf(stop, words, replay!, entry.name);
          const page = text(markup);
          const policy = replay!.policies[stop];
          expect(page).toContain(`${words.num(policy.never_seen)} ${words.of} ${words.num(replay!.counts.cves_replayed)} ${words.neverSeenLabel}`);
          // The source, by the file's own name for it, in the box at the top and under Evidence, linked.
          expect(page).toContain(words.sources(timeline.name));
          expect(markup).toContain(`href="${timeline.url!.replace(/&/g, "&amp;")}"`);
          expect(page).toContain(timeline.clock);
          expect(page).toContain(`${words.evidenceClock} ${words.cveClock} ${replay!.clocks.published}`);
          // Mozilla's tables are the release channel; the picker can fold ESR titles under the row.
          expect(page.includes(words.releaseChannelOnly(entry.name))).toBe(timeline.edition === "release");
          // A window the file cut short says so, and gives the file's reason under Evidence.
          expect(page.includes(words.shortened(replay!.window.until, replay!.window.requested_until ?? null))).toBe(cut.length > 0);
          for (const each of cut) expect(page).toContain(each.sentence);
          expect(page).not.toMatch(/jamf/i);
          expect(page).not.toMatch(/\bFleet\b/);
        }
      }
    });
  }

  it("Google Chrome: ends on 2026-11-17, waits for each major's promotion, and says the promotion table is behind", async () => {
    const chrome = REPLAY_INDEX.find((entry) => entry.id === "chrome")!;
    const { replay } = await loadReplay(chrome);
    const page = drawn("7d", copy, replay!, chrome.name);
    expect(page).toContain("One hypothetical Mac that runs Google Chrome, replayed from 2024-11-23 to 2026-11-17");
    expect(page).toContain("This replay ends on 2026-11-17, before the 2026-11-23 it was asked to reach");
    expect(page).toContain("2024-11-23 → 2026-11-17 · asked to reach 2026-11-23");
    expect(page).toContain("Release dates come from Google's Chrome VersionHistory API, platform mac, channel stable.");
    expect(page).toContain("is installed no earlier than the promotion day");
    expect(page).toContain("The promotion table has no row yet for the newest major version in Google's Chrome VersionHistory API");
    expect(page).toContain("149 of 3,415 vulnerabilities never seen");
    expect(page).not.toContain("held on");
  });

  it("Wireshark: held on 4.4, with the vendor's tag dates and the other line's choice counted", async () => {
    const wireshark = REPLAY_INDEX.find((entry) => entry.id === "wireshark")!;
    const { replay } = await loadReplay(wireshark);
    const page = drawn("14d", copy, replay!, wireshark.name);
    expect(page).toContain("One hypothetical Mac that runs Wireshark, held on its 4.4 release line, replayed from 2024-11-23 to 2026-11-23");
    expect(page).toContain("16 of 115 vulnerabilities never seen");
    expect(page).toContain("16 of the 16 never seen were never in range: they affect only versions off the 4.4 line");
    expect(page).toContain("Release dates come from The wireshark/wireshark repository's tags on GitLab (gitlab.com/wireshark/wireshark).");
    expect(page).toContain("Fix on 4.4, with its release date");
    expect(page).toContain("Following the newest release line instead");
    expect(page).not.toContain("promoted to stable");
  });

  it("Firefox: the release channel, with ESR named as not replayed yet, in German too", async () => {
    const firefox = REPLAY_INDEX.find((entry) => entry.id === "firefox")!;
    const { replay } = await loadReplay(firefox);
    expect(drawn("1d", copy, replay!, firefox.name)).toContain(
      "This replays Firefox's release channel. Firefox ESR is not replayed yet, though the app list may show it under this row, because the two share a bundle ID."
    );
    expect(drawn("1d", patchPolicyGerman, replay!, firefox.name)).toContain("Firefox ESR wird noch nicht nachgespielt");
    expect(drawn("1d", copy, replay!, firefox.name)).toContain("NVD lists only another edition (ESR) as affected, not this release channel 50");
  });
});

describe("AppPicker", () => {
  const apps = [
    { key: "wireshark", name: "Wireshark", replayId: "wireshark" },
    { key: "com.google.chrome", name: "Google Chrome", replayId: null }
  ];
  const markup = renderToStaticMarkup(<AppPicker apps={apps} selected="wireshark" onSelect={() => {}} copy={copy} />);

  it("offers only the app with a replay, and marks it selected", () => {
    expect(markup.split("<button").length - 1).toBe(1);
    expect(markup).toContain('aria-pressed="true"');
    expect(text(markup)).toContain("Wireshark Reference replay");
  });

  it("lists an app without one as 'no reference replay yet', never as a count", () => {
    expect(markup).toContain('aria-disabled="true"');
    expect(text(markup)).toContain("Google Chrome No reference replay yet");
    expect(text(markup)).not.toMatch(/Google Chrome\s+0/);
  });
});
