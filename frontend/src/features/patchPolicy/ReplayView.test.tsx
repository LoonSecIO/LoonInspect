/** The patch-policy reference page as it is drawn (#614, first slice), on hand-made schema-2 replays
 *  whose numbers are invented (`testing/replayFixtures.ts`): the numbers at each stop, the release-date
 *  source and the CVE clock the page names, an app replayed as one release line, and the things the
 *  page must keep saying. Then every shipped file, drawn as a reader sees it. Node lane (#285): the
 *  views are stateless enough to render to markup, and the slider's own movement is the browser's. */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AppPicker } from "@/features/patchPolicy/AppPicker";
import { patchPolicyEnglish, patchPolicyGerman } from "@/features/patchPolicy/copy";
import { SLIDER_STOPS, heldFixes, readReplay, type PatchPolicyReplay, type SliderStop } from "@/features/patchPolicy/replay";
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
/** One CVE's row in the per-CVE table, as its cells read: the CVE, the outcome, published, severity,
 *  and each fix in the Fix column as its own line. */
function ledgerRow(markup: string, cve: string): { outcome: string; fixes: string[] } {
  const table = markup.split("<tbody>")[2];
  const row = table.split("<tr").find((each) => each.includes(`>${cve}</td>`));
  expect(row, `${cve} has no row in the per-CVE table`).toBeDefined();
  const cells = row!.split("<td").slice(1);
  const fixes = cells[4].split('<span class="block">').slice(1).map((each) => text(each).trim());
  return { outcome: text(`<td${cells[1]}`).trim(), fixes };
}

describe("ReplayView on an app held on one release line", () => {
  it("at 1 day: 3 of 4 never seen, 1 exposed for 1 day, 3 update events", () => {
    const page = drawn("1d");
    expect(page).toContain("3 of 4 vulnerabilities never seen");
    expect(page).toContain("1 of the 3 never seen was never in range: it affects only versions off the 4.4 line, so no patch policy meets it here.");
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

  it("never: splits the never seen by why, as the walk does, in place of 'never in range', in English and German", () => {
    // The device keeps 4.4.1, and its one never seen is outside every range NVD names: `outside` would
    // say it never affects this Mac, which is what the split warns against.
    const page = drawn("never");
    expect(page).toContain(copy.neverStays("4.4.1", 1, 1));
    expect(page).toContain(
      "A device that never updates stays on 4.4.1. The one never seen falls outside every range NVD names: either it affects only other versions, or NVD names no range for 4.4.1's line, since NVD often stops naming a line once it reaches end of life. It does not show the device was safe (troubleshooting.md §33 step 11)."
    );
    expect(page).not.toContain("never seen was never in range");
    const german = drawn("never", patchPolicyGerman);
    expect(german).toContain(patchPolicyGerman.neverStays("4.4.1", 1, 1));
    expect(german).toContain("Ein Gerät, das nie aktualisiert, bleibt auf 4.4.1. Die eine nie gesehene liegt außerhalb jedes Bereichs, den NVD nennt");
    expect(german).not.toContain("nie gesehenen war nie im betroffenen Bereich");
    // The other stops keep `outside`.
    expect(drawn("60d")).toContain("never seen was never in range");
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

  it("lets a long word fold inside its table before the table outgrows its box, as the walk's tables do", () => {
    // The every-stop and per-CVE tables floor at 38rem and hyphenate, the excluded-CVE list hyphenates,
    // and an exclusion's detail (a machine word with no break in it) may break anywhere. The
    // two-column count of each reason already fits.
    const markup = markupOf("7d", patchPolicyGerman);
    const tables = [...markup.matchAll(/<table class="([^"]*)"/g)].map((match) => match[1].split(" "));
    expect(tables).toHaveLength(4);
    expect(tables[0]).toEqual(expect.arrayContaining(["min-w-[38rem]", "hyphens-auto"]));
    expect(tables[1]).toEqual(expect.arrayContaining(["min-w-[38rem]", "hyphens-auto"]));
    expect(tables[3]).toEqual(expect.arrayContaining(["hyphens-auto"]));
    const exclusions = markup.split("<table").at(-1)!;
    const lastCells = [...exclusions.matchAll(/<tr[^>]*>(?:<td[^>]*>.*?<\/td>)*?<td class="([^"]*)">[^<]*<\/td><\/tr>/g)].map((match) => match[1]);
    expect(lastCells).toHaveLength(held.exclusions.cves.length);
    for (const detail of lastCells) expect(detail.split(" ")).toContain("[overflow-wrap:anywhere]");
  });

  it("names the release-date source from the file, and never 'released on'", () => {
    const page = drawn("7d");
    expect(page).toContain("Release dates: Example App's release tags.");
    expect(page).toContain("Every release is installed by day 7, where day one is the date the release-date source above gives the release.");
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
    expect(page).toContain("Release-Daten: Example App's release tags.");
    expect(page).toContain("Tag eins ist das Datum, das die oben genannte Quelle der Release-Daten dem Release gibt.");
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

  it("shows each CVE's fix on the one line, not 'none on this line', and no range beside a fix that is alone", () => {
    const shown = page("1d");
    expect(shown).toContain("131.0.5, dated 2024-12-10");
    expect(shown).toContain("132.0.9, dated 2025-02-04");
    expect(shown).not.toContain(copy.noFixOnLine);
    expect(shown).not.toContain("for versions");
  });

  it("shows every fix a CVE has on the one line, each with NVD's range it closes, never only the first", () => {
    const several = readReplay({
      ...singleLineReplay(),
      ledger: (singleLineReplay().ledger as Record<string, unknown>[]).map((row) =>
        row.cve_id !== "CVE-2099-1001"
          ? row
          : {
              ...row,
              fixes: [
                { branch: "", fixed_version: "116.0", release_date: "2023-08-01", affected: { kind: "range", bounds: { versionStartIncluding: "115.0", versionEndExcluding: "115.18.0" } } },
                { branch: "", fixed_version: "131.0.5", release_date: "2024-12-10", affected: { kind: "range", bounds: { versionEndExcluding: "131.0.5" } } }
              ]
            }
      )
    }).replay as PatchPolicyReplay;
    const row = ledgerRow(markupOf("7d", copy, several, "Example Browser"), "CVE-2099-1001");
    expect(row.outcome).toBe("Exposed 6 days, until 131.0.5 on 2024-12-16");
    expect(row.fixes).toEqual([
      "116.0, dated 2023-08-01, for versions from 115.0 (including) up to 115.18.0 (excluding)",
      "131.0.5, dated 2024-12-10, for versions up to 131.0.5 (excluding)"
    ]);
    expect(ledgerRow(markupOf("7d", patchPolicyGerman, several, "Example Browser"), "CVE-2099-1001").fixes[1]).toBe(
      "131.0.5, datiert 2024-12-10, für Versionen bis 131.0.5 (ausschließlich)"
    );
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

  it("says so when the promotion table is behind the timeline, unless the window already ends before that major", () => {
    const behind = readReplay({ ...singleLineReplay(), early_stable_choice: { device: "skip", promotion_table_behind_timeline: true } }).replay as PatchPolicyReplay;
    const sentence =
      "The promotion table has no row yet for the newest major version the release-date source above dates, so this Mac never installs that major here.";
    expect(drawn("7d", copy, behind, "Example Browser")).toContain(sentence);
    // Cut at the promotion table, the window ends the day before that major's first date: the missing
    // row limits nothing shown, and the shortened sentence gives the cause instead.
    const cut = readReplay({
      ...singleLineReplay(),
      window: { since: "2024-11-23", until: "2026-11-17", requested_until: "2026-11-23", shortened_by: [{ reason: "promotion_table", date: "2026-11-17", sentence: "The timeline dates a major the table has no row for." }] },
      early_stable_choice: { device: "skip", promotion_table_behind_timeline: true }
    }).replay as PatchPolicyReplay;
    for (const words of [copy, patchPolicyGerman]) {
      const page = drawn("7d", words, cut, "Example Browser");
      expect(page).not.toContain(words.promotionTableBehind);
      expect(page).toContain(words.shortened("2026-11-17", "2026-11-23"));
    }
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

  it("splits each shipped replay's never stop the way its file does, in English and German (w4b review, F7)", async () => {
    // Chrome's never device keeps 131.0.6778.86: of its 6 never seen, 5 were already fixed there and 1
    // falls outside every NVD range. Firefox's and Thunderbird's split unevenly too, so a view that
    // swapped the two counts would say so here; Wireshark's 16 of 16 cannot tell them apart.
    const loaded = async (id: string) => {
      const entry = REPLAY_INDEX.find((each) => each.id === id)!;
      const { replay } = await loadReplay(entry);
      return { replay: replay!, name: entry.name };
    };
    const chrome = await loaded("chrome");
    expect(drawn("never", copy, chrome.replay, chrome.name)).toContain(
      "A device that never updates stays on 131.0.6778.86. Of the 6 never seen, 5 were already fixed in 131.0.6778.86, so the device never ran a version they affect. The other one falls outside every range NVD names: either it affects only other versions, or NVD names no range for 131.0.6778.86's line, since NVD often stops naming a line once it reaches end of life. It does not show the device was safe (troubleshooting.md §33 step 11)."
    );
    expect(drawn("never", patchPolicyGerman, chrome.replay, chrome.name)).toContain(
      "Ein Gerät, das nie aktualisiert, bleibt auf 131.0.6778.86. Von den 6 nie gesehenen waren 5 in 131.0.6778.86 bereits behoben; auf dem Gerät lief also nie eine Version, die sie betreffen. Die übrige liegt außerhalb jedes Bereichs, den NVD nennt: Entweder betrifft sie nur andere Versionen, oder NVD nennt keinen Bereich für die Linie von 131.0.6778.86"
    );
    const firefox = await loaded("firefox");
    expect(drawn("never", copy, firefox.replay, firefox.name)).toContain(
      "A device that never updates stays on 132.0.2. Of the 17 never seen, 9 were already fixed in 132.0.2, so the device never ran a version they affect. The other 8 fall outside every range NVD names"
    );
    expect(drawn("never", patchPolicyGerman, firefox.replay, firefox.name)).toContain(
      "Von den 17 nie gesehenen waren 9 in 132.0.2 bereits behoben; auf dem Gerät lief also nie eine Version, die sie betreffen. Die übrigen 8 liegen außerhalb"
    );
    const thunderbird = await loaded("thunderbird");
    expect(drawn("never", copy, thunderbird.replay, thunderbird.name)).toContain(
      "A device that never updates stays on 132.0.1. Of the 19 never seen, 3 were already fixed in 132.0.1, so the device never ran a version they affect. The other 16 fall outside every range NVD names"
    );
    expect(drawn("never", patchPolicyGerman, thunderbird.replay, thunderbird.name)).toContain(
      "Von den 19 nie gesehenen waren 3 in 132.0.1 bereits behoben; auf dem Gerät lief also nie eine Version, die sie betreffen. Die übrigen 16 liegen außerhalb"
    );
  });

  it("Google Chrome: ends on 2026-11-17, waits for each major's promotion, and gives the window's cut, not the table, as the cause", async () => {
    const chrome = REPLAY_INDEX.find((entry) => entry.id === "chrome")!;
    const { replay } = await loadReplay(chrome);
    const page = drawn("7d", copy, replay!, chrome.name);
    expect(page).toContain("One hypothetical Mac that runs Google Chrome, replayed from 2024-11-23 to 2026-11-17");
    expect(page).toContain("This replay ends on 2026-11-17, before the 2026-11-23 it was asked to reach");
    expect(page).toContain("2024-11-23 → 2026-11-17 · asked to reach 2026-11-23");
    expect(page).toContain("Release dates: Google's Chrome VersionHistory API, platform mac, channel stable.");
    expect(page).toContain("is installed no earlier than the promotion day");
    // The file says the table is behind its timeline, and its window already ends the day before.
    expect(replay!.early_stable_choice?.promotion_table_behind_timeline).toBe(true);
    expect(page).not.toContain("The promotion table has no row yet");
    expect(page).toContain("153 of 3,415 vulnerabilities never seen");
    expect(page).not.toContain("held on");
  });

  it("Wireshark: held on 4.4, with the vendor's tag dates and the other line's choice counted", async () => {
    const wireshark = REPLAY_INDEX.find((entry) => entry.id === "wireshark")!;
    const { replay } = await loadReplay(wireshark);
    const page = drawn("14d", copy, replay!, wireshark.name);
    expect(page).toContain("One hypothetical Mac that runs Wireshark, held on its 4.4 release line, replayed from 2024-11-23 to 2026-11-23");
    expect(page).toContain("16 of 115 vulnerabilities never seen");
    expect(page).toContain("16 of the 16 never seen were never in range: they affect only versions off the 4.4 line");
    const never = replay!.policies.never;
    expect(drawn("never", copy, replay!, wireshark.name)).toContain(
      copy.neverStays(never.initial_version, never.never_seen, never.never_seen_outside_affected_range)
    );
    expect(page).toContain("Release dates: The wireshark/wireshark repository's tags on GitLab (gitlab.com/wireshark/wireshark).");
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
    expect(drawn("1d", copy, replay!, firefox.name)).toContain(
      "NVD lists only another edition (ESR) as affected: no release this channel was shipping when the CVE was published 11"
    );
    expect(drawn("1d", patchPolicyGerman, replay!, firefox.name)).toContain(
      "NVD führt nur eine andere Edition (ESR) als betroffen: kein Release, das dieser Kanal bei Veröffentlichung der CVE auslieferte 11"
    );
  });

  it("Firefox: ranges that end on ESR lines but hold the release current when NVD published are replayed", async () => {
    // CVE-2026-74934: NVD's Firefox ranges all end on ESR lines, and `141.0 ..< 153.1.0` holds
    // 153.0.4, the release current the day before NVD published it; the release fix is 154.0.
    const firefox = REPLAY_INDEX.find((entry) => entry.id === "firefox")!;
    const { replay } = await loadReplay(firefox);
    const row = ledgerRow(markupOf("7d", copy, replay!, firefox.name), "CVE-2026-74934");
    expect(row.outcome).toBe("Exposed 6 days, until 154.0 on 2026-08-24");
    expect(replay!.exclusions.cves.map((excluded) => excluded.cve_id)).not.toContain("CVE-2026-74934");
  });

  it("Firefox: a CVE NVD states several ranges for shows every fix with its range, not the oldest alone", async () => {
    const firefox = REPLAY_INDEX.find((entry) => entry.id === "firefox")!;
    const { replay } = await loadReplay(firefox);
    const row = ledgerRow(markupOf("7d", copy, replay!, firefox.name), "CVE-2026-100756");
    expect(row.outcome).toBe("Exposed 6 days, until 157.0 on 2026-10-05");
    expect(row.fixes).toEqual([
      "116.0, dated 2023-08-01, for versions from 115.0 (including) up to 115.42.0 (excluding)",
      "141.0, dated 2025-07-22, for versions from 140.0.0 (including) up to 140.17.0 (excluding)",
      "154.0, dated 2026-08-18, for versions from 153.0.0 (including) up to 153.4.0 (excluding)",
      "157.0, dated 2026-09-29, for versions from 154.0.0 (including) up to 157.0.0 (excluding)"
    ]);
  });

  it("Thunderbird: the fix that cleared a CVE is in its Fix cell", async () => {
    const thunderbird = REPLAY_INDEX.find((entry) => entry.id === "thunderbird")!;
    const { replay } = await loadReplay(thunderbird);
    const row = ledgerRow(markupOf("7d", copy, replay!, thunderbird.name), "CVE-2024-11692");
    expect(row.outcome).toBe("Exposed 6 days, until 133.0 on 2024-12-02");
    expect(row.fixes).toEqual([
      "129.0, dated 2024-08-06, for versions up to 128.5 (excluding)",
      "133.0, dated 2024-11-26, for versions from 129.0 (including) up to 133.0 (excluding)"
    ]);
  });

  it("every shipped file: each exposed CVE cleared by a fixed version lists that fix in its Fix cell, at every stop", async () => {
    let held = 0;
    for (const entry of REPLAY_INDEX) {
      const { replay } = await loadReplay(entry);
      const line = replay!.branch_choice.held_at_branch;
      for (const stop of SLIDER_STOPS) {
        for (const row of replay!.ledger.filter((each) => !each.exclusion)) {
          const outcome = row.outcomes?.[stop];
          const named = (row.fixes ?? []).filter((fix) => (fix.branch ?? "") === (line ?? "")).map((fix) => fix.fixed_version);
          // A device that installs past the fix is cleared by a later build (Chrome skips builds):
          // only a cleared_by that is itself a fix on the line is held here.
          if (outcome?.outcome !== "exposed" || !outcome.cleared_by || !named.includes(outcome.cleared_by)) continue;
          expect(heldFixes(row, line).map((fix) => fix.fixed_version), `${entry.id} ${stop} ${row.cve_id}`).toContain(outcome.cleared_by);
          held += 1;
        }
      }
    }
    // Not vacuous: the shipped files clear thousands of CVEs by a fix's own version.
    expect(held).toBeGreaterThan(1000);
  });

  it("the excluded list gives each CVE's NVD status as the file records it", async () => {
    const firefox = REPLAY_INDEX.find((entry) => entry.id === "firefox")!;
    const { replay } = await loadReplay(firefox);
    for (const words of [copy, patchPolicyGerman]) {
      const markup = markupOf("1d", words, replay!, firefox.name);
      expect(text(markup)).toContain(words.colStatus);
      const excluded = markup.split("<tbody>").at(-1)!;
      const row = excluded.split("<tr").find((each) => each.includes(">CVE-2026-109704</td>"))!;
      expect(text(row)).toContain("2026-10-13");
      expect(text(row)).toContain(`${words.reasons.no_configuration_for_pair} Deferred NVD holds no configurations for this CVE`);
    }
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
