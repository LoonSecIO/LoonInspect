/** The patch-policy reference page as it is drawn (#614, first slice), on hand-made schema-3 replays
 *  whose numbers are invented (`testing/replayFixtures.ts`): the numbers at each of the eight stops,
 *  the release-date source and the CVE clock the page names, an app replayed as one release line, and
 *  the things the page must keep saying. Then the shipped files, which the view is not handed while
 *  they count the old way. Node lane (#285): the views are stateless enough to render to markup, and
 *  the slider's own movement is the browser's. */

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
/** The markup with tags dropped, so a sentence can be matched across the spans that style it (a date
 *  is a span of its own, so no space is left before the punctuation that follows one). */
const text = (markup: string) =>
  markup
    .replace(/<[^>]+>/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .replace(/ ([.,;:)])/g, "$1");
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
  it("at 0 days: 3 of 4 never seen, 1 exposed for 1 day, 3 update events", () => {
    const page = drawn("0d");
    expect(page).toContain("3 of 4 vulnerabilities never seen");
    expect(page).toContain("1 of the 3 never seen was never in range: it affects only versions off the 4.4 line, so no patch policy meets it here.");
    expect(page).toContain("Exposed 1 CVEs this Mac ran");
    expect(page).toContain("Exposure days 1 CVE-days");
    expect(page).toContain("Update events 3 days on which");
    expect(page).toContain("Opens the window on 4.4.1 and ends it on 4.4.4.");
    // The one CVE still seen when each release is installed on its date, as its row reads.
    expect(page).toContain("CVE-2099-0004");
    expect(page).toContain("Exposed 1 day, until 4.4.4 on 2025-03-05");
    expect(page).toContain("Never seen: the fix was installed first");
  });

  it("the headline along the whole slider is 3, 3, 2, 2, 1, 1, 1, 1", () => {
    expect(SLIDER_STOPS.map((stop) => /(\d+) of 4 vulnerabilities never seen/.exec(drawn(stop))?.[1])).toEqual(["3", "3", "2", "2", "1", "1", "1", "1"]);
  });

  it("a day later at 1 day: CVE-0004, published the day before its fix's date, is open two days", () => {
    const page = drawn("1d");
    expect(page).toContain("3 of 4 vulnerabilities never seen");
    expect(page).toContain("Exposed 2 days, until 4.4.4 on 2025-03-06");
    expect(page).toContain("Opens the window on 4.4.1 and ends it on 4.4.4.");
    expect(drawn("3d")).toContain("Exposed 2 days, until 4.4.2 on 2024-11-30");
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

  it("keeps its tables in their boxes with words whole: headings wrap at spaces, narrow columns shrink to fit", () => {
    // Every table but the two-column count floors its width (a phone scrolls it inside its box), and none
    // hyphenates: a heading wraps at its spaces, smaller than the cells ("Re-lease-Datum" read as
    // "re-lease"), and in the per-CVE and excluded lists the CVE id, the day and NVD's status shrink to
    // their widest word or date so the outcome, the fixes, the reason and the detail take the room. An
    // exclusion's detail (a machine word with no break in it) may still break anywhere.
    const markup = markupOf("7d", patchPolicyGerman);
    const tables = [...markup.matchAll(/<table class="([^"]*)"/g)].map((match) => match[1].split(" "));
    expect(tables).toHaveLength(4);
    expect(tables[0]).toContain("min-w-[38rem]");
    expect(tables[1]).toContain("min-w-[38rem]");
    expect(tables[3]).toContain("min-w-[36rem]");
    for (const table of tables) expect(table).not.toContain("hyphens-auto");
    const heads = markup.split("<table").slice(1).map((table) => [...table.matchAll(/<th class="([^"]*)"/g)].map((match) => match[1].split(" ").filter(Boolean)));
    for (const head of heads.flat()) expect(head).toEqual(expect.arrayContaining(["text-xs", "hyphens-manual"]));
    expect(heads[0].every((head) => head.includes("px-2"))).toBe(true);
    expect(heads[1].map((head) => head.includes("w-[1%]"))).toEqual([true, false, true, true, false]);
    expect(heads[3].map((head) => head.includes("w-[1%]"))).toEqual([true, true, false, true, false]);
    const exclusions = markup.split("<table").at(-1)!;
    const lastCells = [...exclusions.matchAll(/<tr[^>]*>(?:<td[^>]*>.*?<\/td>)*?<td class="([^"]*)">[^<]*<\/td><\/tr>/g)].map((match) => match[1]);
    expect(lastCells).toHaveLength(held.exclusions.cves.length);
    for (const detail of lastCells) expect(detail.split(" ")).toContain("[overflow-wrap:anywhere]");
  });

  it("keeps every date whole: in the list of updates, the outcome and the fix, in English and German", () => {
    for (const words of [patchPolicyEnglish, patchPolicyGerman]) {
      const markup = markupOf("0d", words);
      // The updates: as many columns as fit one a line, each date a span that does not wrap.
      const updates = markup.split('<ul class="')[1];
      expect(updates.startsWith("grid grid-cols-[repeat(auto-fill,minmax(12rem,1fr))]")).toBe(true);
      expect(updates.split("</ul>")[0]).toContain('4.4.2 · <span class="whitespace-nowrap">2024-11-27</span>');
      // The outcome and the fix: the date inside the sentence is its own span.
      expect(markup).toContain('<span class="whitespace-nowrap">2025-03-05</span>');
      const fix = words === patchPolicyEnglish ? "4.4.2, dated " : "4.4.2, datiert ";
      expect(markup).toContain(`${fix}<span class="whitespace-nowrap">2024-11-27</span>`);
      // No date anywhere on the page is left as text a line could break at its hyphens: each is a span,
      // or a cell, that does not wrap.
      const whole = /<(span|td) class="[^"]*whitespace-nowrap[^"]*">\d{4}-\d{2}-\d{2}<\/(span|td)>/g;
      expect(markup.replace(whole, "").match(/\d{4}-\d{2}-\d{2}/g)).toBeNull();
    }
  });

  it("names the release-date source from the file, and never 'released on'", () => {
    const page = drawn("7d");
    expect(page).toContain("Release dates: Example App's release tags.");
    // A stop's label is the days it waits after that date (ruled 2026-11-27, "0 = same day").
    expect(page).toContain("Every release is installed 7 days after the date the release-date source above gives it.");
    expect(drawn("1d")).toContain("Every release is installed 1 day after the date the release-date source above gives it.");
    expect(drawn("0d")).toContain("Every release is installed on the date the release-date source above gives it.");
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
    const page = drawn("0d");
    expect(page).toContain("A reference analysis, not this organization's exposure");
    expect(page).toContain("One hypothetical Mac that runs Example App, held on its 4.4 release line, replayed from 2024-11-23 to 2026-11-23");
    expect(page).toContain("No inventory from this instance is read");
  });

  it("says what following the newest line instead would change, under the stop shown", () => {
    expect(drawn("7d")).toContain("Following the newest release line instead, which crosses to newer lines as they ship, changes the outcome of 1 CVE under this policy.");
    expect(drawn("never")).toContain("changes the outcome of 2 CVEs under this policy.");
  });

  it("carries the evidence: window, release-date source with its link, fetch time and digest, and run id", () => {
    const markup = markupOf("0d");
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
    const markup = renderToStaticMarkup(<ReplayView replay={replay} appName="Example App" stop="0d" onStop={() => {}} copy={copy} />);
    expect(markup).not.toContain("href=");
    expect(text(markup)).toContain("javascript:alert(1)");
  });

  it("keeps the tabled policy off the slider and out of every table, and quotes none of its numbers", () => {
    for (const stop of SLIDER_STOPS) {
      const markup = markupOf(stop);
      // Eight stops and no ninth, on the slider and in the comparison table.
      expect(markup).toContain('max="7"');
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
    expect(page).toContain("Jedes Release wird 14 Tage nach dem Datum installiert, das die oben genannte Quelle der Release-Daten ihm gibt.");
    expect(drawn("1d", patchPolicyGerman)).toContain("Jedes Release wird 1 Tag nach dem Datum installiert");
    expect(drawn("0d", patchPolicyGerman)).toContain("Jedes Release wird an dem Datum installiert, das die oben genannte Quelle der Release-Daten ihm gibt.");
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
    const shown = page("0d");
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
    expect(row.outcome).toBe("Exposed 7 days, until 131.0.5 on 2024-12-17");
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

  it("counts what it replayed: 1 of 2 never seen at 0 days, none from a day on", () => {
    expect(SLIDER_STOPS.map((stop) => /(\d+) of 2 vulnerabilities never seen/.exec(page(stop))?.[1])).toEqual(["1", "0", "0", "0", "0", "0", "0", "0"]);
    expect(page("0d")).toContain("0 of the 1 never seen were never in range: they affect only versions this Mac never runs");
    // Published the day its fix is dated: exposed for exactly the days each stop waits.
    expect(page("1d")).toContain("Exposed 1 day, until 131.0.5 on 2024-12-11");
    expect(page("3d")).toContain("Exposed 3 days, until 131.0.5 on 2024-12-13");
    expect(page("60d")).toContain("Exposed 60 days, until 131.0.5 on 2025-02-08");
  });
});

describe("ReplayView and the shipped replays", () => {
  // Until LoonVD-Internal#151's schema-3 files land in replays/, every shipped file counts the old way
  // and is refused before the view is handed it (replay.test.ts holds that, and the page draws the
  // refusal), so nothing here draws one: drawn under these stops, each number would sit a day early.
  // When those files land, this block draws each of them again, with numbers read from the new files:
  // its release-date source and CVE clock in both languages, the never stop's split, Chrome's cut
  // window and waiting device, Wireshark's held line, Firefox's release channel and its several
  // ranges, Thunderbird's clearing fix, and each excluded CVE's NVD status. The old files' tests are
  // this file at 8c42d569.
  it("is handed none of them while they count the old way", async () => {
    for (const entry of REPLAY_INDEX) {
      expect(await loadReplay(entry), entry.file).toEqual({ refusal: { why: "old_count" } });
    }
  });

  it("every shipped file: each exposed CVE cleared by a fix on the held line has that fix among the line's fixes", async () => {
    // `heldFixes` is what the Fix column prints, and reads only a row's fixes, so it is held to every
    // shipped file as it stands, under the file's own rows (whose labels count the old way).
    let held = 0;
    for (const entry of REPLAY_INDEX) {
      const file = (await entry.load()) as PatchPolicyReplay;
      const line = file.branch_choice.held_at_branch;
      const rows = Object.keys(file.policies).filter((key) => key !== "critical_or_kev");
      for (const key of rows) {
        for (const row of file.ledger.filter((each) => !each.exclusion)) {
          const outcome = row.outcomes?.[key];
          const named = (row.fixes ?? []).filter((fix) => (fix.branch ?? "") === (line ?? "")).map((fix) => fix.fixed_version);
          // A device that installs past the fix is cleared by a later build (Chrome skips builds):
          // only a cleared_by that is itself a fix on the line is held here.
          if (outcome?.outcome !== "exposed" || !outcome.cleared_by || !named.includes(outcome.cleared_by)) continue;
          expect(heldFixes(row, line).map((fix) => fix.fixed_version), `${entry.id} ${key} ${row.cve_id}`).toContain(outcome.cleared_by);
          held += 1;
        }
      }
    }
    // Not vacuous: the shipped files clear thousands of CVEs by a fix's own version.
    expect(held).toBeGreaterThan(1000);
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
