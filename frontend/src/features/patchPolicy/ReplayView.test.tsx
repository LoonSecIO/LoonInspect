/** The patch-policy reference page as it is drawn (#614, first slice): the Wireshark numbers at each
 *  stop, and the four things the page must keep saying. Node lane (#285): the views are stateless
 *  enough to render to markup, and the slider's own movement is the browser's. */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AppPicker } from "@/features/patchPolicy/AppPicker";
import { patchPolicyEnglish, patchPolicyGerman } from "@/features/patchPolicy/copy";
import { SLIDER_STOPS, readReplay, type PatchPolicyReplay, type SliderStop } from "@/features/patchPolicy/replay";
import { ReplayView } from "@/features/patchPolicy/ReplayView";
import wireshark from "./replays/wireshark-2026-10-02.json";

const replay = readReplay(wireshark).replay as PatchPolicyReplay;
const copy = patchPolicyEnglish;
/** The markup with tags dropped, so a sentence can be matched across the spans that style it. */
const text = (markup: string) => markup.replace(/<[^>]+>/g, " ").replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/\s+/g, " ");
const drawn = (stop: SliderStop, words = copy) =>
  text(renderToStaticMarkup(<ReplayView replay={replay} appName="Wireshark" stop={stop} onStop={() => {}} copy={words} />));

describe("ReplayView on the Wireshark replay", () => {
  it("at 1 day: 100 of 101 never seen, 1 exposed for 2 days, 19 update events", () => {
    const page = drawn("1d");
    expect(page).toContain("100 of 101 vulnerabilities never seen");
    expect(page).toContain("13 of the 100 never seen were never in range");
    expect(page).toContain("Exposed 1 CVEs this Mac ran");
    expect(page).toContain("Exposure days 2 CVE-days");
    expect(page).toContain("Update events 19 days on which");
    expect(page).toContain("Opens the window on 4.4.0 and ends it on 4.4.19.");
    // The one CVE still seen under a 1-day policy, as its row reads.
    expect(page).toContain("CVE-2025-13946");
    expect(page).toContain("Exposed 2 days, until 4.4.12 on 2025-12-05");
  });

  it("at 14 days: 13 of 101 never seen, every one of them never in range, 88 exposed for 946 days", () => {
    const page = drawn("14d");
    expect(page).toContain("13 of 101 vulnerabilities never seen");
    expect(page).toContain("13 of the 13 never seen were never in range");
    expect(page).toContain("Exposed 88 CVEs this Mac ran");
    expect(page).toContain("Exposure days 946 CVE-days");
    expect(page).toContain("Update events 18 days on which");
    expect(page).toContain("Never seen: never in range");
    expect(page).not.toContain("Never seen: the fix was installed first");
  });

  it("the headline along the whole slider is 100, 39, 13, 13, 13, 13", () => {
    expect(SLIDER_STOPS.map((stop) => /(\d+) of 101 vulnerabilities never seen/.exec(drawn(stop))?.[1])).toEqual(["100", "39", "13", "13", "13", "13"]);
  });

  it("never: no update events, and all 88 exposed are still open at window end", () => {
    const page = drawn("never");
    expect(page).toContain("Update events 0 days on which");
    expect(page).toContain("Still open at window end 88 exposed");
    expect(page).toContain("Exposure days 14,287");
    expect(page).not.toContain("this Mac makes");
  });

  it("never presents the replayed count as all the CVEs, and shows the exclusions with their reasons", () => {
    const page = drawn("7d");
    expect(page).toContain("101 CVEs were replayed, of 122 published in the window. The other 21 are excluded and counted below");
    expect(page).toContain("Excluded: 21 CVEs");
    expect(page).toContain("NVD has not yet listed which versions are affected 19");
    expect(page).toContain("The affected range covers a release line whose fix it does not name 1");
    expect(page).toContain("Not about macOS 1");
    // A reason nothing was excluded for is still a row: the replay looked.
    expect(page).toContain("Rejected by the CVE program 0");
    expect(page).toContain("CVE-2026-0962");
  });

  it("says release dates are as reported by Jamf's patch catalog, and never 'released on'", () => {
    const page = drawn("7d");
    expect(page).toContain("day one is the date Jamf's patch catalog reports for the release");
    expect(page).toContain("Release dates are as reported by Jamf's patch catalog.");
    expect(page).toContain("Fix on 4.4, as reported by Jamf");
    expect(page).toContain("4.4.2, reported 2024-11-20");
    expect(page.toLowerCase()).not.toContain("released on");
    expect(text(renderToStaticMarkup(<ReplayView replay={replay} appName="Wireshark" stop="7d" onStop={() => {}} copy={patchPolicyGerman} />)).toLowerCase()).not.toContain("veröffentlicht am");
  });

  it("is labelled a reference analysis of the Wireshark 4.4 title, not this organization's exposure", () => {
    const page = drawn("1d");
    expect(page).toContain("A reference analysis, not this organization's exposure");
    expect(page).toContain('follows Jamf\'s "Wireshark 4.4" patch title, replayed from 2024-10-02 to 2026-10-02');
    expect(page).toContain("No inventory from this instance is read");
  });

  it("carries the evidence line: window, catalog snapshot date, run id", () => {
    const page = drawn("1d");
    expect(page).toContain("2024-10-02 → 2026-10-02");
    expect(page).toContain("fetched 2026-10-02 07:45 UTC");
    expect(page).toContain("d6d412eb4ace1c38924212e8883ece963de413d12c8f28adbec23fad9fdc6aad");
    expect(page).toContain("8e578b5804537684112659c2bcc38695ce6e8db412851f147d194d216001fe4c");
  });

  it("keeps the tabled policy off the slider and out of every table, and quotes none of its numbers", () => {
    for (const stop of SLIDER_STOPS) {
      const markup = renderToStaticMarkup(<ReplayView replay={replay} appName="Wireshark" stop={stop} onStop={() => {}} copy={copy} />);
      // Six stops and no seventh, on the slider and in the comparison table.
      expect(markup).toContain('max="5"');
      for (const label of Object.values(copy.stops)) expect(markup).toContain(`>${label}</button>`);
      expect(markup.split("<tbody>")[1].split("</tbody>")[0].split("<tr").length - 1).toBe(SLIDER_STOPS.length);
      const page = text(markup);
      // Its definition is shown apart, in the file's own words, which say it is tabled.
      expect(page).toContain("Not on the slider");
      expect(page).toContain("TABLED 2026-10-02, not ruled: do not quote this row.");
      // Its exposure days appear nowhere; its 38 and 63 are too common on the page to search for.
      expect(page).not.toContain("10,415");
      expect(markup).not.toContain(">critical_or_kev</dt>");
    }
  });

  it("reads in German from the same file", () => {
    const page = drawn("14d", patchPolicyGerman);
    expect(page).toContain("13 von 101 Schwachstellen nie gesehen");
    expect(page).toContain("Eine Referenzanalyse, nicht die Exposition dieser Organisation");
    expect(page).toContain("wie von Jamf gemeldet");
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
