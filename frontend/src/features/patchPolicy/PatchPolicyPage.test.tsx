// @vitest-environment jsdom
/** Posture › Patch policy after its reads land (#614): which mode the page draws, what the source
 *  toggle offers and refuses, what the slider and the pager ask for, and every way a walk can fail
 *  to be shown, in English and German. The reads are stubbed (`/apps`, the walk, Jamf's catalog);
 *  the replays the fallback draws are the files that ship with the build. */

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { PatchPolicyPage } from "@/features/patchPolicy/PatchPolicyPage";
import { CHECK_DETAIL, FLAG_OFF_SENTENCE, NO_TITLE_SENTENCE, appFixture, appsFixture, openApp, walkFixture } from "@/features/patchPolicy/testing/walkFixtures";
import type { PatchPolicyWalk, WalkAnswer, WalkSource } from "@/features/patchPolicy/walk";
import { patchPolicyEnglish, patchPolicyGerman } from "@/features/patchPolicy/copy";
import { walkEnglish, walkGerman } from "@/features/patchPolicy/walkCopy";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const locale = vi.hoisted(() => ({ current: "en" as "en" | "de" }));
vi.mock("@/i18n/LocaleContext", async () => {
  const { en: english } = await import("@/i18n/en");
  const { de: german } = await import("@/i18n/de");
  return { useLocale: () => ({ t: locale.current === "de" ? german : english, locale: locale.current }) };
});
const feedApi = vi.hoisted(() => ({ getPatchPolicyApps: vi.fn() }));
vi.mock("@/features/support/patchPolicyFeed", async (actual) => ({ ...(await actual<object>()), ...feedApi }));
const walkApi = vi.hoisted(() => ({ getPatchPolicyWalk: vi.fn() }));
vi.mock("@/features/patchPolicy/walk", async (actual) => ({ ...(await actual<object>()), ...walkApi }));
const jamfApi = vi.hoisted(() => ({ listJamfPatchTitles: vi.fn() }));
vi.mock("@/features/jamfPatch/api", () => jamfApi);

function Address() {
  return <output data-testid="address">{useLocation().search}</output>;
}

async function open(search = "") {
  render(
    <MemoryRouter initialEntries={[`/posture/patch-policy${search}`]}>
      <Routes>
        <Route path="/posture/patch-policy" element={<><PatchPolicyPage /><Address /></>} />
      </Routes>
    </MemoryRouter>
  );
  await settle();
}
/** Lets every stubbed read, and the dynamic import of a replay file, land. */
async function settle() {
  for (let round = 0; round < 6; round += 1) await act(async () => { await new Promise((done) => setTimeout(done, 0)); });
}
/** The page's words with every tag a space, so a sentence matches across the spans that style it. */
const text = () =>
  document.body.innerHTML
    .replace(/<[^>]+>/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&gt;/g, ">")
    .replace(/&lt;/g, "<")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .replace(/ ([.,;:)])/g, "$1");
const address = () => new URLSearchParams(screen.getByTestId("address").textContent ?? "");
const asked = () => walkApi.getPatchPolicyWalk.mock.calls.map(([query]) => new URLSearchParams(query as string));
const button = (name: string | RegExp) => screen.getByRole("button", { name });

beforeEach(() => {
  locale.current = "en";
  jamfApi.listJamfPatchTitles.mockResolvedValue({ items: [{ name: "Example", bundleId: "com.example.app" }, { name: "Other App", bundleId: "com.example.other" }] });
  feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture());
  walkApi.getPatchPolicyWalk.mockResolvedValue({ walk: walkFixture() } satisfies WalkAnswer);
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("without LoonSec's data, the page falls back to the reference replays", () => {
  it("says the data has not arrived, in the feed's own sentence, and draws the build's replay", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture(null, { state: "never", docId: null, asOf: null }));
    await open();
    expect(text()).toContain(walkEnglish.fallback(en.support.patchPolicyFeed.states.never));
    // The replay the build ships, drawn by the replay view: its reference box and its source line.
    // The file is a chunk of its own, so it lands when it lands.
    await waitFor(() => expect(text()).toContain("A reference analysis, not this organization's exposure"), { timeout: 5000 });
    expect(text()).toContain("Release dates: The wireshark/wireshark repository's tags on GitLab");
    expect(walkApi.getPatchPolicyWalk).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /Public/ })).toBeNull();
  });

  it("says this organization shares no data, when that is why", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture(null, { state: "tier_off", docId: null, asOf: null }));
    await open();
    expect(text()).toContain(walkEnglish.fallback(en.support.patchPolicyFeed.states.tier_off));
  });

  it("says a failed read of the data's state is a failed read, not missing data, and still draws a replay", async () => {
    feedApi.getPatchPolicyApps.mockRejectedValue(new ApiError(500, null));
    await open();
    expect(text()).toContain(walkEnglish.appsFailed(500));
    await waitFor(() => expect(text()).toContain("A reference analysis, not this organization's exposure"), { timeout: 5000 });
    feedApi.getPatchPolicyApps.mockRejectedValue(new TypeError("Failed to fetch"));
    cleanup();
    await open();
    expect(text()).toContain("(no answer)");
  });

  it("says a failed Jamf catalog leaves only the replays listed", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture(null, { state: "never", docId: null, asOf: null }));
    jamfApi.listJamfPatchTitles.mockRejectedValue(new ApiError(500, null));
    await open();
    expect(text()).toContain(en.patchPolicy.catalogFailed);
    expect(text()).not.toContain(walkEnglish.catalogFailed);
    await waitFor(() => expect(text()).toContain("A reference analysis, not this organization's exposure"), { timeout: 5000 });
  });

  it("says it is reading before either answer lands", async () => {
    feedApi.getPatchPolicyApps.mockReturnValue(new Promise(() => {}));
    await open();
    expect(text()).toContain(walkEnglish.appsLoading);
    expect(text()).not.toContain("A reference analysis");
  });
});

describe("with LoonSec's data, the page walks it", () => {
  it("opens on the first app's default track, over Public, for two years, at 1 day", async () => {
    await open();
    expect(asked()).toHaveLength(1);
    expect(Object.fromEntries(asked()[0])).toEqual({ app: "example", track: "example/4.4", source: "public", years: "2" });
    expect(button(/^Public/).getAttribute("aria-pressed")).toBe("true");
    expect(text()).toContain("One hypothetical Mac that runs Example 4.4, held on its 4.4 line, walked day by day from 2025-01-01 to 2025-01-10");
    expect(text()).toContain("Release dates: Example release tags (fixture).");
    expect(text()).toContain(walkEnglish.clockLine);
    expect(text()).toContain("2 of 3 vulnerabilities never seen");
    expect(text()).toContain("Open CVEs per day, at 1 day");
  });

  it("lists the data's apps first, and every other catalog app as no reference yet", async () => {
    await open();
    expect(button(/Example\s*In LoonSec's data/)).toBeTruthy();
    expect(text()).toContain("Other App");
    expect(text()).toContain(walkEnglish.appNoReference);
  });

  it("draws an unavailable source disabled, with its sentence and the instance's words for a report", async () => {
    await open();
    expect((button(/^Jamf/) as HTMLButtonElement).disabled).toBe(true);
    expect((button(/^Fleet/) as HTMLButtonElement).disabled).toBe(true);
    expect(text()).toContain(`Jamf: ${walkEnglish.reasons.no_title({ app: "Example", track: "Example 4.4", source: "", sourceId: "jamf" })}`);
    expect(text()).toContain(walkEnglish.serverSaid(NO_TITLE_SENTENCE));
    // The Fleet flag's sentence is the instance's own, word for word, so it is printed once.
    expect(text()).toContain(`Fleet: ${FLAG_OFF_SENTENCE}`);
    expect(text()).not.toContain(walkEnglish.serverSaid(FLAG_OFF_SENTENCE));
  });

  it("asks for the Jamf walk when Jamf is picked, and says its dates are read on this instance", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    walkApi.getPatchPolicyWalk.mockImplementation((query: string) =>
      Promise.resolve({ walk: walkFixture({ source: new URLSearchParams(query).get("source") as "public" | "jamf" | "fleet" }) })
    );
    await open();
    fireEvent.click(button(/^Jamf/));
    await settle();
    expect(address().get("source")).toBe("jamf");
    expect(asked().at(-1)?.get("source")).toBe("jamf");
    expect(text()).toContain("Release dates: this instance's copy of Jamf's public patch catalog (Example, Example 4.4).");
    expect(text()).toContain(walkEnglish.readHere);
    fireEvent.click(button(/^Fleet/));
    await settle();
    expect(text()).toContain(walkEnglish.fleetNote);
    expect(text()).toContain("These are Fleet's dates, not the vendor's (fixture note).");
  });

  it("moves along the slider without asking again", async () => {
    await open();
    fireEvent.click(screen.getAllByRole("button", { name: "30 days" })[0]);
    await settle();
    expect(address().get("policy")).toBe("30d");
    expect(text()).toContain("1 of 3 vulnerabilities never seen");
    expect(text()).toContain("Open CVEs per day, at 30 days");
    expect(asked()).toHaveLength(1);
  });

  it("asks for the next page of CVEs, and starts again at the first when the window changes", async () => {
    walkApi.getPatchPolicyWalk.mockImplementation((query: string) => {
      const page = Number(new URLSearchParams(query).get("page") ?? 1);
      return Promise.resolve({ walk: walkFixture({ cves_page: { page, page_size: 200, pages: 3, total: 450 } }) });
    });
    await open();
    expect(text()).toContain("Page 1 of 3 · 450 CVEs");
    fireEvent.click(screen.getAllByRole("button", { name: "Next" })[0]);
    await settle();
    expect(address().get("page")).toBe("2");
    expect(asked().at(-1)?.get("page")).toBe("2");
    expect(text()).toContain("Page 2 of 3 · 450 CVEs");
    fireEvent.click(button("3 years"));
    await settle();
    expect(address().get("page")).toBeNull();
    expect(asked().at(-1)?.get("years")).toBe("3");
    expect(asked().at(-1)?.get("page")).toBeNull();
  });

  it("asks for an aligned window, and names the source left out with its reason", async () => {
    walkApi.getPatchPolicyWalk.mockResolvedValue({
      walk: walkFixture({
        window: {
          requested: { years: 2, since: "2023-01-10", until: "2025-01-10" },
          since: "2025-01-01",
          until: "2025-01-10",
          days: 10,
          shortened_by: [{ reason: "common_window", date: "2025-01-01", sentence: "The view is aligned to the days every compared timeline covers." }],
          aligned: { sources: ["public"], since: "2025-01-01", until: "2025-01-10", left_out: [{ source: "fleet", reason: "flag_off", sentence: FLAG_OFF_SENTENCE }] }
        }
      })
    });
    await open();
    fireEvent.click(screen.getByRole("checkbox"));
    await settle();
    expect(address().get("align")).toBe("common");
    expect(asked().at(-1)?.get("align")).toBe("common");
    expect(text()).toContain("You asked for 2 years; this view covers 2025-01-01 to 2025-01-10 because it is aligned to the days every compared source covers.");
    expect(text()).toContain(`Fleet is left out: ${FLAG_OFF_SENTENCE}`);
  });

  it("names each cut of a shortened window in the reader's words, and the instance's under Evidence", async () => {
    const sentence = "Example 4.4 begins with 4.4.0 on 2024-08-28, and the 60-day stop needs 59 days of it.";
    walkApi.getPatchPolicyWalk.mockResolvedValue({
      walk: walkFixture({
        window: { requested: { years: 3, since: "2022-01-10", until: "2025-01-10" }, since: "2025-01-01", until: "2025-01-10", days: 10, shortened_by: [{ reason: "line_start", date: "2025-01-01", sentence }] }
      })
    });
    await open("?years=3");
    expect(text()).toContain("You asked for 3 years; this view covers 2025-01-01 to 2025-01-10 because the held line begins later");
    expect(text()).toContain(sentence);
  });

  it("says a reason that cuts both ends of the window once, and the instance's sentence for it once, marked as the instance's", async () => {
    const sentence = "The view is aligned to the days every compared timeline covers.";
    walkApi.getPatchPolicyWalk.mockResolvedValue({
      walk: walkFixture({
        window: {
          requested: { years: 2, since: "2023-01-10", until: "2025-01-10" },
          since: "2025-01-01",
          until: "2025-01-09",
          days: 9,
          // align=common cuts the start and the end for one reason, with one sentence each time.
          shortened_by: [
            { reason: "common_window", date: "2025-01-01", sentence },
            { reason: "common_window", date: "2025-01-09", sentence }
          ],
          aligned: { sources: ["public"], since: "2025-01-01", until: "2025-01-09", left_out: [] }
        }
      })
    });
    await open("?align=common");
    expect(text()).toContain("this view covers 2025-01-01 to 2025-01-09 because it is aligned to the days every compared source covers.");
    expect(text().split(walkEnglish.windowReasons.common_window)).toHaveLength(2);
    expect(text()).toContain(walkEnglish.serverSaid(sentence));
    expect(text().split(sentence)).toHaveLength(2);
    cleanup();
    locale.current = "de";
    await open("?align=common");
    expect(text().split(walkGerman.windowReasons.common_window)).toHaveLength(2);
    // The instance's English sentence is marked as the instance's, as a refusal's is.
    expect(text()).toContain(walkGerman.serverSaid(sentence));
    expect(text().split(sentence)).toHaveLength(2);
  });

  it("marks every sentence Evidence prints from the instance as the instance's, in English and German", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk: walkFixture({ source: "fleet" }) } satisfies WalkAnswer);
    await open("?source=fleet");
    expect(text()).toContain(walkEnglish.serverSaid("These are Fleet's dates, not the vendor's (fixture note)."));
    expect(text()).toContain(walkEnglish.serverSaid(CHECK_DETAIL));
    cleanup();
    locale.current = "de";
    await open("?source=fleet");
    expect(text()).toContain(walkGerman.serverSaid("These are Fleet's dates, not the vendor's (fixture note)."));
    expect(text()).toContain(walkGerman.serverSaid(CHECK_DETAIL));
  });

  it("keeps both of two choices made before the page draws again", async () => {
    // E2E wave 4: an app, then a source, clicked quickly left the old app with the new source.
    // useSearchParams hands an updater the address of the last render; the page builds on its own.
    const other = { ...openApp(), app: "other", name: "Other App", bundleIds: ["com.example.other"] };
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp(), other]));
    await open();
    expect(address().get("app")).toBeNull();
    act(() => {
      button(/Other App\s*In LoonSec's data/).click();
      button(/^Fleet/).click();
    });
    await settle();
    expect(address().get("app")).toBe("other");
    expect(address().get("source")).toBe("fleet");
    expect(asked().at(-1)?.get("app")).toBe("other");
    expect(asked().at(-1)?.get("source")).toBe("fleet");
    // And the next choice builds on both.
    fireEvent.click(button("3 years"));
    await settle();
    expect(Object.fromEntries(address())).toEqual({ app: "other", source: "fleet", years: "3" });
  });

  it("says a window LoonSec has no check for is shown because another matched", async () => {
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk: walkFixture({ check: { state: "unchecked_window", detail: "LoonSec has no check for a 3-year window of Example; it is shown because the 2-year walk matched." } }) });
    await open("?years=3");
    expect(text()).toContain(walkEnglish.uncheckedWindow(2, "Example"));
    expect(text()).toContain("LoonSec has no check for a 3-year window of Example; it is shown because the 2-year walk matched.");
  });

  it("names the walk it is reading by the track's label alone, which already begins with the app's name", async () => {
    walkApi.getPatchPolicyWalk.mockReturnValue(new Promise(() => {}));
    await open();
    expect(text()).toContain(walkEnglish.walkLoading("Example 4.4", "Public"));
    expect(text()).toContain("Walking Example 4.4 over Public…");
    expect(text()).not.toContain("Example Example");
  });

  it("says with the joined versions how many of a channel LoonSec's data does not walk were set aside", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    const walk = walkFixture({ source: "jamf" });
    walk.inputs.timeline = {
      ...walk.inputs.timeline,
      other_channel: 3,
      other_channels: [{ channel: "esr", label: "Example ESR", source: "https://example.test/esr.json", count: 3, versions: ["128.1.0", "128.2.0", "128.3.0"] }],
      note: null
    };
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
    await open("?source=jamf");
    expect(text()).toContain(walkEnglish.channelSetAside(3, "Example ESR", 4));
    expect(text()).toContain("Example ESR, set aside: 128.1.0, 128.2.0, 128.3.0");
    // Said once: the instance counts them and leaves the words to the page.
    expect(text().split("set aside: LoonSec's data does not walk that channel yet")).toHaveLength(2);
    // One version is said in the singular, and an answer from an older instance says nothing of channels.
    walk.inputs.timeline = { ...walk.inputs.timeline, other_channel: 1, other_channels: [{ channel: "esr", label: "Example ESR", source: "", count: 1, versions: ["128.1.0"] }], note: null };
    cleanup();
    await open("?source=jamf");
    expect(text()).toContain("1 version of Example ESR set aside: LoonSec's data does not walk that channel yet, so it is neither walked nor counted as unmatched");
    const older = { ...walk.inputs.timeline };
    delete older.other_channel;
    delete older.other_channels;
    walk.inputs.timeline = older;
    cleanup();
    await open("?source=jamf");
    expect(text()).not.toContain("set aside: LoonSec's data");
  });

  it("splits the never stop's never seen into those already fixed in the version it keeps and those outside every NVD range", async () => {
    const walk = walkFixture();
    walk.policies.never = { ...walk.policies.never, never_seen: 120, never_seen_outside_affected_range: 113 };
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
    await open("?policy=never");
    expect(text()).toContain(patchPolicyEnglish.neverStays("4.4.1", 120, 113));
    expect(text()).toContain(
      "A device that never updates stays on 4.4.1. Of the 120 never seen, 7 were already fixed in 4.4.1, so the device never ran a version they affect. The other 113 fall outside every range NVD names: either they affect only other versions, or NVD names no range for 4.4.1's line, since NVD often stops naming a line once it reaches end of life. They do not show the device was safe (troubleshooting.md §33 step 11)."
    );
    // In its place, not beside it: `outside` would say those 113 never affect this Mac.
    expect(text()).not.toContain("never seen were never in range");
    cleanup();
    await open("?policy=30d");
    expect(text()).not.toContain("A device that never updates stays on");
    expect(text()).toContain("1 of the 1 never seen was never in range");
  });

  it("says how each fix was dated beside the CVE, and counts the fixes so dated under Evidence", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    const walk = walkFixture({ source: "fleet" });
    // Fleet's first dated day is 2024-10-01 (`inputs.timeline.first`): a fix dated by a version Fleet
    // first carried that day is older than Fleet's history, and the page says so.
    const [first, second, third] = walk.cves;
    first.fix_dated_by = [
      { line: "4.4", fix: "4.4.3", named: null, dated_as: "4.4.3", on: "2025-01-09", how: "fix" },
      { line: "4.4", fix: "4.4.3", named: "4.4.2.9", dated_as: "4.4.3", on: "2025-01-09", how: "fix" }
    ];
    // A fix Fleet dates itself on its first day is the fix and its date, with no word about Fleet's
    // history: the note is for a fix older than the history, dated by the first version it holds.
    second.fix_dated_by = [
      { line: "4.4", fix: "4.4.2", named: null, dated_as: "4.4.4", on: "2024-10-01", how: "next_dated" },
      { line: "4.4", fix: "4.4.1", named: null, dated_as: "4.4.1", on: "2024-10-01", how: "fix" }
    ];
    third.fix_dated_by = [
      { line: "4.2", fix: null, named: "4.2.9", dated_as: null, on: null, how: "undated" },
      { line: "4.4", fix: "4.4.2", named: null, dated_as: "4.4.5", on: "2024-12-03", how: "next_dated" },
      { line: "4.4", fix: "4.4.7", named: null, dated_as: null, on: null, how: "undated" },
      // A `how` a later instance may add is printed as the walk spells it, never as one this build knows.
      { line: "4.4", fix: "4.4.9", named: null, dated_as: null, on: null, how: "later_word" as never }
    ];
    walk.counts = { ...walk.counts, fix_dating: { fix: 3, next_dated: 2, undated: 2 } };
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
    await open("?source=fleet");
    // Under each CVE, a full-width list with one item per entry, not a seventh column.
    expect(text()).toContain(walkEnglish.fixDatedLead("CVE-2099-0001", 2));
    expect(text()).toContain(walkEnglish.fixDatedLead("CVE-2099-0003", 4));
    expect(screen.getAllByRole("columnheader").map((each) => each.textContent)).not.toContain("Fix, as this source dates it");
    const listed = (cve: string) =>
      Array.from(screen.getByText(walkEnglish.fixDatedLead(cve, cve === "CVE-2099-0003" ? 4 : 2)).parentElement!.querySelectorAll("li")).map((each) => each.textContent);
    // Two entries at one version (the fix, then NVD's bound that lands there) are two items.
    expect(listed("CVE-2099-0001")).toEqual(["4.4.3, dated 2025-01-09", "4.4.3, dated 2025-01-09 (NVD names 4.4.2.9)"]);
    expect(listed("CVE-2099-0003")).toHaveLength(4);
    // A fix the source dates itself: the fix and its date, and nothing more; NVD's own version beside it where it differs.
    expect(text()).toContain("4.4.3, dated 2025-01-09 4.4.3, dated 2025-01-09 (NVD names 4.4.2.9)");
    expect(text()).toContain(`${walkEnglish.fixNextDated("4.4.2", "4.4.4", "2024-10-01")} Fleet's history begins here 4.4.1, dated 2024-10-01`);
    // Dated later than the source's first day: no word about its history.
    expect(text()).toContain(walkEnglish.fixNextDated("4.4.2", "4.4.5", "2024-12-03"));
    expect(text().split("history begins here")).toHaveLength(2);
    expect(text()).toContain(`${walkEnglish.fixNone("4.2")} (NVD names 4.2.9)`);
    expect(text()).toContain(walkEnglish.fixUndated("4.4.7", "4.4"));
    expect(text()).toContain("4.4.9 (later_word)");
    expect(text()).not.toContain(walkEnglish.fixUndated("4.4.9", "4.4"));
    expect(text()).toContain(`Fixes dated ${walkEnglish.fixDating(3, 2, 2)}`);

    // An answer from an instance older than the ruling carries neither: no line under a CVE, and no Evidence row.
    cleanup();
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk: walkFixture({ source: "fleet" }) } satisfies WalkAnswer);
    await open("?source=fleet");
    expect(text()).not.toContain("Fixes dated");
    expect(text()).not.toContain("dated by the fix itself");
    expect(text()).not.toContain("as this source dates");
  });

  it("says a set-aside channel it cannot count nowhere, rather than 'undefined versions'", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    const walk = walkFixture({ source: "jamf" });
    walk.inputs.timeline = {
      ...walk.inputs.timeline,
      other_channels: [{ channel: "esr", label: "Example ESR", source: "https://example.test/esr.json", versions: ["128.1.0"] } as never]
    };
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
    await open("?source=jamf");
    expect(text()).not.toContain("undefined");
    expect(text()).not.toContain("set aside: LoonSec's data");
  });

  it("says a failed or empty Jamf catalog leaves only the data's apps listed, not the replays", async () => {
    jamfApi.listJamfPatchTitles.mockRejectedValue(new ApiError(500, null));
    await open();
    expect(text()).toContain(walkEnglish.catalogFailed);
    expect(text()).not.toContain(en.patchPolicy.catalogFailed);
    expect(text()).not.toContain("reference replay");
    cleanup();
    jamfApi.listJamfPatchTitles.mockResolvedValue({ items: [] });
    await open();
    expect(text()).toContain(walkEnglish.catalogEmpty);
    expect(text()).not.toContain(en.patchPolicy.catalogEmpty);
  });

  it("says a page past the end of the CVE list is past it, and offers the last page", async () => {
    let pages = 1;
    walkApi.getPatchPolicyWalk.mockImplementation((query: string) => {
      const page = Number(new URLSearchParams(query).get("page") ?? 1);
      const past = page > pages ? { cves: [] } : {};
      return Promise.resolve({ walk: walkFixture({ ...past, cves_page: { page, page_size: 200, pages, total: pages === 1 ? 3 : 1100 } }) });
    });
    await open("?page=2");
    expect(asked().at(-1)?.get("page")).toBe("2");
    expect(text()).toContain(walkEnglish.pastEnd(2, 1, 3));
    expect(text()).toContain("Page 2 is past the end of this list: it holds 3 CVEs on 1 page.");
    expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
    fireEvent.click(button("Show page 1"));
    await settle();
    expect(address().get("page")).toBeNull();
    expect(asked().at(-1)?.get("page")).toBeNull();
    expect(text()).toContain("CVE-2099-0001");
    expect(text()).not.toContain("past the end");

    cleanup();
    pages = 6;
    await open("?page=7");
    expect(text()).toContain("Page 7 is past the end of this list: it holds 1100 CVEs on 6 pages.");
    // The pager would read "Page 7 of 6"; the sentence and its button stand in for it.
    expect(text()).not.toContain("Page 7 of 6");
    fireEvent.click(button("Show page 6"));
    await settle();
    expect(address().get("page")).toBe("6");
    expect(text()).toContain("Page 6 of 6 · 1100 CVEs");
  });

  it("says under Evidence that only the public, unaligned view is the walk that was checked", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    const alignedWindow: PatchPolicyWalk["window"] = {
      requested: { years: 2, since: "2023-01-10", until: "2025-01-10" },
      since: "2025-01-01",
      until: "2025-01-10",
      days: 10,
      shortened_by: [{ reason: "common_window", date: "2025-01-01", sentence: "The view is aligned to the days every compared timeline covers." }],
      aligned: { sources: ["public", "jamf", "fleet"], since: "2025-01-01", until: "2025-01-10", left_out: [] }
    };
    walkApi.getPatchPolicyWalk.mockImplementation((query: string) => {
      const request = new URLSearchParams(query);
      const aligned = request.get("align") === "common" ? { window: alignedWindow } : {};
      return Promise.resolve({ walk: walkFixture({ source: request.get("source") as WalkSource, ...aligned }) });
    });
    await open();
    expect(text()).toContain(`${walkEnglish.evidenceCheck} ${walkEnglish.checks.matched} ${walkEnglish.serverSaid(CHECK_DETAIL)}`);
    for (const source of [/^Jamf/, /^Fleet/]) {
      fireEvent.click(button(source));
      await settle();
      expect(text()).toContain(`${walkEnglish.evidenceCheck} ${walkEnglish.checkedByPublic} ${walkEnglish.serverSaid(CHECK_DETAIL)}`);
      expect(text()).not.toContain(walkEnglish.checks.matched);
      // The detail beneath names the walk that was checked; the page's own words do not name it again.
      expect(text().split("over 2 years")).toHaveLength(2);
    }
    fireEvent.click(button(/^Public/));
    fireEvent.click(screen.getByRole("checkbox"));
    await settle();
    expect(asked().at(-1)?.get("source")).toBe("public");
    expect(asked().at(-1)?.get("align")).toBe("common");
    expect(text()).toContain(walkEnglish.checkedByPublic);
    expect(text()).not.toContain(walkEnglish.checks.matched);
  });

  it("prints each row's clock, and Evidence counts both clocks", async () => {
    await open();
    expect(text()).toContain("2025-01-06 first detectable");
    expect(text()).toContain("2025-01-02 NVD publication");
    // The KEV cell may wrap beside its date, never inside it (a date breaks at its hyphens).
    expect(text()).toContain("listed 2025-01-08");
    expect(screen.getByText("2025-01-08").className).toContain("whitespace-nowrap");
    expect(screen.getAllByText("2025-01-06").some((each) => each.tagName === "SPAN" && each.className.includes("whitespace-nowrap"))).toBe(true);
    expect(text()).toContain("2 counted from the first day they were detectable, 1 from NVD publication.");
    expect(text()).toContain("fixture-doc-0001");
    expect(text()).toContain("fixture-digest-timeline");
    expect(text()).toContain("fixture-input-0001");
    expect(text()).toContain("fixture-run-0001");
  });

  it("says when the data held is old, above the walk", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([appFixture()], { state: "stale" }));
    await open();
    // The instance judged the fixture's last build (2025-01-11) stopped (`publisherRunning: false`), and the page says so.
    expect(text()).toContain("Showing patch-policy data dated 2025-01-11, more than three days old: LoonSec's publisher last ran on 2025-01-11, more than three days ago");
    expect(asked()).toHaveLength(1);
  });

  it("names the stale copy's cause the instance judged, not the one this browser's clock would", async () => {
    // A build of 2025-01-11 is years old by this browser's clock; the instance says it judged the
    // publisher running, and the page follows the instance, as its own sentence does.
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([appFixture()], { state: "stale", publisherRunning: true }));
    await open();
    expect(text()).toContain("LoonSec's publisher last ran on 2025-01-11, but its NVD data has not advanced since 2025-01-11");
  });

  it("asks nothing for a source the address names and the instance cannot date", async () => {
    await open("?source=fleet");
    expect(walkApi.getPatchPolicyWalk).not.toHaveBeenCalled();
    expect(text()).toContain(walkEnglish.notWalked("Fleet"));
    expect(button(/^Fleet/).getAttribute("aria-pressed")).toBe("true");
  });

  it("keeps Public as the default when it cannot date the track, says why, and walks nothing until a source is picked", async () => {
    const app = openApp();
    const undated = "LoonSec's patch-policy data lists Example's versions without public release dates.";
    const none = { ...app.sources.public, available: false, state: "no_public_dates", sentence: undated, tracks: app.sources.public.tracks.map((each) => ({ ...each, available: false, state: "no_public_dates", sentence: undated })) };
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([{ ...app, sources: { ...app.sources, public: none } }]));
    await open();
    expect(button(/^Public/).getAttribute("aria-pressed")).toBe("true");
    expect((button(/^Public/) as HTMLButtonElement).disabled).toBe(true);
    expect(text()).toContain(`Public: ${walkEnglish.reasons.no_public_dates({ app: "Example", track: "Example 4.4", source: "", sourceId: "public" })}`);
    expect(text()).toContain(walkEnglish.serverSaid(undated));
    expect(text()).toContain(walkEnglish.notWalked("Public"));
    expect(walkApi.getPatchPolicyWalk).not.toHaveBeenCalled();
    fireEvent.click(button(/^Jamf/));
    await settle();
    expect(asked().at(-1)?.get("source")).toBe("jamf");
  });

  it("says an app or a track the data does not reference is not a count of zero", async () => {
    await open("?app=nothing");
    expect(text()).toContain(walkEnglish.unknownApp("nothing"));
    expect(walkApi.getPatchPolicyWalk).not.toHaveBeenCalled();
    cleanup();
    await open("?track=example/esr");
    expect(text()).toContain(walkEnglish.unknownTrack("Example", "example/esr", "Example 4.4, Example (newest line)"));
    expect(walkApi.getPatchPolicyWalk).not.toHaveBeenCalled();
  });

  it("says an ESR title folded under the app is not walked", async () => {
    jamfApi.listJamfPatchTitles.mockResolvedValue({ items: [{ name: "Example ESR", bundleId: "com.example.app" }] });
    await open();
    expect(text()).toContain(walkEnglish.esrNotInData("Example"));
  });
});

describe("a walk that is not shown says why", () => {
  const refuse = (reason: string, detail: string, facts: Record<string, unknown> = {}, source: string | null = "public") =>
    walkApi.getPatchPolicyWalk.mockResolvedValue({ refusal: { reason, detail, source, facts } } satisfies WalkAnswer);

  it("parity: no view of the app, and the instance's sentence for the report", async () => {
    const detail = "The walk of LoonSec's published dates for Example 4.4 over 2 years does not match the totals LoonSec published with the data (1d: exposed is 2 here and 3 in the data), so no view of Example is shown.";
    refuse("parity", detail, { stop: "1d", key: "exposed", walked: 2, published: 3 });
    await open();
    expect(text()).toContain(walkEnglish.reasons.parity({ app: "Example", track: "Example 4.4", source: "", sourceId: "public" }));
    expect(text()).toContain(walkEnglish.serverSaid(detail));
    // The totals that disagreed, from the refusal's facts, with the stop in the reader's words.
    expect(text()).toContain("At 1 day, exposed: the walk of LoonSec's dates counts 2, and LoonSec published 3.");
    expect(text()).not.toContain("vulnerabilities never seen");
  });

  it("unchecked or no public dates: each window of the app and why it was not matched", async () => {
    const detail = "LoonSec holds no public release dates for Example yet, so no walk of Example can be checked against the totals LoonSec publishes, and no view of it is shown from any source, Jamf and Fleet included: a view is shown only once the walk of LoonSec's own dates for one of the app's windows matches those totals. Nothing on this instance is wrong.";
    refuse("no_public_dates", detail, { windows: { "example/4.4 2y": "no_public_dates", "example/4.4 3y": "no_public_dates" } });
    await open();
    const lead = walkEnglish.reasons.no_public_dates({ app: "Example", track: "Example 4.4", source: "", sourceId: "public" });
    expect(text()).toContain(lead);
    // The page no longer promises Jamf or Fleet for an app none of whose windows can be checked.
    expect(lead).not.toContain("Jamf or Fleet may");
    expect(text()).toContain("Each window: example/4.4 2y: no_public_dates; example/4.4 3y: no_public_dates");
  });

  it("too many unmatched: the versions that matched nothing are listed", async () => {
    refuse("too_many_unmatched", "3 of the 20 versions … match no version.", { in_reach: { unmatched: ["4.5.0rc1", "4.5.0rc2", "4.5.0rc3"] } }, "jamf");
    await open();
    expect(text()).toContain("More than 5% of the versions this instance's copy of Jamf's public patch catalog dates");
    expect(text()).toContain(walkEnglish.reasons.too_many_unmatched({ app: "Example", track: "Example 4.4", source: walkEnglish.sourceWords.jamf, sourceId: "jamf" }));
    expect(text()).toContain("Choose Public (troubleshooting.md §33 step 4).");
    expect(text()).toContain("Unmatched: 4.5.0rc1, 4.5.0rc2, 4.5.0rc3");
  });

  it("too many unmatched with a channel set aside: the set-aside count is said beside the unmatched versions", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    const facts = {
      in_reach: { unmatched: ["147.0b1"] },
      other_channels: [{ channel: "esr", label: "Example ESR", source: "https://example.test/esr.json", count: 12, versions: ["128.1.0"] }]
    };
    refuse("too_many_unmatched", "1 of the 10 versions … match no version.", facts, "fleet");
    await open("?source=fleet");
    expect(text()).toContain("Unmatched: 147.0b1");
    expect(text()).toContain(walkEnglish.channelSetAside(12, "Example ESR", 5));
    expect(text()).toContain("12 versions of Example ESR set aside: LoonSec's data does not walk that channel yet, so they are neither walked nor counted as unmatched (troubleshooting.md §33 step 5).");
  });

  it("too many unmatched, or none matched, over Fleet: the Fleet step, not the Jamf one", async () => {
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    refuse("too_many_unmatched", "3 of the 20 versions … match no version.", { in_reach: { unmatched: ["128.5.0esr"] } }, "fleet");
    await open("?source=fleet");
    expect(text()).toContain("More than 5% of the versions this instance's Fleet history dates");
    expect(text()).toContain("Choose Public (troubleshooting.md §33 step 5).");
    expect(text()).not.toContain("§33 step 4");
    cleanup();
    refuse("no_matched_versions", "None of the 4 versions … is a version LoonSec's patch-policy data lists.", {}, "fleet");
    await open("?source=fleet");
    expect(text()).toContain(walkEnglish.reasons.no_matched_versions({ app: "Example", track: "Example 4.4", source: walkEnglish.sourceWords.fleet, sourceId: "fleet" }));
    expect(text()).toContain("Choose another source (troubleshooting.md §33 step 5).");
    expect(text()).not.toContain("§33 step 4");
  });

  it("a word this build has no sentence for is still shown, as the instance worded it", async () => {
    refuse("something_new", "A sentence from a newer instance.");
    await open();
    expect(text()).toContain("A sentence from a newer instance.");
  });

  it("a failed read is not a refusal", async () => {
    walkApi.getPatchPolicyWalk.mockResolvedValue({ failed: { status: 502 } } satisfies WalkAnswer);
    await open();
    expect(text()).toContain(walkEnglish.walkFailed(502));
    walkApi.getPatchPolicyWalk.mockResolvedValue({ failed: { status: 200, unreadable: "schema 2" } } satisfies WalkAnswer);
    cleanup();
    await open();
    expect(text()).toContain(walkEnglish.walkUnreadable("schema 2"));
  });
});

describe("in German", () => {
  it("names the sources, the reasons and the instance's English words as English", async () => {
    locale.current = "de";
    const detail = "LoonSec has published no totals this build could match for any window of Example.";
    walkApi.getPatchPolicyWalk.mockResolvedValue({ refusal: { reason: "unchecked", detail, source: "public", facts: {} } } satisfies WalkAnswer);
    await open();
    expect(button(/^Öffentlich/)).toBeTruthy();
    expect(text()).toContain(`Jamf: ${walkGerman.reasons.no_title({ app: "Example", track: "Example 4.4", source: "", sourceId: "jamf" })}`);
    expect(text()).toContain(`Fleet: ${walkGerman.reasons.flag_off({ app: "", track: "", source: "", sourceId: "fleet" })}`);
    expect(text()).toContain(walkGerman.serverSaid(FLAG_OFF_SENTENCE));
    expect(text()).toContain(walkGerman.reasons.unchecked({ app: "Example", track: "Example 4.4", source: "", sourceId: "public" }));
    expect(text()).toContain(walkGerman.serverSaid(detail));
  });

  it("falls back with the feed's German sentence", async () => {
    locale.current = "de";
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture(null, { state: "never", docId: null, asOf: null }));
    await open();
    expect(text()).toContain(walkGerman.fallback(de.support.patchPolicyFeed.states.never));
  });

  it("draws a walk with German words", async () => {
    locale.current = "de";
    await open();
    expect(text()).toContain("Offene CVEs pro Tag, bei 1 Tag");
    expect(text()).toContain(walkGerman.clockLine);
    expect(text()).toContain(walkGerman.checks.matched);
  });

  it("says in German that a Jamf view was not checked itself, and a failed catalog lists the data's apps", async () => {
    locale.current = "de";
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    jamfApi.listJamfPatchTitles.mockRejectedValue(new ApiError(500, null));
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk: walkFixture({ source: "jamf" }) });
    await open("?source=jamf");
    expect(text()).toContain(walkGerman.checkedByPublic);
    expect(text()).not.toContain(walkGerman.checks.matched);
    expect(text()).toContain(walkGerman.catalogFailed);
    expect(text()).not.toContain(de.patchPolicy.catalogFailed);
  });

  it("says in German what was set aside, what the never stop means, and why a parity refusal disagreed", async () => {
    locale.current = "de";
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    const walk = walkFixture({ source: "fleet" });
    walk.inputs.timeline = {
      ...walk.inputs.timeline,
      other_channel: 2,
      other_channels: [{ channel: "esr", label: "Example ESR", source: "https://example.test/esr.json", count: 2, versions: ["128.1.0", "128.2.0"] }]
    };
    walk.policies.never = { ...walk.policies.never, never_seen: 3, never_seen_outside_affected_range: 1 };
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
    await open("?source=fleet&policy=never");
    expect(text()).toContain(walkGerman.channelSetAside(2, "Example ESR", 5));
    expect(text()).toContain("2 Versionen von Example ESR beiseitegelegt: Die Daten von LoonSec spielen diesen Kanal noch nicht nach");
    expect(text()).toContain(patchPolicyGerman.neverStays("4.4.1", 3, 1));
    expect(text()).toContain(
      "Ein Gerät, das nie aktualisiert, bleibt auf 4.4.1. Von den 3 nie gesehenen waren 2 in 4.4.1 bereits behoben; auf dem Gerät lief also nie eine Version, die sie betreffen. Die übrige liegt außerhalb jedes Bereichs, den NVD nennt: Entweder betrifft sie nur andere Versionen, oder NVD nennt keinen Bereich für die Linie von 4.4.1"
    );
    cleanup();
    walkApi.getPatchPolicyWalk.mockResolvedValue({
      refusal: { reason: "parity", detail: "…", source: "public", facts: { stop: "never", key: "exposed", walked: 4, published: 5 } }
    } satisfies WalkAnswer);
    await open();
    expect(text()).toContain("Bei Nie, exposed: Der Durchlauf über die Daten von LoonSec zählt 4, LoonSec hat 5 veröffentlicht.");
  });

  it("says in German how each fix was dated, and counts them under Evidence", async () => {
    locale.current = "de";
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    const walk = walkFixture({ source: "jamf" });
    walk.cves[0].fix_dated_by = [{ line: "4.4", fix: "4.4.2", named: "4.4.1.5", dated_as: "4.4.3", on: "2024-10-01", how: "next_dated" }];
    walk.counts = { ...walk.counts, fix_dating: { fix: 0, next_dated: 1, undated: 0 } };
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
    await open("?source=jamf");
    expect(text()).toContain(walkGerman.fixDatedLead("CVE-2099-0001", 1));
    expect(text()).toContain(`${walkGerman.fixNextDated("4.4.2", "4.4.3", "2024-10-01")} (NVD nennt 4.4.1.5) Hier beginnt Jamfs Historie`);
    expect(text()).toContain(`Datierte Fixes ${walkGerman.fixDating(0, 1, 0)}`);
  });

  it("sends a German reader of a Fleet refusal to the Fleet step, and of a page past the end to step 10", async () => {
    locale.current = "de";
    feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
    walkApi.getPatchPolicyWalk.mockResolvedValue({ refusal: { reason: "too_many_unmatched", detail: "…", source: "fleet", facts: {} } } satisfies WalkAnswer);
    await open("?source=fleet");
    expect(text()).toContain("Wählen Sie Öffentlich (troubleshooting.md §33 Schritt 5).");
    cleanup();
    walkApi.getPatchPolicyWalk.mockResolvedValue({ walk: walkFixture({ cves: [], cves_page: { page: 3, page_size: 200, pages: 2, total: 250 } }) });
    await open("?page=3");
    expect(text()).toContain(walkGerman.pastEnd(3, 2, 250));
    expect(text()).toContain("Seite 3 liegt hinter dem Ende dieser Liste: Sie umfasst 250 CVEs auf 2 Seiten.");
    expect(button("Seite 2 zeigen")).toBeTruthy();
  });
});

describe("the walk's tables and dates, as a reader at 1280 px sees them (w5 e2e)", () => {
  /** A table's markup with every date that cannot wrap taken out: what is left is a date a line could
   *  break at its hyphens ("2026-" above "09-01"). */
  const bareDates = (element: Element) =>
    element.innerHTML.replace(/<(span|td) class="[^"]*whitespace-nowrap[^"]*">\d{4}-\d{2}-\d{2}<\/(span|td)>/g, "").match(/\d{4}-\d{2}-\d{2}/g) ?? [];
  const classes = (element: Element) => element.className.split(" ").filter(Boolean);
  /** The walk view's tables in their order: the day graph's, every stop, each listed CVE, the count of
   *  each reason, and the excluded CVEs. */
  const tables = () => {
    const all = Array.from(document.querySelectorAll("table"));
    expect(all).toHaveLength(5);
    return { stops: all[1], ledger: all[2], reasons: all[3], excluded: all[4] };
  };
  const heads = (table: Element) => Array.from(table.querySelectorAll("thead th")).map(classes);

  it("lets the outcome take the room, and wraps every heading and cell at its spaces, never inside a word", async () => {
    for (const language of ["en", "de"] as const) {
      locale.current = language;
      await open();
      const { stops, ledger, reasons, excluded } = tables();
      for (const table of [stops, ledger, reasons, excluded]) {
        // Hyphenated, a German heading broke mid-word ("Richtli-nie", "Expositi-onstage") while a space
        // was free: no table of the walk hyphenates, and every heading is smaller than its cells.
        expect(classes(table)).not.toContain("hyphens-auto");
        for (const head of heads(table)) expect(head).toEqual(expect.arrayContaining(["text-xs", "hyphens-manual"]));
      }
      // Eight columns at a 1280 px window: tighter cells, so each German heading's longest word fits.
      expect(heads(stops).every((head) => head.includes("px-2"))).toBe(true);
      expect(Array.from(stops.querySelectorAll("tbody td")).every((cell) => classes(cell).includes("px-2"))).toBe(true);
      // Each listed CVE: every column but the outcome shrinks to its widest word or date, so "Herkunft"
      // is not squeezed to a syllable beside a KEV column holding a dash.
      expect(heads(ledger).map((head) => head.includes("w-[1%]"))).toEqual([true, false, true, true, true, true]);
      const firstRow = ledger.querySelector("tbody tr")!;
      expect(Array.from(firstRow.children).every((cell) => classes(cell).includes("px-1.5"))).toBe(true);
      // The excluded CVEs: the id shrinks to fit, and the clock's word wraps under its whole date.
      expect(heads(excluded).map((head) => head.includes("w-[1%]"))).toEqual([true, false, false, false]);
      cleanup();
    }
  });

  it("keeps every date whole: the updates, the outcome, KEV, each fix line, the window and Evidence, in English and German", async () => {
    for (const language of ["en", "de"] as const) {
      locale.current = language;
      feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
      const walk = walkFixture({ source: "fleet" });
      walk.cves[0].fix_dated_by = [
        { line: "4.4", fix: "4.4.3", named: null, dated_as: "4.4.3", on: "2025-01-09", how: "fix" },
        { line: "4.4", fix: "4.4.2", named: null, dated_as: "4.4.4", on: "2024-10-01", how: "next_dated" }
      ];
      walk.exclusions.cves = [{ ...walk.exclusions.cves[0], detail: "recorded exception ruled 2026-11-25" }];
      walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
      await open("?source=fleet");
      const { ledger, excluded } = tables();
      // The list of updates: as many columns as fit one update a line, each date a span of its own.
      const updates = document.querySelector("details ul")!;
      expect(classes(updates)).toContain("grid-cols-[repeat(auto-fill,minmax(12rem,1fr))]");
      const items = Array.from(updates.querySelectorAll("li"));
      expect(items.length).toBeGreaterThan(0);
      for (const item of items) expect(item.querySelector("span.whitespace-nowrap")?.textContent).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      // Each fix line, in the reader's language: the fix's date and the date a later version gave it.
      const fixes = Array.from(ledger.querySelectorAll("li"));
      expect(fixes.map((each) => each.textContent)).toEqual([
        language === "en" ? "4.4.3, dated 2025-01-09" : "4.4.3, datiert 2025-01-09",
        (language === "en" ? walkEnglish : walkGerman).fixNextDated("4.4.2", "4.4.4", "2024-10-01") +
          (language === "en" ? walkEnglish : walkGerman).historyBegins.fleet
      ]);
      for (const each of fixes) expect(bareDates(each)).toEqual([]);
      expect(fixes[0].innerHTML).toContain('<span class="whitespace-nowrap">2025-01-09</span>');
      expect(fixes[1].innerHTML).toContain('<span class="whitespace-nowrap">2024-10-01</span>');
      // The outcome ("…until 4.4.3 on 2025-01-09"), the clock day, KEV: nothing left to break.
      expect(bareDates(ledger)).toEqual([]);
      expect(bareDates(excluded)).toEqual([]);
      // The view's own window line, the dates it reads, and Evidence.
      const view = ledger.closest("div.min-w-0")!;
      expect(bareDates(view.firstElementChild!)).toEqual([]);
      expect(bareDates(view.querySelector("dl")!)).toEqual([]);
      cleanup();
    }
  });

  it("says why a fix sits below the build NVD names: the Mac's build of that release, in English and German", async () => {
    for (const language of ["en", "de"] as const) {
      locale.current = language;
      const words = language === "en" ? walkEnglish : walkGerman;
      const copy = language === "en" ? patchPolicyEnglish : patchPolicyGerman;
      feedApi.getPatchPolicyApps.mockResolvedValue(appsFixture([openApp()]));
      const walk = walkFixture({ source: "fleet" });
      // Invented four-part builds of one release: the Mac's .41 below NVD's .52, dated itself and, over
      // a source that does not date it, by the next build; a fix above NVD's build (.84, a later
      // release of the same build) and one on another build keep the plain words.
      walk.cves[0].fix_dated_by = [
        { line: "", fix: "131.0.6700.41", named: "131.0.6700.52", dated_as: "131.0.6700.41", on: "2025-01-03", how: "fix" },
        { line: "", fix: "131.0.6700.41", named: "131.0.6700.52", dated_as: "131.0.6700.42", on: "2025-01-05", how: "next_dated" },
        { line: "", fix: "131.0.6700.84", named: "131.0.6700.52", dated_as: "131.0.6700.84", on: "2025-01-08", how: "fix" },
        { line: "", fix: "131.0.6650.90", named: "131.0.6700.52", dated_as: "131.0.6650.90", on: "2025-01-08", how: "fix" }
      ];
      walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
      await open("?source=fleet");
      const lines = Array.from(tables().ledger.querySelectorAll("li")).map((each) => each.textContent);
      expect(lines).toEqual([
        `${copy.fix("131.0.6700.41", "2025-01-03")} (${words.nvdNamedMacBuild("131.0.6700.52")})`,
        `${words.fixNextDated("131.0.6700.41", "131.0.6700.42", "2025-01-05")} (${words.nvdNamedMacBuild("131.0.6700.52")})`,
        `${copy.fix("131.0.6700.84", "2025-01-08")} (${words.nvdNamed("131.0.6700.52")})`,
        `${copy.fix("131.0.6650.90", "2025-01-08")} (${words.nvdNamed("131.0.6700.52")})`
      ]);
      // The reason, and where the step-through is.
      expect(words.nvdNamedMacBuild("131.0.6700.52")).toContain(language === "en" ? "another platform's build of the same release" : "anderen Plattform aus demselben Release");
      expect(words.nvdNamedMacBuild("131.0.6700.52")).toContain(language === "en" ? "troubleshooting.md §33 step 12" : "troubleshooting.md §33 Schritt 12");
      cleanup();
    }
  });

  it("marks an exclusion's detail as LoonSec's English words in German, and one the walk worded as the instance's", async () => {
    for (const language of ["en", "de"] as const) {
      locale.current = language;
      const words = language === "en" ? walkEnglish : walkGerman;
      const walk = walkFixture();
      walk.counts = { ...walk.counts, excluded: 2, in_window: 5 };
      walk.exclusions = {
        ...walk.exclusions,
        by_reason: { rejected: 0, no_configuration_for_pair: 1, branch_ambiguity: 1 },
        cves: [
          { ...walk.exclusions.cves[0], detail: "no configuration names this CPE pair" },
          {
            cve_id: "CVE-2099-0010",
            reason: "branch_ambiguity",
            clock: "detectable_at",
            clock_date: "2025-01-05",
            published: "2025-01-04",
            detail: "the range is ambiguous on '4.2', which the path visits"
          }
        ]
      };
      walkApi.getPatchPolicyWalk.mockResolvedValue({ walk } satisfies WalkAnswer);
      await open();
      const { excluded } = tables();
      // The header says whose words the column holds, in German only: English needs no note.
      expect(Array.from(excluded.querySelectorAll("thead th")).map((each) => each.textContent).at(-1)).toBe(
        language === "en" ? "Detail" : "Detail (Wortlaut von LoonSec, englisch)"
      );
      const details = Array.from(excluded.querySelectorAll("tbody tr")).map((row) => row.lastElementChild!.textContent);
      // LoonSec's detail as it is; the walk's own (LoonSec's data never excludes for a branch ambiguity) marked as the instance's.
      expect(details).toEqual(["no configuration names this CPE pair", words.serverSaid("the range is ambiguous on '4.2', which the path visits")]);
      cleanup();
    }
  });
});
