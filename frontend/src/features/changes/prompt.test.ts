/** The Changes Prompt bar's words and its one move on the page. Frontend lane (#285). */

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiBodyError, ApiError, apiRequest } from "@/config/api";
import type { ChangeFilters, ChangeKind, PromptFilters, PromptResult, PromptSummary, PromptWhen } from "@/features/changes/types";
import {
  MAX_QUESTION_CHARS,
  answerLines,
  askFailureText,
  bannerKind,
  failureReason,
  filtersFromPrompt,
  filtersOnArrival,
  hasSomethingToClear,
  isPromptResult,
  isPromptStatus,
  modelOptions,
  proposedFilters,
  providerLabel,
  readReply,
  readback,
  replyDisposition,
  stillShowing
} from "@/features/changes/prompt";
import { CHANGE_KINDS } from "@/features/changes/render";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const NO_DIMENSIONS = { model: null, osVersion: null, department: null, managed: null, departmentName: null } as const;
const WIRESHARK: PromptFilters = { q: null, artifact: "Wireshark", level: null, section: "applications", change: null, ...NO_DIMENSIONS };
// Kyle's first demo question, "List new application installs".
const NEW_INSTALLS: PromptFilters = { q: null, artifact: null, level: null, section: "applications", change: "added", ...NO_DIMENSIONS };
// A correction that widens, as the server words it (backend/app/ai/changes_prompt.py).
const WIDENED_SECTION = "The model named a section this page does not have, so it was read as any section.";

function result(overrides: Partial<PromptResult> = {}): PromptResult {
  return {
    outcome: "applied",
    filters: { ...WIRESHARK },
    unsupported: null,
    repairs: [],
    widening: [],
    summary: null,
    provider: "apple_fm",
    model: "system",
    destination: "http://host.docker.internal:1976",
    latencyMs: 412,
    error: null,
    ...overrides
  };
}

function summary(overrides: Partial<PromptSummary> = {}): PromptSummary {
  return { total: 0, devicesTotal: 0, truncated: false, otherSubjects: 0, devices: [], when: null, ...overrides };
}

// A question the filters cannot answer, as the server sends it: nothing to run, the reason
// and the server's sentence in `error`.
const INVALID = result({
  outcome: "invalid",
  filters: null,
  error: { kind: "not_about_changes", message: "It is not a question about changes on your devices.", status: null }
});

describe("filtersFromPrompt replaces the page's filters, never merges into them", () => {
  it("carries the five keys the bar speaks, nulls as unset", () => {
    expect(filtersFromPrompt(WIRESHARK)).toMatchObject({
      q: undefined,
      artifact: "Wireshark",
      level: undefined,
      section: "applications",
      change: undefined
    });
    expect(filtersFromPrompt({ q: "KY4QVD7430", artifact: null, level: "high", section: null, change: null, ...NO_DIMENSIONS })).toMatchObject({
      q: "KY4QVD7430",
      artifact: undefined,
      level: "high",
      section: undefined,
      change: undefined
    });
  });

  it("carries the change kind: new installs are Applications and Added", () => {
    expect(filtersFromPrompt(NEW_INSTALLS)).toMatchObject({ section: "applications", change: "added" });
  });

  it("names every other key as undefined, so update() clears the window and the device", () => {
    const next = filtersFromPrompt(WIRESHARK);
    for (const key of ["minLevel", "since", "connectionId", "subjectId", "subjectKind"] as const) {
      expect(next).toHaveProperty(key, undefined);
    }
    // What the page's update() does with it: a spread over the current filters.
    const fromDevicePage: ChangeFilters = {
      q: "old",
      since: "2026-09-07T12:00:00.000Z",
      minLevel: "normal",
      change: "removed",
      connectionId: 1,
      subjectId: "42",
      subjectKind: "computer",
      page: 3
    };
    const merged = { ...fromDevicePage, ...next };
    expect(merged).toEqual({
      q: undefined,
      artifact: "Wireshark",
      level: undefined,
      section: "applications",
      change: undefined,
      minLevel: undefined,
      since: undefined,
      connectionId: undefined,
      subjectId: undefined,
      subjectKind: undefined,
      page: 1
    });
  });

  // #447: the four a repair can set, and the six it cannot.
  it("carries the dimensions a repair moved a Search into", () => {
    const answer = { ...WIRESHARK, model: "MacBook Air", osVersion: "26", department: "5", managed: "false" };
    expect(filtersFromPrompt(answer)).toMatchObject({
      q: undefined,
      artifact: "Wireshark",
      model: "MacBook Air",
      osVersion: "26",
      department: "5",
      managed: "false"
    });
  });

  it("clears the hidden keys the bar cannot set, so a narrowed feed answers for the fleet", () => {
    const next = filtersFromPrompt(WIRESHARK);
    for (const key of ["trigger", "spanId", "version", "fileVault", "site", "user", "model", "osVersion", "department", "managed"] as const) {
      expect(next).toHaveProperty(key, undefined);
    }
    const fromALink: ChangeFilters = { trigger: "webhook", spanId: "2f6c1e4a", version: "153", user: "dana", model: "Mac mini" };
    expect({ ...fromALink, ...next }).toMatchObject({ trigger: undefined, spanId: undefined, version: undefined, user: undefined });
  });

  it("an empty string is unset too, not a filter on nothing", () => {
    expect(filtersFromPrompt({ q: "", artifact: "", level: null, section: "", change: null, ...NO_DIMENSIONS })).toMatchObject({
      q: undefined,
      artifact: undefined,
      section: undefined
    });
  });
});

describe("stillShowing hides an answer about filters the page no longer shows", () => {
  const applied = filtersFromPrompt(WIRESHARK);

  it("a hidden filter is one of those filters (#447)", () => {
    const shown = { artifact: "Wireshark", section: "applications" };
    expect(stillShowing(applied, shown)).toBe(true);
    for (const key of ["trigger", "spanId", "version", "model", "osVersion", "fileVault", "site", "department", "managed", "user"] as const) {
      expect(stillShowing(applied, { ...shown, [key]: "anything" })).toBe(false);
    }
    expect(hasSomethingToClear({ model: "MacBook Air" }, { q: "", artifact: "" }, false)).toBe(true);
    expect(hasSomethingToClear({ trigger: "webhook" }, { q: "", artifact: "" }, false)).toBe(true);
  });

  it("the page as the bar left it, on any page of results", () => {
    expect(stillShowing(applied, { artifact: "Wireshark", section: "applications", page: 1 })).toBe(true);
    expect(stillShowing(applied, { artifact: "Wireshark", section: "applications", page: 4 })).toBe(true);
  });

  it("any control moved, or Back to where the page was", () => {
    expect(stillShowing(applied, { artifact: "Wireshark", section: "applications", level: "high" })).toBe(false);
    expect(stillShowing(applied, { artifact: "Docker", section: "applications" })).toBe(false);
    expect(stillShowing(applied, { artifact: "Wireshark" })).toBe(false);
    expect(stillShowing(applied, { artifact: "Wireshark", section: "applications", subjectId: "42" })).toBe(false);
  });

  it("the Change control is one of those controls", () => {
    expect(stillShowing(applied, { artifact: "Wireshark", section: "applications", change: "added" })).toBe(false);
    const installs = filtersFromPrompt(NEW_INSTALLS);
    expect(stillShowing(installs, { section: "applications", change: "added" })).toBe(true);
    expect(stillShowing(installs, { section: "applications", change: "updated" })).toBe(false);
    expect(stillShowing(installs, { section: "applications" })).toBe(false);
  });
});

describe("readback — the handoff's describe(), in the page's labels", () => {
  it("nothing set says so", () => {
    expect(readback({ q: null, artifact: null, level: null, section: null }, en.changes)).toBe("Showing all changes");
  });

  it("the demo question", () => {
    expect(readback(WIRESHARK, en.changes)).toBe("Showing changes named “Wireshark”, in Applications");
  });

  it("device, thing, section, level — in that order, with section and level labels", () => {
    expect(
      readback({ q: "Kyle’s Mac mini", artifact: "Wireshark", level: "high", section: "disk_encryption" }, en.changes)
    ).toBe("Showing changes for a device matching “Kyle’s Mac mini”, named “Wireshark”, in Disk encryption, at high level");
  });

  it("an unknown section shows as its key rather than as nothing", () => {
    expect(readback({ q: null, artifact: null, level: null, section: "future_section" }, en.changes)).toBe(
      "Showing changes in future_section"
    );
  });

  it("German reads German", () => {
    expect(readback({ q: null, artifact: "Wireshark", level: "high", section: "applications" }, de.changes)).toBe(
      "Angezeigt werden Änderungen mit dem Namen „Wireshark“, im Abschnitt Anwendungen, auf Stufe Hoch"
    );
  });

  // #447: no control on the page, so the words are where a reader sees them.
  it("a dimension a repair set is named after the controls", () => {
    expect(readback({ ...WIRESHARK, model: "MacBook Air" }, en.changes)).toBe(
      "Showing changes named “Wireshark”, in Applications, on Macs whose model matches “MacBook Air”"
    );
    expect(readback({ osVersion: "26", department: "5" }, en.changes)).toBe(
      "Showing changes on Macs observed on OS 26, on Macs in Jamf department 5"
    );
    expect(readback({ managed: "false" }, en.changes)).toBe("Showing changes on Macs Jamf does not manage");
    // #450: the name the server resolved, when it resolved one; the id otherwise.
    expect(readback({ department: "5", departmentName: "Engineering : Product" }, en.changes)).toBe(
      "Showing changes on Macs in department “Engineering : Product”"
    );
    expect(readback({ managed: "true" }, en.changes)).toBe("Showing changes on Macs Jamf manages");
    expect(readback({ model: "Mac mini" }, de.changes)).toBe("Angezeigt werden Änderungen auf Macs mit Modell „Mac mini“");
  });

  it("the kind of change comes last: the first demo question", () => {
    expect(readback(NEW_INSTALLS, en.changes)).toBe("Showing changes in Applications, that were added");
  });

  it("the third demo question: Wireshark, Applications, Added", () => {
    expect(readback({ ...WIRESHARK, change: "added" }, en.changes)).toBe(
      "Showing changes named “Wireshark”, in Applications, that were added"
    );
  });

  it("every kind reads, alone or after the rest", () => {
    expect(readback({ change: "removed" }, en.changes)).toBe("Showing changes that were removed");
    expect(readback({ q: "VKM73DMG47", level: "high", change: "changed" }, en.changes)).toBe(
      "Showing changes for a device matching “VKM73DMG47”, at high level, that were changed"
    );
  });

  it("a kind this page has no word for shows as its key rather than as nothing", () => {
    expect(readback({ change: "moved" as ChangeKind }, en.changes)).toBe("Showing changes that were moved");
  });

  it("German names the kind in German", () => {
    expect(readback({ ...WIRESHARK, change: "added" }, de.changes)).toBe(
      "Angezeigt werden Änderungen mit dem Namen „Wireshark“, im Abschnitt Anwendungen, die hinzugefügt wurden"
    );
  });
});

describe("the Change filter's vocabulary", () => {
  it("is the ledger's four kinds, in the order the dropdown offers them", () => {
    // backend/tests/test_changes_prompt.py reads this same literal from render.ts.
    expect(CHANGE_KINDS).toEqual(["added", "removed", "updated", "changed"]);
  });

  it("every kind has a dropdown label and a response-box word, in both languages", () => {
    for (const strings of [en.changes, de.changes]) {
      expect(Object.keys(strings.changeKinds).sort()).toEqual([...CHANGE_KINDS].sort());
      expect(Object.keys(strings.prompt.answerKinds).sort()).toEqual([...CHANGE_KINDS].sort());
    }
  });
});

describe("answerLines — the response box, written from the server's count", () => {
  // The demo's Wireshark install on the pod: Jamf's report time, the report before it, and
  // our clock. Formatted through the same call the table's Observed column uses, so the
  // expectation holds in any zone the suite runs in.
  const OBSERVED = "2026-09-14T16:57:26Z";
  const EARLIER = "2026-09-14T00:33:16Z";
  const COLLECTED = "2026-09-14T16:57:56Z";
  const at = (iso: string) => new Date(iso).toLocaleString();
  const when = (overrides: Partial<PromptWhen> = {}): PromptWhen => ({
    observedAt: OBSERVED,
    oldestObservedAt: OBSERVED,
    collectedAt: COLLECTED,
    previousObservedAt: EARLIER,
    previousCollectedAt: EARLIER,
    deviceTimeMoved: true,
    ...overrides
  });
  const macMini = { connectionId: 1, label: "Kyle’s Mac mini", added: 0, removed: 0, updated: 0, changed: 0, lastObservedAt: OBSERVED };

  it("the demo: two computers, one line each, serial first", () => {
    const lines = answerLines(
      summary({
        total: 2,
        devicesTotal: 2,
        devices: [
          { ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 1 },
          { ...macMini, subjectId: "9", serial: "VKM73DMG47", updated: 1 }
        ]
      }),
      en.changes
    );
    expect(lines).toEqual([
      "2 computers, 2 changes.",
      `KY4QVD7430 — Kyle’s Mac mini · added 1 · ${at(OBSERVED)}`,
      `VKM73DMG47 — Kyle’s Mac mini · updated 1 · ${at(OBSERVED)}`
    ]);
  });

  it("no match says so", () => {
    expect(answerLines(summary(), en.changes)).toEqual(["No changes match."]);
  });

  it("names every kind that moved, and a device with no name by its Jamf ID", () => {
    const [, line] = answerLines(
      summary({
        total: 4,
        devicesTotal: 1,
        devices: [{ ...macMini, subjectId: "42", label: null, serial: null, added: 1, removed: 2, changed: 1 }]
      }),
      en.changes
    );
    expect(line).toBe(`Jamf ID 42 · added 1, removed 2, changed 1 · ${at(OBSERVED)}`);
  });

  it("a Mac named after its own serial is not printed twice", () => {
    const [, line] = answerLines(
      summary({ total: 1, devicesTotal: 1, devices: [{ ...macMini, subjectId: "7", label: "KY4QVD7430", serial: "KY4QVD7430", added: 1 }] }),
      en.changes
    );
    expect(line).toBe(`KY4QVD7430 · added 1 · ${at(OBSERVED)}`);
  });

  it("a truncated list says how many it left out", () => {
    const devices = Array.from({ length: 25 }, (_, i) => ({ ...macMini, subjectId: String(i), serial: `SERIAL${i}`, added: 1 }));
    const lines = answerLines(summary({ total: 30, devicesTotal: 30, truncated: true, devices }), en.changes);
    expect(lines[0]).toBe("30 computers, 30 changes.");
    expect(lines).toHaveLength(1 + 25 + 1);
    expect(lines.at(-1)).toBe("+5 more");
  });

  it("changes on groups and definitions are their own line, never counted as computers", () => {
    const lines = answerLines(
      summary({ total: 5, devicesTotal: 1, otherSubjects: 3, devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 2 }] }),
      en.changes
    );
    expect(lines).toEqual([
      "1 computer, 2 changes.",
      `KY4QVD7430 — Kyle’s Mac mini · added 2 · ${at(OBSERVED)}`,
      "Plus 3 changes on groups or definitions."
    ]);
  });

  it("only groups matched: no '0 computers' headline", () => {
    expect(answerLines(summary({ total: 1, otherSubjects: 1 }), en.changes)).toEqual([
      "1 change on groups or definitions, none on computers."
    ]);
  });

  it("German counts in German", () => {
    const lines = answerLines(
      summary({ total: 2, devicesTotal: 1, devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 2 }] }),
      de.changes
    );
    expect(lines).toEqual(["1 Computer, 2 Änderungen.", `KY4QVD7430 — Kyle’s Mac mini · hinzugefügt 2 · ${at(OBSERVED)}`]);
  });

  it("states when, and the inventory before it as the other end of the window", () => {
    const lines = answerLines(
      summary({ total: 1, devicesTotal: 1, devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 1 }], when: when() }),
      en.changes
    );
    expect(lines).toEqual([
      "1 computer, 1 change.",
      `Observed ${at(OBSERVED)}.`,
      `The inventory before it, ${at(EARLIER)}, did not show this change, so it happened between the two.`,
      `KY4QVD7430 — Kyle’s Mac mini · added 1 · ${at(OBSERVED)}`
    ]);
  });

  it("more than one change states both ends, which answers the first time as well as the last", () => {
    const [, span] = answerLines(
      summary({
        total: 2,
        devicesTotal: 1,
        devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 2 }],
        when: when({ oldestObservedAt: EARLIER })
      }),
      en.changes
    );
    expect(span).toBe(`Observed from ${at(EARLIER)} to ${at(OBSERVED)}.`);
  });

  it("several changes from one inventory share a time, and the box says it once", () => {
    const [, observed] = answerLines(
      summary({ total: 2, devicesTotal: 1, devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 2 }], when: when() }),
      en.changes
    );
    expect(observed).toBe(`Observed ${at(OBSERVED)}.`);
  });

  it("an inventory time that did not move is bounded by our own clock, not by a window of no length", () => {
    const earlierCollection = "2026-09-12T06:00:00Z";
    const [, line] = answerLines(
      summary({
        total: 1,
        devicesTotal: 1,
        devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", changed: 1 }],
        when: when({ previousObservedAt: OBSERVED, previousCollectedAt: earlierCollection, deviceTimeMoved: false })
      }),
      en.changes
    );
    expect(line).toBe(`Observed ${at(OBSERVED)}.`);
    expect(answerLines(summary({ total: 1, devicesTotal: 1, devices: [], when: when({ previousObservedAt: OBSERVED, previousCollectedAt: earlierCollection, deviceTimeMoved: false }) }), en.changes).at(-1)).toBe(
      `Its inventory time did not move, so this came from Jamf's copy or from what LoonInspect reads: seen here between ${at(earlierCollection)} and ${at(COLLECTED)}.`
    );
  });

  it("no earlier observation stored, no window claimed", () => {
    const lines = answerLines(
      summary({
        total: 1,
        devicesTotal: 1,
        devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 1 }],
        when: when({ previousObservedAt: null, previousCollectedAt: null, deviceTimeMoved: false })
      }),
      en.changes
    );
    expect(lines).toEqual(["1 computer, 1 change.", `Observed ${at(OBSERVED)}.`, `KY4QVD7430 — Kyle’s Mac mini · added 1 · ${at(OBSERVED)}`]);
  });

  it("an answer that is only groups still says when", () => {
    expect(answerLines(summary({ total: 1, otherSubjects: 1, when: when({ previousObservedAt: null, previousCollectedAt: null, deviceTimeMoved: false }) }), en.changes)).toEqual([
      "1 change on groups or definitions, none on computers.",
      `Observed ${at(OBSERVED)}.`
    ]);
  });

  it("German states when in German", () => {
    const [, observed, window] = answerLines(
      summary({ total: 1, devicesTotal: 1, devices: [{ ...macMini, subjectId: "7", serial: "KY4QVD7430", added: 1 }], when: when() }),
      de.changes
    );
    expect(observed).toBe(`Beobachtet ${at(OBSERVED)}.`);
    expect(window).toBe(`Die Inventarisierung davor, ${at(EARLIER)}, zeigte diese Änderung nicht, sie geschah also zwischen beiden.`);
  });
});

describe("bannerKind — the handoff's showBanner states", () => {
  it("a question the filters cannot answer, whatever else the body holds", () => {
    expect(bannerKind(INVALID)).toBe("invalid");
    // Never the readback: that would say "Showing all changes" over a page that ran nothing.
    expect(bannerKind({ ...INVALID, filters: { ...NEW_INSTALLS } })).toBe("invalid");
    expect(bannerKind(INVALID, true)).toBe("invalid");
    expect(en.changes.prompt.invalid).toBe("Invalid question — the Prompt bar can't answer it, so nothing was run.");
    expect(de.changes.prompt.invalid).toBe(
      "Ungültige Frage – die Prompt-Leiste kann sie nicht beantworten, daher wurde nichts ausgeführt."
    );
  });

  it("an endpoint failure", () => {
    expect(bannerKind(result({ outcome: "error", filters: null, error: { kind: "unreachable", message: "x", status: null } }))).toBe(
      "error"
    );
  });

  it("an answer that was not filter settings", () => {
    expect(bannerKind(result({ outcome: "unparseable", filters: null }))).toBe("unparseable");
  });

  it("applied with nothing to apply never claims 'all changes'", () => {
    expect(bannerKind(result({ filters: null }))).toBe("unparseable");
  });

  it("the controls answered a narrower question", () => {
    expect(bannerKind(result({ unsupported: "Cannot express 'but not' — run the second filter separately." }))).toBe(
      "unsupported"
    );
  });

  it("otherwise, the readback", () => {
    expect(bannerKind(result())).toBe("readback");
    expect(bannerKind(result({ unsupported: "" }))).toBe("readback");
  });

  it("a proposal until it is applied, then the answer it is", () => {
    const proposal = result({ outcome: "proposed", repairs: [WIDENED_SECTION], widening: [WIDENED_SECTION] });
    expect(bannerKind(proposal)).toBe("proposal");
    expect(bannerKind(proposal, false)).toBe("proposal");
    expect(bannerKind(proposal, true)).toBe("readback");
    expect(bannerKind({ ...proposal, unsupported: "Cannot express 'but not'." }, true)).toBe("unsupported");
    // A proposal with nothing to propose applied nothing either.
    expect(bannerKind({ ...proposal, filters: null })).toBe("unparseable");
  });

  it("an applied answer is never a proposal, whatever the flag says", () => {
    expect(bannerKind(result(), false)).toBe("readback");
  });
});

describe("a proposal is not applied: a person applies it (ruled 1C, #436)", () => {
  const proposal = result({
    outcome: "proposed",
    filters: { ...NEW_INSTALLS },
    repairs: [WIDENED_SECTION, "Ignored 1 field the Prompt bar does not use."],
    widening: [WIDENED_SECTION]
  });

  it("an applied answer moves the page on arrival; a proposal does not", () => {
    expect(filtersOnArrival(result())).toEqual(filtersFromPrompt(WIRESHARK));
    expect(filtersOnArrival(proposal)).toBeNull();
  });

  it("an endpoint failure or an answer that was not filters moves nothing", () => {
    expect(filtersOnArrival(result({ outcome: "error", filters: null }))).toBeNull();
    expect(filtersOnArrival(result({ outcome: "unparseable", filters: null }))).toBeNull();
    // "What model are you?" used to arrive as every filter unset, the whole log, and run.
    expect(filtersOnArrival(INVALID)).toBeNull();
    expect(proposedFilters(INVALID)).toBeNull();
    expect(filtersOnArrival(result({ filters: null }))).toBeNull();
  });

  it("its Apply button replaces the page's filters with the proposal's, as the bar always does", () => {
    const next = proposedFilters(proposal);
    expect(next).toEqual(filtersFromPrompt(NEW_INSTALLS));
    // Every other key named as cleared, so a device's feed does not stay under it.
    expect(next).toHaveProperty("subjectId", undefined);
    expect(next).toHaveProperty("page", 1);
  });

  it("nothing but a proposal has an Apply button to press", () => {
    expect(proposedFilters(result())).toBeNull();
    expect(proposedFilters({ ...proposal, filters: null })).toBeNull();
    expect(proposedFilters(result({ outcome: "error", filters: null }))).toBeNull();
  });

  it("the readback says what the filters would show, since nothing has run", () => {
    expect(readback(NEW_INSTALLS, en.changes, "proposed")).toBe("Would show changes in Applications, that were added");
    expect(readback({ q: null, artifact: null, level: null, section: null }, en.changes, "proposed")).toBe(
      "Would show all changes"
    );
    expect(readback({ ...WIRESHARK, change: "added" }, de.changes, "proposed")).toBe(
      "Angezeigt würden Änderungen mit dem Namen „Wireshark“, im Abschnitt Anwendungen, die hinzugefügt wurden"
    );
    expect(readback({ section: null }, de.changes, "proposed")).toBe("Angezeigt würden alle Änderungen");
    // And an answer on the page still reads as shown.
    expect(readback(NEW_INSTALLS, en.changes, "showing")).toBe(readback(NEW_INSTALLS, en.changes));
  });

  it("the lead says what happened and why, the next sentence what to do, in both languages", () => {
    expect(en.changes.prompt.proposalLead(1)).toBe(
      "The model's answer needed a correction that widens the search, so it was not applied."
    );
    expect(en.changes.prompt.proposalLead(2)).toBe(
      "The model's answer needed corrections that widen the search, so it was not applied."
    );
    expect(en.changes.prompt.proposalNext).toBe("Check the filters it would set, then apply them, or rephrase the question.");
    expect(en.changes.prompt.applyProposal).toBe("Apply these filters");
    expect(de.changes.prompt.proposalLead(1)).toBe(
      "Die Antwort des Modells brauchte eine Korrektur, die die Suche erweitert, und wurde deshalb nicht angewendet."
    );
    expect(de.changes.prompt.proposalLead(3)).toBe(
      "Die Antwort des Modells brauchte Korrekturen, die die Suche erweitern, und wurde deshalb nicht angewendet."
    );
    expect(de.changes.prompt.applyProposal).toBe("Diese Filter anwenden");
  });

  it("a proposal's caveat is said of filters not yet applied, in both languages", () => {
    // Shown before Apply: the caveat is part of what the operator checks.
    expect(en.changes.prompt.proposalCloseAsAllowed).toBe("These filters would be as close as these controls allow.");
    expect(de.changes.prompt.proposalCloseAsAllowed).toBe("Diese Filter wären so genau, wie diese Bedienelemente es erlauben.");
    const proposal = result({ outcome: "proposed", repairs: [WIDENED_SECTION], widening: [WIDENED_SECTION] });
    expect(bannerKind({ ...proposal, unsupported: "Cannot express 'but not'." }, false)).toBe("proposal");
  });
});

describe("the bar's own limits and names", () => {
  it("stops typing where the server stops reading", () => {
    expect(MAX_QUESTION_CHARS).toBe(500);
  });

  it("names the provider by its Settings › AI card, or by its id when unknown", () => {
    expect(providerLabel("apple_fm", en.ai.providerLabels)).toBe("Apple Foundation Models via Docker Desktop");
    expect(providerLabel("someday", en.ai.providerLabels)).toBe("someday");
  });

  it("no hint under the box: Kyle read 'the model never sees device data' as false beside the counts", () => {
    // The design is unchanged — the counts are Postgres's — but the sentence went (2026-09-15).
    expect("hint" in en.changes.prompt).toBe(false);
    expect("hint" in de.changes.prompt).toBe(false);
  });
});

describe("modelOptions — the Model picker, shown with one saved provider as with three", () => {
  const apple = { provider: "apple_fm" as const, model: "system" };
  const anthropic = { provider: "anthropic" as const, model: "claude-x" };

  it("one saved provider is still one option, so what answers is on screen", () => {
    expect(modelOptions([apple], en.ai.providerLabels)).toEqual([
      { value: "apple_fm", text: "Apple Foundation Models via Docker Desktop · system" }
    ]);
  });

  it("two saved: the server's order, the first the default", () => {
    expect(modelOptions([apple, anthropic], en.ai.providerLabels)).toEqual([
      { value: "apple_fm", text: "Apple Foundation Models via Docker Desktop · system" },
      { value: "anthropic", text: "Anthropic · claude-x" }
    ]);
  });

  it("a provider this page has no card for shows as its id", () => {
    expect(modelOptions([{ provider: "someday" as never, model: "m1" }], en.ai.providerLabels)).toEqual([
      { value: "someday", text: "someday · m1" }
    ]);
  });

  it("labelled Model, and German reads German", () => {
    expect(en.changes.prompt.model).toBe("Model");
    expect(de.changes.prompt.model).toBe("Modell");
    expect(modelOptions([apple], de.ai.providerLabels)[0].text).toBe("Apple Foundation Models über Docker Desktop · system");
  });
});

describe("hasSomethingToClear — the Changes page's Clear is enabled only when it has work", () => {
  const empty = { q: "", artifact: "" };

  it("the unfiltered first page, empty drafts, a Prompt bar not used: nothing", () => {
    expect(hasSomethingToClear({ page: 1 }, empty, false)).toBe(false);
    expect(hasSomethingToClear({}, empty, false)).toBe(false);
    // What `?q=` parses to: a key with nothing in it filters nothing.
    expect(hasSomethingToClear({ q: "", section: "", page: 1 }, empty, false)).toBe(false);
  });

  it("every filter the URL carries, the link-only ones included", () => {
    const one: Partial<ChangeFilters>[] = [
      { q: "KY4QVD7430" },
      { artifact: "Wireshark" },
      { level: "high" },
      { change: "added" },
      { section: "applications" },
      { minLevel: "normal" },
      { since: "2026-09-07T12:00:00.000Z" },
      { connectionId: 1 },
      { subjectId: "42" },
      { subjectKind: "computer" }
    ];
    for (const filter of one) expect(hasSomethingToClear({ ...filter, page: 1 }, empty, false)).toBe(true);
  });

  it("a page past the first, since Clear goes back to page 1", () => {
    expect(hasSomethingToClear({ page: 3 }, empty, false)).toBe(true);
  });

  it("text in either draft box, applied or not", () => {
    expect(hasSomethingToClear({}, { q: "Kyle", artifact: "" }, false)).toBe(true);
    expect(hasSomethingToClear({}, { q: "", artifact: "Steam" }, false)).toBe(true);
    expect(hasSomethingToClear({}, { q: " ", artifact: "" }, false)).toBe(true);
  });

  it("a Prompt bar used since the last Clear — a question asked, or only typed", () => {
    expect(hasSomethingToClear({}, empty, true)).toBe(true);
  });

  it("the words, in both languages", () => {
    expect(en.changes.clearAll).toBe("Clear");
    expect(en.changes.clearAllTitle).toBe("Clear every filter and the Prompt box");
    expect(de.changes.clearAll).toBe("Zurücksetzen");
    expect(de.changes.clearAllTitle).toBe("Alle Filter und das Prompt-Feld zurücksetzen");
  });
});

describe("apiRequest — a server that answered is never reported as one that did not", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // A 200 whose body starts and then stops: the connection went mid-stream.
  function cutOff(reason: unknown): Response {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"outcome":"appl'));
        controller.error(reason);
      }
    });
    return new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
  }

  function answering(response: () => Response | Promise<Response>) {
    vi.stubGlobal("fetch", vi.fn(async () => response()));
  }

  async function rejection(): Promise<unknown> {
    return apiRequest("/changes/prompt").then(
      () => null,
      (error: unknown) => error
    );
  }

  it("a body cut off mid-stream is ApiBodyError — it used to be fetch's TypeError, read as 'did not reach'", async () => {
    answering(() => cutOff(new TypeError("terminated")));
    const error = await rejection();
    expect(error).toBeInstanceOf(ApiBodyError);
    expect(error).not.toBeInstanceOf(TypeError);
    expect(error).not.toBeInstanceOf(ApiError);
    expect((error as ApiBodyError).status).toBe(200);
    expect(failureReason(error, en.changes.prompt)).toBe("the server's answer could not be read");
    expect(askFailureText(error, en.changes.prompt)).toBe(en.changes.prompt.askUnreadable);
  });

  it("a 200 that is not JSON is the same answered-but-unreadable", async () => {
    answering(() => new Response("<html>proxy page</html>", { status: 200, headers: { "Content-Type": "text/html" } }));
    const error = await rejection();
    expect(error).toBeInstanceOf(ApiBodyError);
    expect(readReply({ ok: false, error }, en.changes.prompt)).toEqual({ refusal: en.changes.prompt.askUnreadable });
  });

  it("a request that never got an answer is still fetch's own TypeError", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    const error = await rejection();
    expect(error).toBeInstanceOf(TypeError);
    expect(failureReason(error, en.changes.prompt)).toBe("this server did not answer");
  });

  it("an abort is the caller's, whenever it lands, and reaches the caller as it came", async () => {
    answering(() => cutOff(new DOMException("The operation was aborted.", "AbortError")));
    const error = await rejection();
    expect(error).not.toBeInstanceOf(ApiBodyError);
    expect((error as { name?: string }).name).toBe("AbortError");
  });

  it("everything else as before: a refusal is an ApiError, a 204 is nothing, JSON null is null", async () => {
    answering(() => new Response(JSON.stringify({ detail: "Type a question first." }), { status: 422 }));
    const refused = await rejection();
    expect(refused).toBeInstanceOf(ApiError);
    expect((refused as ApiError).detail).toBe("Type a question first.");

    answering(() => new Response(null, { status: 204 }));
    await expect(apiRequest("/system/ai/configs/apple_fm", { method: "GET" })).resolves.toBeUndefined();

    // Whether null is the answer is the caller's to judge (`isPromptResult`, `savedConfigsOf`).
    answering(() => new Response("null", { status: 200, headers: { "Content-Type": "application/json" } }));
    await expect(apiRequest("/changes/prompt")).resolves.toBeNull();
  });
});

describe("askFailureText — a question that got no answer says which way it failed", () => {
  const tp = en.changes.prompt;

  it("a refusal is the server's sentence, as written", () => {
    const sentence = "No AI provider is saved. An admin saves one in Settings › AI; then the Prompt bar can use it.";
    expect(askFailureText(new ApiError(409, sentence), tp)).toBe(sentence);
  });

  it("only a request that never arrived says the question did not reach this server", () => {
    expect(askFailureText(new TypeError("Failed to fetch"), tp)).toBe(
      "The question did not reach this server. Check that LoonInspect is running, then reload the page."
    );
  });

  it("a status with no reason — a plain-text 500, a proxy's 502 or 504 — names the status and the log", () => {
    for (const status of [500, 502, 504]) {
      expect(askFailureText(new ApiError(status, null), tp)).toBe(
        `The server answered ${status} without a reason. Check docker compose logs app for the error.`
      );
    }
  });

  it("an answer that was not JSON is neither of those", () => {
    expect(askFailureText(new SyntaxError("Unexpected token '<'"), tp)).toBe(
      "The server answered, but not in a form this page can read. Check docker compose logs app for the error."
    );
  });

  it("German says it in German", () => {
    expect(askFailureText(new ApiError(502, null), de.changes.prompt)).toBe(
      "Der Server hat mit 502 ohne Begründung geantwortet. Den Fehler nennt docker compose logs app."
    );
  });
});

describe("failureReason — a failed read, as the clause its sentence goes on from", () => {
  const tp = en.changes.prompt;

  it("the Prompt bar's status read: what failed, then where to look", () => {
    expect(tp.statusFailed(failureReason(new ApiError(500, null), tp))).toBe(
      "The Prompt bar could not check its settings: the server answered 500 without a reason. Check docker compose logs app."
    );
    expect(tp.statusFailed(failureReason(new TypeError("Load failed"), tp))).toBe(
      "The Prompt bar could not check its settings: this server did not answer. Check docker compose logs app."
    );
  });

  it("the server's own words, without a full stop the sentence would double", () => {
    expect(failureReason(new ApiError(404, "Not Found"), tp)).toBe("Not Found");
    expect(failureReason(new ApiError(409, "No saved config for anthropic."), tp)).toBe("No saved config for anthropic");
  });

  it("never the browser's own message", () => {
    expect(failureReason(new SyntaxError("Unexpected end of JSON input"), tp)).toBe("the server's answer could not be read");
  });

  it("a body that arrived but was not the shape the read promises is unreadable, never 'did not answer'", () => {
    expect(failureReason(null, tp)).toBe("the server's answer could not be read");
    expect(tp.statusFailed(failureReason(null, tp))).toBe(
      "The Prompt bar could not check its settings: the server's answer could not be read. Check docker compose logs app."
    );
  });

  it("Settings › AI's two reads fail in their own lines", () => {
    const reason = failureReason(new ApiError(500, null), tp);
    expect(en.ai.configsLoadFailed(reason)).toBe(
      "Could not read the saved providers: the server answered 500 without a reason. Check docker compose logs app."
    );
    expect(en.ai.promptStatusLoadFailed(reason)).toBe(
      "Could not read whether the Changes Prompt bar shows: the server answered 500 without a reason. Check docker compose logs app."
    );
  });
});

describe("replyDisposition — a reply moves the page only from where it was asked", () => {
  const changes = { pathname: "/devices/changes", search: "?section=applications" };

  it("the page as it was when asked: apply", () => {
    expect(replyDisposition(changes, { ...changes }, false, true)).toBe("apply");
    const bare = { pathname: "/devices/changes", search: "" };
    expect(replyDisposition(bare, { ...bare }, false, true)).toBe("apply");
  });

  it("aborted — the bar went away — or replaced by a newer question: drop", () => {
    expect(replyDisposition(changes, changes, true, true)).toBe("drop");
    expect(replyDisposition(changes, changes, false, false)).toBe("drop");
    // Even where the filters also moved: nobody is waiting for this one.
    expect(replyDisposition(changes, { ...changes, search: "" }, true, true)).toBe("drop");
  });

  it("the address bar already on another page while the Changes page is still mounted: drop", () => {
    // The race: a sidebar click to the Overview, and the reply lands inside the router's
    // transition. Applying it then resolved against the Changes route and pushed it back.
    expect(replyDisposition(changes, { pathname: "/", search: "" }, false, true)).toBe("drop");
    expect(replyDisposition(changes, { pathname: "/devices", search: "?section=applications" }, false, true)).toBe("drop");
  });

  it("the same page with the filters moved by hand while waiting: stale", () => {
    expect(replyDisposition(changes, { ...changes, search: "?section=applications&level=high" }, false, true)).toBe("stale");
    expect(replyDisposition(changes, { ...changes, search: "" }, false, true)).toBe("stale");
    expect(replyDisposition({ ...changes, search: "" }, changes, false, true)).toBe("stale");
  });

  it("the stale line says what happened, why, and what to do, in both languages", () => {
    expect(en.changes.prompt.staleReply).toBe(
      "The answer came back after the filters changed, so it was not applied. Ask again to apply it."
    );
    expect(de.changes.prompt.staleReply).toBe(
      "Die Antwort kam, nachdem sich die Filter geändert hatten, und wurde deshalb nicht angewendet. Stellen Sie die Frage erneut, um sie anzuwenden."
    );
  });
});

describe("isPromptResult — a 200's body is checked before anything reads it", () => {
  const withDevices = result({
    summary: summary({
      total: 1,
      devicesTotal: 1,
      devices: [
        { connectionId: 1, subjectId: "7", label: "Kyle’s Mac mini", serial: "KY4QVD7430", added: 1, removed: 0, updated: 0, changed: 0, lastObservedAt: "2026-09-14T16:57:26Z" }
      ],
      when: {
        observedAt: "2026-09-14T16:57:26Z",
        oldestObservedAt: "2026-09-14T16:57:26Z",
        collectedAt: "2026-09-14T16:57:56Z",
        previousObservedAt: "2026-09-14T00:33:16Z",
        previousCollectedAt: "2026-09-14T00:40:00Z",
        deviceTimeMoved: true
      }
    })
  });

  it("every shape the wire contract names", () => {
    expect(isPromptResult(result())).toBe(true);
    expect(isPromptResult(withDevices)).toBe(true);
    expect(isPromptResult(result({ outcome: "error", filters: null, error: { kind: "unreachable", message: "x", status: null } }))).toBe(true);
    expect(isPromptResult(result({ outcome: "unparseable", filters: null, error: { kind: "malformed", message: "x", status: 200 } }))).toBe(true);
    expect(isPromptResult(result({ unsupported: "Cannot express 'but not'.", repairs: ["dropped q"] }))).toBe(true);
    expect(isPromptResult(result({ outcome: "proposed", repairs: ["dropped q"], widening: ["dropped q"] }))).toBe(true);
    expect(isPromptResult(INVALID)).toBe(true);
  });

  it("a key it does not know is left alone", () => {
    expect(isPromptResult({ ...result(), futureKey: [1, 2] })).toBe(true);
  });

  // The times the box states (#443): a body without them would print "Invalid Date" over
  // the answer, so it is a body this page cannot read.
  it("filters without the dimension keys are not this shape", () => {
    const withoutModel = { ...WIRESHARK } as Record<string, unknown>;
    delete withoutModel.model;
    expect(isPromptResult(result({ filters: withoutModel as never }))).toBe(false);
    expect(isPromptResult(result({ filters: { ...WIRESHARK, managed: true } as never }))).toBe(false);
    expect(isPromptResult(result({ filters: { ...WIRESHARK, model: "MacBook Air" } }))).toBe(true);
  });

  it("a summary without the times is not this shape", () => {
    const body = withDevices.summary!;
    expect(isPromptResult(result({ summary: { ...body, when: undefined } as never }))).toBe(false);
    expect(isPromptResult(result({ summary: { ...body, when: { ...body.when!, observedAt: 17 } } as never }))).toBe(false);
    expect(isPromptResult(result({ summary: { ...body, when: { ...body.when!, deviceTimeMoved: "yes" } } as never }))).toBe(false);
    expect(isPromptResult(result({ summary: { ...body, devices: [{ ...body.devices[0], lastObservedAt: undefined }] } as never }))).toBe(
      false
    );
    // A change with no observation before it: null, not missing.
    expect(isPromptResult(result({ summary: { ...body, when: { ...body.when!, previousObservedAt: null, previousCollectedAt: null } } }))).toBe(
      true
    );
  });

  it("not an object with a known outcome", () => {
    for (const body of [null, undefined, "applied", 42, [], {}, { outcome: 5 }, { outcome: "maybe" }]) {
      expect(isPromptResult(body)).toBe(false);
    }
    expect(isPromptResult({ ...result(), outcome: "later" })).toBe(false);
  });

  it("a field the bar or its answer box reads, in the wrong shape", () => {
    const bad: Record<string, unknown>[] = [
      { filters: undefined },
      { filters: "Wireshark" },
      { filters: { ...WIRESHARK, q: 7 } },
      { filters: { q: null, artifact: "Wireshark", level: null, section: "applications" } },
      { unsupported: { text: "x" } },
      { repairs: null },
      { repairs: ["ok", 3] },
      // The proposal's reason is read off it, so an older body without it is not the answer.
      { widening: undefined },
      { widening: "dropped q" },
      { widening: [{ text: "dropped q" }] },
      { summary: { total: 1 } },
      { summary: { ...withDevices.summary, devices: [{ connectionId: 1, subjectId: "7", label: null, serial: null }] } },
      { summary: { ...withDevices.summary, truncated: "no" } },
      // React cannot render an object as text; this one would have crashed the page.
      { model: { id: "system" } },
      { provider: null },
      { destination: undefined },
      { latencyMs: "412" },
      { latencyMs: Number.NaN },
      { error: { kind: "unreachable", message: "x", status: "504" } },
      { error: "unreachable" }
    ];
    for (const overrides of bad) expect(isPromptResult({ ...result(), ...overrides })).toBe(false);
  });
});

describe("readReply — only a rejected request is one that did not reach the server", () => {
  const tp = en.changes.prompt;

  it("the request's own rejection keeps askFailureText's reading", () => {
    expect(readReply({ ok: false, error: new TypeError("Failed to fetch") }, tp)).toEqual({ refusal: tp.askFailed });
    const sentence = "No AI provider is saved. An admin saves one in Settings › AI; then the Prompt bar can use it.";
    expect(readReply({ ok: false, error: new ApiError(409, sentence) }, tp)).toEqual({ refusal: sentence });
    expect(readReply({ ok: false, error: new ApiError(502, null) }, tp)).toEqual({ refusal: tp.askNoReason(502) });
    expect(readReply({ ok: false, error: new SyntaxError("Unexpected token '<'") }, tp)).toEqual({ refusal: tp.askUnreadable });
  });

  it("a 200 whose body is JSON null is unreadable — reading it used to throw a TypeError, reported as 'did not reach'", () => {
    // What the bar did before: read `outcome` off the body inside the same try, and send
    // whatever that threw to askFailureText.
    let thrown: unknown = null;
    try {
      void (null as unknown as { outcome: string }).outcome;
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(TypeError);
    expect(askFailureText(thrown, tp)).toBe(tp.askFailed);

    expect(readReply({ ok: true, body: null }, tp)).toEqual({ refusal: tp.askUnreadable });
    expect(tp.askUnreadable).toBe(
      "The server answered, but not in a form this page can read. Check docker compose logs app for the error."
    );
  });

  it("any other body that is not the answer is unreadable too", () => {
    for (const body of [{}, { outcome: "applied" }, "ok", [result()], { ...result(), repairs: "none" }]) {
      expect(readReply({ ok: true, body }, tp)).toEqual({ refusal: tp.askUnreadable });
    }
  });

  it("the answer, as it came", () => {
    const answer = result({ filters: { ...NEW_INSTALLS } });
    const read = readReply({ ok: true, body: answer }, tp);
    expect(read).toEqual({ result: answer });
    expect("result" in read && read.result).toBe(answer);
  });

  it("German says it in German", () => {
    expect(readReply({ ok: true, body: null }, de.changes.prompt)).toEqual({ refusal: de.changes.prompt.askUnreadable });
  });
});

describe("isPromptStatus — the bar's status read is checked the same way", () => {
  const status = { available: true, reason: null, providers: [{ provider: "apple_fm", model: "system" }] };

  it("the shapes the wire contract names", () => {
    expect(isPromptStatus(status)).toBe(true);
    expect(isPromptStatus({ available: false, reason: "no_provider", providers: [] })).toBe(true);
    expect(isPromptStatus({ available: false, reason: "consent_off", providers: status.providers })).toBe(true);
  });

  it("anything else", () => {
    for (const body of [null, [], {}, "ok"]) expect(isPromptStatus(body)).toBe(false);
    expect(isPromptStatus({ ...status, available: "yes" })).toBe(false);
    expect(isPromptStatus({ ...status, reason: "maintenance" })).toBe(false);
    expect(isPromptStatus({ ...status, providers: null })).toBe(false);
    expect(isPromptStatus({ ...status, providers: [{ provider: "apple_fm" }] })).toBe(false);
  });
});
