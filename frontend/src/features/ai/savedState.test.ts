/** Settings › AI's saved cards: how a Remove moves them. Frontend lane (#285). */

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiBodyError, ApiError } from "@/config/api";
import { listConfigs, type Provider, type SavedConfig } from "@/features/ai/api";
import {
  PROVIDER_ORDER,
  REMOVED,
  byProvider,
  cardEffort,
  effortToSend,
  isSavedConfigList,
  openingCard,
  removeAnswer,
  removeLine,
  savedAfterAnswer,
  savedConfigsOf,
  statusAfterAnswer,
  statusLine,
  takesReasoningEffort,
  type RemoveAnswer,
  type SavedByProvider,
  type StatusReading
} from "@/features/ai/savedState";
import { failureReason } from "@/features/changes/prompt";
import type { PromptStatus } from "@/features/changes/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const ta = en.ai;

function config(provider: Provider, overrides: Partial<SavedConfig> = {}): SavedConfig {
  return {
    provider,
    hostReach: provider === "anthropic" ? "custom" : "docker_desktop",
    baseUrl: provider === "anthropic" ? "https://api.anthropic.com" : "http://host.docker.internal:1976/v1",
    model: provider === "anthropic" ? "claude-x" : "system",
    reasoningEffort: null,
    hasKey: provider === "anthropic",
    updatedAt: "2026-09-14T20:00:00Z",
    updatedBy: "admin@example.com",
    ...overrides
  } as SavedConfig;
}

const BOTH: SavedByProvider = byProvider([config("apple_fm"), config("anthropic")]);
const ANTHROPIC_ONLY: SavedByProvider = byProvider([config("anthropic")]);
const FAILED: RemoveAnswer = { kind: "failed", sentence: ta.configRemoveFailed };

/**
 * The page's own sequence in handleRemove, from these pieces: the map moves when the
 * DELETE is answered, then the re-read replaces it when it lands (readSaved sets the
 * server's list; a failed re-read leaves the map as it was), then the line is written.
 */
function removeFlow(before: SavedByProvider, provider: Provider, answer: RemoveAnswer, reread: SavedByProvider | null) {
  const answered = savedAfterAnswer(before, provider, answer);
  return { answered, final: reread ?? answered, line: removeLine(provider, answer, reread, ta) };
}

describe("removeAnswer — what a rejected DELETE said", () => {
  it("404: someone removed it first, so the goal is met", () => {
    expect(removeAnswer(new ApiError(404, "No saved config for apple_fm."), ta.configRemoveFailed)).toEqual({ kind: "absent" });
  });

  it("a refusal in the server's own words, as written", () => {
    expect(removeAnswer(new ApiError(409, "AI features are off."), ta.configRemoveFailed)).toEqual({
      kind: "failed",
      sentence: "AI features are off."
    });
  });

  it("a status with no reason, or no answer at all: the page's sentence", () => {
    expect(removeAnswer(new ApiError(500, null), ta.configRemoveFailed)).toEqual(FAILED);
    expect(removeAnswer(new TypeError("Failed to fetch"), ta.configRemoveFailed)).toEqual(FAILED);
  });
});

describe("savedAfterAnswer — the map as soon as the Remove is answered", () => {
  it("a 204 or a 404 takes the card away now, whatever the re-read does", () => {
    expect(savedAfterAnswer(BOTH, "apple_fm", REMOVED)).toEqual(ANTHROPIC_ONLY);
    expect(savedAfterAnswer(BOTH, "apple_fm", { kind: "absent" })).toEqual(ANTHROPIC_ONLY);
    // Without touching the map it was given.
    expect(BOTH.apple_fm).toBeDefined();
  });

  it("any other answer leaves the map for the re-read to settle", () => {
    expect(savedAfterAnswer(BOTH, "apple_fm", FAILED)).toBe(BOTH);
  });

  it("a card that was not in the map leaves it alone", () => {
    expect(savedAfterAnswer(ANTHROPIC_ONLY, "apple_fm", REMOVED)).toBe(ANTHROPIC_ONLY);
  });
});

describe("a Remove, start to finish — the map follows the server's latest known truth", () => {
  it("204, re-read fine: gone, and says so", () => {
    const flow = removeFlow(BOTH, "apple_fm", REMOVED, ANTHROPIC_ONLY);
    expect(flow.final).toEqual(ANTHROPIC_ONLY);
    expect(flow.line).toEqual({ notice: "Removed from this server.", error: null });
  });

  it("204, re-read failed: still gone — the server said so", () => {
    const flow = removeFlow(BOTH, "apple_fm", REMOVED, null);
    expect(flow.final).toEqual(ANTHROPIC_ONLY);
    expect(flow.line).toEqual({ notice: ta.removedNotice, error: null });
  });

  it("404 and the re-read failed: no Saved pill or Remove beside 'already removed'", () => {
    const flow = removeFlow(BOTH, "apple_fm", { kind: "absent" }, null);
    expect(flow.answered.apple_fm).toBeUndefined();
    expect(flow.final.apple_fm).toBeUndefined();
    expect(flow.line).toEqual({ notice: "These settings were already removed from this server.", error: null });
  });

  it("500 after the commit: the re-read finds it gone, so it was removed — not 'could not be removed'", () => {
    const flow = removeFlow(BOTH, "apple_fm", removeAnswer(new ApiError(500, null), ta.configRemoveFailed), ANTHROPIC_ONLY);
    expect(flow.answered).toBe(BOTH);
    expect(flow.final.apple_fm).toBeUndefined();
    expect(flow.line).toEqual({ notice: ta.removedNotice, error: null });
  });

  it("the connection dropped after the commit: the same", () => {
    const flow = removeFlow(BOTH, "apple_fm", removeAnswer(new TypeError("Failed to fetch"), ta.configRemoveFailed), {});
    expect(flow.final).toEqual({});
    expect(flow.line).toEqual({ notice: ta.removedNotice, error: null });
  });

  it("500 and the re-read still finds it: the error stands, and so does the card", () => {
    const flow = removeFlow(BOTH, "apple_fm", FAILED, BOTH);
    expect(flow.final.apple_fm).toBeDefined();
    expect(flow.line).toEqual({ notice: null, error: "The saved settings could not be removed." });
  });

  it("a refusal and the re-read failed: the refusal, and the card as last known", () => {
    const refused = removeAnswer(new ApiError(409, "AI features are off."), ta.configRemoveFailed);
    const flow = removeFlow(BOTH, "apple_fm", refused, null);
    expect(flow.final).toBe(BOTH);
    expect(flow.line).toEqual({ notice: null, error: "AI features are off." });
  });

  it("the re-read's own failure is its own line, in the reader's words", () => {
    expect(ta.configsLoadFailed(failureReason(new ApiError(500, null), en.changes.prompt))).toBe(
      "Could not read the saved providers: the server answered 500 without a reason. Check docker compose logs app."
    );
    expect(ta.configsLoadFailed(failureReason(null, en.changes.prompt))).toBe(
      "Could not read the saved providers: the server's answer could not be read. Check docker compose logs app."
    );
  });

  it("German says it in German", () => {
    expect(removeLine("apple_fm", FAILED, {}, de.ai)).toEqual({ notice: de.ai.removedNotice, error: null });
    expect(removeLine("apple_fm", { kind: "absent" }, null, de.ai)).toEqual({ notice: de.ai.alreadyRemoved, error: null });
  });
});

describe("the Prompt bar's status line — never a status the page no longer knows", () => {
  const shown: PromptStatus = {
    available: true,
    reason: null,
    providers: [
      { provider: "apple_fm", model: "system" },
      { provider: "anthropic", model: "claude-x" }
    ]
  };
  const reading: StatusReading = { status: shown };

  it("reads as it did before", () => {
    expect(statusLine(null, ta)).toBeNull();
    expect(statusLine(reading, ta)).toEqual({
      text: "Changes Prompt bar: shown (uses Apple Foundation Models via Docker Desktop unless a user picks another; 2 providers saved)",
      failed: false
    });
    expect(statusLine({ status: { available: true, reason: null, providers: [shown.providers[1]] } }, ta)?.text).toBe(
      "Changes Prompt bar: shown (uses Anthropic)"
    );
    expect(statusLine({ status: { available: false, reason: "no_provider", providers: [] } }, ta)?.text).toBe(
      "Changes Prompt bar: hidden — no provider is saved. Fill in a card and press Save."
    );
    expect(statusLine({ status: { available: false, reason: null, providers: [] } }, ta)?.text).toBe("Changes Prompt bar: hidden");
  });

  it("a Remove the server confirmed takes away a line naming that provider", () => {
    expect(statusAfterAnswer(reading, "apple_fm", REMOVED)).toBeNull();
    expect(statusAfterAnswer(reading, "apple_fm", { kind: "absent" })).toBeNull();
  });

  it("and leaves a line that does not name it, or a Remove that failed, alone", () => {
    const appleOnly: StatusReading = { status: { ...shown, providers: [shown.providers[0]] } };
    expect(statusAfterAnswer(appleOnly, "anthropic", REMOVED)).toBe(appleOnly);
    expect(statusAfterAnswer(reading, "apple_fm", FAILED)).toBe(reading);
    const failure: StatusReading = { failure: "x" };
    expect(statusAfterAnswer(failure, "apple_fm", REMOVED)).toBe(failure);
    expect(statusAfterAnswer(null, "apple_fm", REMOVED)).toBeNull();
  });

  it("the re-read failed: says the status could not be read, never 'shown (uses …)'", () => {
    // The page's sequence: the answer clears the line, the failed re-read replaces it.
    const answered = statusAfterAnswer(reading, "apple_fm", REMOVED);
    expect(statusLine(answered, ta)).toBeNull();
    const reread: StatusReading = { failure: ta.promptStatusLoadFailed(failureReason(new TypeError("Load failed"), en.changes.prompt)) };
    expect(statusLine(reread, ta)).toEqual({
      text: "Could not read whether the Changes Prompt bar shows: this server did not answer. Check docker compose logs app.",
      failed: true
    });
  });
});

describe("isSavedConfigList — the saved cards' read is checked before it is read", () => {
  it("a list of cards, or none", () => {
    expect(isSavedConfigList([config("apple_fm"), config("anthropic")])).toBe(true);
    expect(isSavedConfigList([])).toBe(true);
  });

  it("anything else is unreadable, never an empty list", () => {
    for (const body of [null, undefined, {}, { configs: [] }, "[]"]) expect(isSavedConfigList(body)).toBe(false);
    expect(isSavedConfigList([{ ...config("apple_fm"), hasKey: "no" }])).toBe(false);
    expect(isSavedConfigList([{ ...config("apple_fm"), model: null }])).toBe(false);
    expect(isSavedConfigList([null])).toBe(false);
  });
});

describe("savedConfigsOf — the configs read's body, checked before anything is read off it", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("the body the contract names", () => {
    expect(savedConfigsOf({ configs: [config("apple_fm"), config("anthropic")] })).toEqual([config("apple_fm"), config("anthropic")]);
    expect(savedConfigsOf({ configs: [] })).toEqual([]);
  });

  it("anything else is null, which the page reads as unreadable", () => {
    for (const body of [null, undefined, {}, [], [config("apple_fm")], { configs: "none" }, { configs: [{ provider: "apple_fm" }] }, "ok"]) {
      expect(savedConfigsOf(body)).toBeNull();
    }
  });

  it("a 200 whose body is JSON null settles with the body — it used to reject with a TypeError, read as 'did not answer'", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("null", { status: 200, headers: { "Content-Type": "application/json" } })));
    const body = await listConfigs();
    expect(body).toBeNull();
    // The page's own sequence (readSaved): not a list, so the unreadable line.
    expect(savedConfigsOf(body)).toBeNull();
    expect(ta.configsLoadFailed(failureReason(null, en.changes.prompt))).toBe(
      "Could not read the saved providers: the server's answer could not be read. Check docker compose logs app."
    );
  });

  it("a 200 whose body is cut off mid-stream is answered-but-unreadable too", async () => {
    const cut = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"configs":[{"prov'));
        controller.error(new TypeError("terminated"));
      }
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(cut, { status: 200 })));
    const error = await listConfigs().then(
      () => null,
      (rejected: unknown) => rejected
    );
    expect(error).toBeInstanceOf(ApiBodyError);
    expect(ta.configsLoadFailed(failureReason(error, en.changes.prompt))).toBe(
      "Could not read the saved providers: the server's answer could not be read. Check docker compose logs app."
    );
  });
});

describe("openingCard — the newest read of the saved cards wins the opening selection too", () => {
  const untouched = { newerRead: false, removeAsked: false, current: "apple_fm" as const };
  // The two card lists `offeredProviders` returns; its own table is in offered.test.ts.
  const ALL = PROVIDER_ORDER;
  const WITHOUT_APPLE: readonly Provider[] = ["openai_compatible", "anthropic"];

  it("the opening read still the newest: the first saved card, clean lines", () => {
    expect(openingCard({ ...untouched, latest: BOTH, offered: ALL })).toEqual({ card: "apple_fm", clearLines: true });
    expect(openingCard({ ...untouched, latest: ANTHROPIC_ONLY, offered: ALL })).toEqual({
      card: "anthropic",
      clearLines: true
    });
  });

  it("none saved (or none readable): the detection hint, among the cards it offers", () => {
    expect(openingCard({ ...untouched, latest: {}, offered: ALL }).card).toBe("apple_fm");
    expect(openingCard({ ...untouched, latest: {}, offered: WITHOUT_APPLE }).card).toBe("openai_compatible");
  });

  it("a saved card that is not offered here is not opened on (#404)", () => {
    // An Apple card saved on a Mac and restored onto a pod that does not offer it: opening
    // on it would light no card and leave no Remove to press. §14 says how to take it off.
    expect(openingCard({ ...untouched, latest: BOTH, offered: WITHOUT_APPLE })).toEqual({ card: "anthropic", clearLines: true });
    const appleOnly = byProvider([config("apple_fm")]);
    expect(openingCard({ ...untouched, latest: appleOnly, offered: WITHOUT_APPLE }).card).toBe("openai_compatible");
  });

  it("a Remove made while the slowest read was out: the page stays on its card and keeps the Remove's line", () => {
    // The page's sequence. The opening read (#1) returns both cards and lands first; the
    // host detection is still out. The Remove of the Apple card is answered 204, and its
    // re-read (#2) returns Anthropic alone. Then the detection lands, and the opening
    // selection runs — with read #2 the newest.
    let savedReads = 0;
    const openingReadNumber = ++savedReads;
    ++savedReads; // the Remove's re-read
    const latest = removeFlow(BOTH, "apple_fm", REMOVED, ANTHROPIC_ONLY).final;
    const opening = openingCard({
      newerRead: openingReadNumber !== savedReads,
      removeAsked: true,
      latest,
      current: "apple_fm",
      offered: ALL
    });
    // Not the opening read's first saved card (the removed Apple card), and not a jump to
    // Anthropic: the card the operator acted on, with "Removed from this server." kept.
    expect(opening).toEqual({ card: "apple_fm", clearLines: false });
    // Its fields come from the newest map — no saved Apple card, so the card's defaults.
    expect(latest.apple_fm).toBeUndefined();
    expect(removeLine("apple_fm", REMOVED, ANTHROPIC_ONLY, ta).notice).toBe("Removed from this server.");
  });

  it("either alone is enough: a newer read, or a Remove pressed before any re-read (its confirm open, its DELETE out)", () => {
    expect(openingCard({ ...untouched, newerRead: true, latest: ANTHROPIC_ONLY, offered: ALL })).toEqual({
      card: "apple_fm",
      clearLines: false
    });
    expect(openingCard({ ...untouched, removeAsked: true, latest: BOTH, current: "anthropic", offered: ALL })).toEqual({
      card: "anthropic",
      clearLines: false
    });
  });

  it("the cards in the order the page shows them", () => {
    expect(PROVIDER_ORDER).toEqual(["apple_fm", "openai_compatible", "anthropic"]);
  });
});

describe("the Apple card takes no reasoning effort — fm serve answers 400 to one", () => {
  it("offered on every card but Apple's", () => {
    expect(takesReasoningEffort("apple_fm")).toBe(false);
    expect(takesReasoningEffort("openai_compatible")).toBe(true);
    expect(takesReasoningEffort("anthropic")).toBe(true);
  });

  it("switching to the Apple card clears it, whatever an older save carried", () => {
    expect(cardEffort("apple_fm", config("apple_fm", { reasoningEffort: "low" }), null)).toBe("");
    expect(cardEffort("apple_fm", undefined, "none")).toBe("");
  });

  it("other cards open with what was saved, else the card's default", () => {
    expect(cardEffort("openai_compatible", config("openai_compatible", { reasoningEffort: "high" }), "none")).toBe("high");
    expect(cardEffort("openai_compatible", config("openai_compatible", { reasoningEffort: null }), "none")).toBe("");
    expect(cardEffort("openai_compatible", undefined, "none")).toBe("none");
    expect(cardEffort("anthropic", undefined, null)).toBe("");
  });

  it("never sent for Apple, on Send or Save: the key is left out of the body", () => {
    for (const chosen of ["", "none", "low", "high"]) expect(effortToSend("apple_fm", chosen)).toBeUndefined();
    expect(JSON.stringify({ provider: "apple_fm", reasoningEffort: effortToSend("apple_fm", "low") })).toBe('{"provider":"apple_fm"}');
  });

  it("elsewhere: blank is the endpoint's default (null), anything else as chosen", () => {
    expect(effortToSend("openai_compatible", "")).toBeNull();
    expect(effortToSend("openai_compatible", "none")).toBe("none");
    expect(effortToSend("anthropic", "high")).toBe("high");
  });
});
