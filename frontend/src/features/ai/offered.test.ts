/** Which cards Settings › AI offers, and what an unsaved one fills in (#404, #474). */

import { describe, expect, it } from "vitest";
import type { HostDetection, Provider, ProviderEntry, SavedConfig } from "@/features/ai/api";
import { localDefaultWithheld, offeredProviders, providerDefaults } from "@/features/ai/offered";
import type { SavedByProvider } from "@/features/ai/savedState";

/** The three entries as `GET /api/system/ai/providers` sends them (`app/core/ai.py`). */
const ENTRIES: Record<Provider, Pick<ProviderEntry, "baseUrl" | "model">> = {
  apple_fm: { baseUrl: "http://host.docker.internal:1976/v1", model: "system" },
  openai_compatible: { baseUrl: "http://host.docker.internal:11434/v1", model: "qwen3.5:2b-mlx" },
  anthropic: { baseUrl: "https://api.anthropic.com", model: "claude-fable-5-1" }
};

const OLLAMA = ENTRIES.openai_compatible;
const EMPTY = { baseUrl: "", model: "" };
const WITHOUT_APPLE: readonly Provider[] = ["openai_compatible", "anthropic"];
const ALL: readonly Provider[] = ["apple_fm", "openai_compatible", "anthropic"];

/** A card as `GET /api/system/ai/configs` sends it. Only its presence decides the list. */
function config(provider: Provider): SavedConfig {
  return {
    provider,
    hostReach: provider === "apple_fm" ? "docker_desktop" : "custom",
    baseUrl: ENTRIES[provider].baseUrl,
    model: ENTRIES[provider].model,
    reasoningEffort: null,
    hasKey: false,
    updatedAt: "2026-09-16T12:00:00Z",
    updatedBy: "admin"
  };
}

const NONE_SAVED: SavedByProvider = {};
const APPLE_SAVED: SavedByProvider = { apple_fm: config("apple_fm") };
const ANTHROPIC_SAVED: SavedByProvider = { anthropic: config("anthropic") };

function reading(overrides: Partial<HostDetection>): HostDetection {
  return {
    runtime: "unknown",
    hostOs: "unknown",
    appleSilicon: false,
    alias: "host.docker.internal",
    aliasResolves: false,
    dockerDesktopOnMacos: false,
    evidence: {},
    ...overrides
  };
}

const mac = { runtime: "docker_desktop", hostOs: "macos", appleSilicon: true, dockerDesktopOnMacos: true };

/**
 * The six readings `GET /api/system/ai/host` returns, and both decisions over each. Two are
 * measured: the first is this Mac's own reading (2026-09-05), and the last is the AWS pod,
 * reproduced 2026-09-12 by running the app image with `--dns 9.9.9.9`. The same run read
 * `runtime: docker_desktop, host_os: macos` with the alias dead — the second row — which is
 * why the full match alone is no longer enough to offer the card.
 */
const SHAPES: [string, HostDetection, readonly Provider[], { baseUrl: string; model: string }][] = [
  // Both halves of the reach hold: an Apple Silicon Mac under Docker Desktop, and the name
  // the container gets to it by. The only row that offers three cards.
  ["Docker Desktop on a Mac, alias resolving", reading({ ...mac, aliasResolves: true }), ALL, OLLAMA],
  // The Mac is right and the name is dead. `fm serve` runs on the Mac, so the card cannot
  // work — and neither can the Ollama pair the other card used to fill in.
  ["Docker Desktop on a Mac, alias dead", reading(mac), WITHOUT_APPLE, EMPTY],
  // Docker Desktop with no Apple implementer: an Intel Mac, or Windows.
  ["Docker Desktop, host OS unknown", reading({ runtime: "docker_desktop", aliasResolves: true }), WITHOUT_APPLE, OLLAMA],
  // A Mac, but not the one runtime this cut implements.
  ["OrbStack on Apple Silicon", reading({ ...mac, runtime: "orbstack", dockerDesktopOnMacos: false, aliasResolves: true }), WITHOUT_APPLE, OLLAMA],
  // Linux compose: `docker-compose.yml` declares the alias, so it resolves.
  ["unknown runtime, alias resolving", reading({ aliasResolves: true }), WITHOUT_APPLE, OLLAMA],
  // The pod: ECS on Fargate, nothing answering to the alias. Kyle's ruling.
  ["unknown runtime, alias dead", reading({}), WITHOUT_APPLE, EMPTY]
];

describe("the Apple card only where its default can work, and no local default where the alias is dead", () => {
  it.each(SHAPES)("%s", (_name, detection, offered, defaults) => {
    expect(offeredProviders(detection, NONE_SAVED)).toEqual(offered);
    expect(providerDefaults(ENTRIES.openai_compatible, detection)).toEqual(defaults);
    // The Apple card's pair is written against the same alias, so it goes the same way —
    // which is a different question from whether the card is offered at all.
    expect(providerDefaults(ENTRIES.apple_fm, detection)).toEqual(defaults === EMPTY ? EMPTY : ENTRIES.apple_fm);
  });

  it("the Anthropic card is offered everywhere and never re-filled: its default is a public endpoint", () => {
    for (const [, detection] of SHAPES) {
      expect(offeredProviders(detection, NONE_SAVED)).toContain("anthropic");
      expect(providerDefaults(ENTRIES.anthropic, detection)).toEqual(ENTRIES.anthropic);
      expect(localDefaultWithheld(ENTRIES.anthropic, detection)).toBe(false);
    }
  });

  it("no reading yet: no card is offered that nothing proves works, and no default is taken away", () => {
    expect(offeredProviders(null, NONE_SAVED)).toEqual(WITHOUT_APPLE);
    expect(providerDefaults(ENTRIES.openai_compatible, null)).toEqual(OLLAMA);
    expect(localDefaultWithheld(ENTRIES.openai_compatible, null)).toBe(false);
  });

  it("the alias the reading names is the one compared, not a name compiled in", () => {
    // It is that reading's alias that failed to resolve, so a default written against
    // another name is left alone.
    const other = reading({ alias: "gateway.docker.internal" });
    expect(localDefaultWithheld(ENTRIES.openai_compatible, other)).toBe(false);
    expect(localDefaultWithheld({ baseUrl: "http://gateway.docker.internal:11434/v1" }, other)).toBe(true);
  });
});

/**
 * #474. The pod reading is the one that matters: an `apple_fm` row restored from a Mac onto
 * a server that cannot reach a Mac keeps its card, because **Remove** is on the card and
 * the Changes Prompt bar dials what is saved wherever this runs.
 */
describe("a card this server holds settings for is offered, whatever the reading says", () => {
  const POD = reading({});
  const MAC = reading({ ...mac, aliasResolves: true });

  it.each<[string, HostDetection | null, SavedByProvider, readonly Provider[]]>([
    // The restored row, on the reading that withholds the card on its own.
    ["the pod's reading, apple_fm saved here", POD, APPLE_SAVED, ALL],
    // The same reading, nothing saved: the card stays off, as #404 cut it.
    ["the pod's reading, nothing saved", POD, NONE_SAVED, WITHOUT_APPLE],
    // A saved card under a reading that already offers it changes nothing.
    ["Docker Desktop on a Mac with the alias up, apple_fm saved here", MAC, APPLE_SAVED, ALL],
    // It is the `apple_fm` row that is read, not whether anything at all is saved.
    ["the pod's reading, another card saved", POD, ANTHROPIC_SAVED, WITHOUT_APPLE]
  ])("%s", (_name, detection, saved, offered) => {
    expect(offeredProviders(detection, saved)).toEqual(offered);
  });

  it("a saved card is still not defaults: what the card fills in follows the reading alone", () => {
    // The pod's Apple card opens on what was saved for it (`fillCard`), never on a
    // `host.docker.internal` default this container has just been told does not resolve.
    expect(providerDefaults(ENTRIES.apple_fm, POD)).toEqual(EMPTY);
    expect(localDefaultWithheld(ENTRIES.apple_fm, POD)).toBe(true);
  });
});
