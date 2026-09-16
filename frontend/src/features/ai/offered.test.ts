/** Which cards Settings › AI offers, and what an unsaved one fills in (#404). */

import { describe, expect, it } from "vitest";
import type { HostDetection, Provider, ProviderEntry } from "@/features/ai/api";
import { localDefaultWithheld, offeredProviders, providerDefaults } from "@/features/ai/offered";

/** The three entries as `GET /api/system/ai/providers` sends them (`app/core/ai.py`). */
const ENTRIES: Record<Provider, Pick<ProviderEntry, "baseUrl" | "model">> = {
  apple_fm: { baseUrl: "http://host.docker.internal:1976/v1", model: "system" },
  openai_compatible: { baseUrl: "http://host.docker.internal:11434/v1", model: "qwen3.5:2b-mlx" },
  anthropic: { baseUrl: "https://api.anthropic.com", model: "claude-fable-5-1" }
};

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

/**
 * The six shapes `GET /api/system/ai/host` returns, named as the issue named them. Two are
 * measured: the fourth is this Mac's own reading (2026-09-05), and the sixth is the AWS pod
 * reproduced on 2026-09-12 by running the app image with `--dns 9.9.9.9`, which read
 * `runtime: docker_desktop`, `host_os: macos` with the alias dead — the second shape.
 */
const SHAPES = {
  dockerDesktopMacAliasUp: reading({
    runtime: "docker_desktop",
    hostOs: "macos",
    appleSilicon: true,
    aliasResolves: true,
    dockerDesktopOnMacos: true
  }),
  dockerDesktopMacAliasDead: reading({
    runtime: "docker_desktop",
    hostOs: "macos",
    appleSilicon: true,
    aliasResolves: false,
    dockerDesktopOnMacos: true
  }),
  dockerDesktopHostUnknown: reading({ runtime: "docker_desktop", aliasResolves: true }),
  orbstackAppleSilicon: reading({ runtime: "orbstack", hostOs: "macos", appleSilicon: true, aliasResolves: true }),
  unknownAliasUp: reading({ aliasResolves: true }),
  unknownAliasDead: reading({})
} as const;

type ShapeName = keyof typeof SHAPES;

describe("offeredProviders — the Apple card only where its default can work", () => {
  const cases: [ShapeName, readonly Provider[]][] = [
    // Both halves of the reach hold: Docker Desktop on an Apple Silicon Mac, and the
    // container can resolve the name it reaches the Mac by. The only shape with three.
    ["dockerDesktopMacAliasUp", ["apple_fm", "openai_compatible", "anthropic"]],
    // The Mac is right and the name is dead. `fm serve` is on the Mac, so the card cannot
    // work — the full match alone never proved that it could.
    ["dockerDesktopMacAliasDead", ["openai_compatible", "anthropic"]],
    // Docker Desktop with no Apple implementer: an Intel Mac, or Windows.
    ["dockerDesktopHostUnknown", ["openai_compatible", "anthropic"]],
    // A Mac, but not the one runtime this cut implements.
    ["orbstackAppleSilicon", ["openai_compatible", "anthropic"]],
    // Linux compose: `docker-compose.yml` declares the alias, so it resolves.
    ["unknownAliasUp", ["openai_compatible", "anthropic"]],
    // The pod: ECS on Fargate, nothing answering to the alias. Kyle's ruling.
    ["unknownAliasDead", ["openai_compatible", "anthropic"]]
  ];

  it.each(cases)("%s", (shape, expected) => {
    expect(offeredProviders(SHAPES[shape])).toEqual(expected);
  });

  it("no reading yet: nothing proves the card can work, so it is not offered", () => {
    expect(offeredProviders(null)).toEqual(["openai_compatible", "anthropic"]);
  });

  it("the two cards that need no local endpoint are offered everywhere", () => {
    for (const shape of Object.values(SHAPES)) {
      expect(offeredProviders(shape)).toContain("openai_compatible");
      expect(offeredProviders(shape)).toContain("anthropic");
    }
  });
});

describe("providerDefaults — no local default where the alias does not resolve", () => {
  const filled: [ShapeName, boolean][] = [
    ["dockerDesktopMacAliasUp", true],
    ["dockerDesktopMacAliasDead", false],
    ["dockerDesktopHostUnknown", true],
    ["orbstackAppleSilicon", true],
    ["unknownAliasUp", true],
    ["unknownAliasDead", false]
  ];

  it.each(filled)("%s: the OpenAI-compatible card fills its Ollama pair = %s", (shape, fills) => {
    expect(providerDefaults(ENTRIES.openai_compatible, SHAPES[shape])).toEqual(
      fills ? { baseUrl: "http://host.docker.internal:11434/v1", model: "qwen3.5:2b-mlx" } : { baseUrl: "", model: "" }
    );
  });

  it.each(filled)("%s: the Anthropic card is untouched (%s)", (shape) => {
    expect(providerDefaults(ENTRIES.anthropic, SHAPES[shape])).toEqual({
      baseUrl: "https://api.anthropic.com",
      model: "claude-fable-5-1"
    });
  });

  it("the Apple card's own pair goes the same way, on the one shape that still offers it", () => {
    expect(providerDefaults(ENTRIES.apple_fm, SHAPES.dockerDesktopMacAliasUp)).toEqual({
      baseUrl: "http://host.docker.internal:1976/v1",
      model: "system"
    });
    expect(providerDefaults(ENTRIES.apple_fm, SHAPES.dockerDesktopMacAliasDead)).toEqual({ baseUrl: "", model: "" });
  });

  it("no reading yet: nothing proves the default cannot work, so it is left alone", () => {
    expect(providerDefaults(ENTRIES.openai_compatible, null)).toEqual({
      baseUrl: "http://host.docker.internal:11434/v1",
      model: "qwen3.5:2b-mlx"
    });
    expect(localDefaultWithheld(ENTRIES.openai_compatible, null)).toBe(false);
  });

  it("the alias the reading names is the one compared, not a name compiled in", () => {
    // A reading whose alias is something else leaves a `host.docker.internal` default
    // alone: it is that reading's alias that failed to resolve, not this one.
    const other = reading({ alias: "gateway.docker.internal", aliasResolves: false });
    expect(localDefaultWithheld(ENTRIES.openai_compatible, other)).toBe(false);
    expect(localDefaultWithheld({ baseUrl: "http://gateway.docker.internal:11434/v1" }, other)).toBe(true);
  });

  it("only the two cards written against the alias can be withheld", () => {
    expect(localDefaultWithheld(ENTRIES.anthropic, SHAPES.unknownAliasDead)).toBe(false);
    expect(localDefaultWithheld(ENTRIES.apple_fm, SHAPES.unknownAliasDead)).toBe(true);
    expect(localDefaultWithheld(ENTRIES.openai_compatible, SHAPES.unknownAliasDead)).toBe(true);
  });
});
