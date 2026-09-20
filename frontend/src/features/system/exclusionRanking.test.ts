import { afterEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { getExclusionRankingStatus, rankExclusionCandidates } from "./api";
import { en } from "@/i18n/en";
import { de } from "@/i18n/de";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn() }));
afterEach(() => vi.clearAllMocks());

describe("local exclusion ranking", () => {
  it("requests ranking separately from the audited settings save and sends no inventory labels", async () => {
    vi.mocked(apiRequest).mockResolvedValue({});
    await getExclusionRankingStatus();
    await rankExclusionCandidates("apple_fm", ["com.acme.*"]);
    expect(apiRequest).toHaveBeenCalledTimes(2);
    expect(apiRequest).toHaveBeenNthCalledWith(1, "/system/data-sharing/exclusion-ranking");
    expect(apiRequest).toHaveBeenNthCalledWith(2, "/system/data-sharing/exclusion-ranking", {
      method: "POST", json: { provider: "apple_fm", globs: ["com.acme.*"] }
    });
  });

  it("labels every closed classification as an estimate in both languages", () => {
    for (const copy of [en.system.sharing, de.system.sharing]) {
      expect(Object.keys(copy.rankingLabels)).toEqual(["likely_in_house", "uncertain", "likely_public"]);
      for (const label of Object.values(copy.rankingLabels)) {
        expect(label).toMatch(/^(AI estimate|KI-Einschätzung):/);
      }
      expect(copy.rankingResult("local-model", "http://127.0.0.1:1976")).toContain("local-model");
    }
  });
});
