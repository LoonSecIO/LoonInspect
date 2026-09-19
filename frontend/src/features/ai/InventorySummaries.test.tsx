import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  InventorySummaryFields,
  InventorySummaryMetricsView,
} from "./InventorySummaries";
import {
  loadSummarySettings,
  saveSummarySettings,
} from "./inventorySummaryApi";
import type { SummaryMetrics } from "./inventorySummaryApi";
import { apiRequest } from "@/config/api";
import { en } from "@/i18n/en";
import { de } from "@/i18n/de";
vi.mock("@/config/api", () => ({ apiRequest: vi.fn(), setUnauthorizedHandler: vi.fn() }));
afterEach(() => vi.clearAllMocks());
const options = {
  enabled: true,
  provider: "apple_fm",
  preprompt: "<script>untrusted</script>",
  intervalSeconds: 2,
};
const empty: SummaryMetrics = {
  enabled: true,
  provider: "apple_fm",
  counts: {},
  attempts: 0,
  overloadJobs: 0,
  averageLatencyMs: null,
  dropRate: null,
  successRate: null,
  oldestQueuedAt: null,
  asOf: "2026-09-19T12:00:00Z",
  reasons: [],
};
describe("inventory summary presentation and API", () => {
  it("uses the shared client's relative path and saves the explicit provider", async () => {
    vi.mocked(apiRequest).mockResolvedValue(options);
    await loadSummarySettings();
    await saveSummarySettings(options);
    expect(apiRequest).toHaveBeenCalledWith("/inventory-summaries/settings");
    expect(apiRequest).toHaveBeenCalledWith("/inventory-summaries/settings", {
      method: "PUT",
      json: options,
    });
  });
  it("renders German labels, enforced limits and a disabled read-only form with escaped customer text", () => {
    const html = renderToStaticMarkup(
      <InventorySummaryFields
        value={options}
        setValue={() => {}}
        canWrite={false}
        busy={false}
        save={() => {}}
        copy={de.ai.inventorySummary}
      />,
    );
    expect(html).toContain("Inventar-Zusammenfassungen aktivieren");
    expect(html).toContain('disabled=""');
    expect(html).toContain('maxLength="500"');
    expect(html).toContain('min="1"');
    expect(html).toContain('max="60"');
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain('value="apple_fm" selected=""');
  });
  it("does not turn absent samples into successful percentages", () => {
    const html = renderToStaticMarkup(
      <InventorySummaryMetricsView
        value={empty}
        failed={false}
        copy={en.ai.inventorySummary}
        locale="en"
      />,
    );
    expect(html).toContain("Apple FM");
    expect(html).toContain("—");
    expect(html).not.toContain("0%");
  });
  it("hides stale values on failure and surfaces actionable failure reasons on success", () => {
    const value = {
      ...empty,
      successRate: 0.75,
      reasons: [{ reason: "expired", count: 2, nextCheck: "Check queue age." }],
    };
    const failed = renderToStaticMarkup(
      <InventorySummaryMetricsView
        value={value}
        failed={true}
        copy={de.ai.inventorySummary}
        locale="de"
      />,
    );
    expect(failed).toContain("nicht verfügbar");
    expect(failed).not.toContain("75");
    const good = renderToStaticMarkup(
      <InventorySummaryMetricsView
        value={value}
        failed={false}
        copy={en.ai.inventorySummary}
        locale="en"
      />,
    );
    expect(good).toContain("Check queue age.");
  });
});
