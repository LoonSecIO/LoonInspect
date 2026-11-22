// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { apiRequest } from "@/config/api";
import { HistoricalUsage } from "./HistoricalUsage";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn(), setUnauthorizedHandler: vi.fn() }));
afterEach(cleanup);
it("labels the reported model and partial token coverage separately from logical jobs", async () => {
  vi.mocked(apiRequest).mockResolvedValue({
    firstMeasured: "2026-11-01",
    retentionDays: 90,
    pending: 0,
    oldestPendingSeconds: null,
    calls: [
      {
        feature: "inventory_summary",
        provider: "local",
        requested: "alias",
        reported: "gemma",
        outcome: "answered",
        events: 2,
        request_ms: 300,
        input_tokens: 50,
        input_reports: 1,
        output_tokens: 0,
        output_reports: 0,
        cached_tokens: 0,
        cache_reports: 0,
        provider_ms: 0,
        provider_reports: 0
      }
    ],
    queue: [{ day: "2026-11-01", provider: "local", outcome: "expired", events: 1, max_queue_wait_ms: 0 }]
  });
  render(
    <LocaleProvider>
      <HistoricalUsage />
    </LocaleProvider>
  );
  expect(await screen.findByText("alias → gemma")).toBeDefined();
  expect(screen.getByText("50 (1/2)")).toBeDefined();
  expect(screen.getAllByText("Unknown")).toHaveLength(3);
  expect(screen.getByText("expired")).toBeDefined();
});
