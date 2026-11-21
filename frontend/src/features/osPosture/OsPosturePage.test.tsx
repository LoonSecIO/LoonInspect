// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { OsPosturePage } from "./OsPosturePage";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn(), setUnauthorizedHandler: vi.fn() }));
afterEach(cleanup);
it("drills from an adoption bar to the same UTC day, version and Mac history", async () => {
  vi.mocked(apiRequest).mockResolvedValue({
    asOf: "2026-11-01",
    target: "26",
    targets: ["26"],
    total: 1,
    releases: [{ version: "15.7", released: "2026-11-03" }],
    eligibilityCounts: { compatible: 1 },
    series: [{ day: "2026-11-03", freshEvidence: true, counts: { "15.7": 1 } }],
    devices: [
      {
        id: 23,
        name: "Design Mac",
        version: "15.7",
        build: "24G1",
        latest: "15.7",
        model: "Mac13,1",
        patch: "current",
        eligibility: "compatible",
        observed: "2026-11-03"
      }
    ]
  });
  render(
    <LocaleProvider>
      <MemoryRouter>
        <OsPosturePage />
      </MemoryRouter>
    </LocaleProvider>
  );
  fireEvent.click(await screen.findByRole("button", { name: "2026-11-03 · 15.7 · 1" }));
  await waitFor(() => {
    const last = String(vi.mocked(apiRequest).mock.lastCall?.[0]);
    const p = new URL(last, "http://test.local").searchParams;
    expect([p.get("day"), p.get("version")]).toEqual(["2026-11-03", "15.7"]);
  });
  expect((await screen.findByRole("link", { name: "Design Mac" })).getAttribute("href")).toBe("/devices/23");
});
