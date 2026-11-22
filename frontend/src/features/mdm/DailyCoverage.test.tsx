// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, expect, it, vi } from "vitest";
import { apiRequest } from "@/config/api";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { DailyCoverage } from "./DailyCoverage";

vi.mock("@/config/api", () => ({ apiRequest: vi.fn(), setUnauthorizedHandler: vi.fn() }));
vi.mock("./RunLogPanel", () => ({ RunLogPanel: ({ jobId }: { jobId: string }) => <p>{jobId}</p> }));
afterEach(cleanup);
it("opens the covering poll for a change first recorded by a full crawl", async () => {
  vi.mocked(apiRequest).mockResolvedValue({
    complete: true,
    affectedMacs: 1,
    counts: { coveredMiss: 1 },
    polls: [],
    gaps: [],
    total: 1,
    rows: [
      {
        id: "span",
        change_id: 8,
        device: 2,
        hostname: "Mac Lab",
        section: "operating_system",
        field: "build",
        old_build: "A",
        build: "B",
        status: "coveredMiss",
        report_at: "10:07",
        discovered: "12:00",
        delaySeconds: 6780,
        poll: "poll-run"
      }
    ]
  });
  render(
    <LocaleProvider>
      <MemoryRouter>
        <DailyCoverage jobId="full-run" />
      </MemoryRouter>
    </LocaleProvider>
  );
  expect(vi.mocked(apiRequest)).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Daily coverage" }));
  expect((await screen.findByRole("link", { name: "Mac Lab" })).getAttribute("href")).toBe("/devices/2");
  expect(vi.mocked(apiRequest)).toHaveBeenCalledWith("/runs/full-run/coverage?page=0");
  fireEvent.click(screen.getByRole("button", { name: "Open poll" }));
  expect(screen.getByText("poll-run")).toBeDefined();
});
