// @vitest-environment jsdom
/** A title's version history panel (#901): the Fleet catalog tab's layout when the caller passes neither new prop, and
 *  the detail layout an app's page mounts, with the cadence chart, the version search, each row's manifest at its
 *  commit and its Compare button. The API module is stubbed; nothing is fetched. */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FleetTitleHistory } from "@/features/fleetCatalog/FleetTitleHistory";
import { historyActivity } from "@/features/fleetCatalog/historyActivity";
import type { FleetTitleHistory as History } from "@/features/fleetCatalog/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const locale = vi.hoisted(() => ({ current: "en" as "en" | "de" }));
vi.mock("@/i18n/LocaleContext", async () => {
  const [{ en }, { de }] = await Promise.all([import("@/i18n/en"), import("@/i18n/de")]);
  return { useLocale: () => ({ locale: locale.current, t: locale.current === "de" ? de : en }) };
});

const api = vi.hoisted(() => ({ getTitleHistory: vi.fn(), readTitleHistory: vi.fn() }));
vi.mock("@/features/fleetCatalog/api", () => api);

// Read on 2026-11-21, so the 13 weeks open on 2026-08-23, the day the oldest version was dated. The two gaps add up
// to 89.2 days, so their median is 44.6.
const HISTORY: History = {
  slug: "example@esr",
  name: "Example ESR",
  latestVersion: "2.0",
  historyReadAt: "2026-11-21T12:00:00Z",
  historySince: "2026-08-23T06:00:00Z",
  historyThrough: "2026-11-20T10:48:00Z",
  historyComplete: true,
  historyDetail: null,
  versions: [
    { version: "2.0", seenAt: "2026-11-20T10:48:00Z", commitSha: "a".repeat(40), previousVersion: "1.9" },
    { version: "1.9", seenAt: "2026-10-01T09:00:00Z", commitSha: "b".repeat(40), previousVersion: "1.8" },
    { version: "1.8", seenAt: "2026-08-23T06:00:00Z", commitSha: "c".repeat(40), previousVersion: null }
  ]
};

async function show(history: History, props: { detail?: boolean; onSelectVersion?: (version: string) => void } = {}) {
  api.getTitleHistory.mockResolvedValue(history);
  await act(async () => {
    render(<FleetTitleHistory slug={history.slug} canRead={false} {...props} />);
  });
}

afterEach(() => {
  cleanup();
  locale.current = "en";
});

describe("historyActivity", () => {
  it("counts the window's first day in its first bar, and takes the median gap over the whole history", () => {
    expect(historyActivity(HISTORY)).toEqual({
      bins: [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1],
      median: 44.6,
      start: Date.parse("2026-08-23T00:00:00Z"),
      end: Date.parse("2026-11-22T00:00:00Z"),
      total: 3,
      whole: true
    });
  });

  it("gives no median for a history with a detail, and nothing for an unread history", () => {
    expect(historyActivity({ ...HISTORY, historyDetail: "1 change could not be read." })).toMatchObject({ median: null, total: 3 });
    expect(historyActivity({ ...HISTORY, historyReadAt: null })).toBeNull();
  });
});

describe("the version history panel", () => {
  it("with neither new prop is the Fleet catalog tab's: three columns, and no search box, chart or button", async () => {
    await show(HISTORY);

    expect(screen.getAllByRole("columnheader")).toHaveLength(3);
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("in detail with Compare, draws the chart and finds one version, its manifest at its commit and its Compare", async () => {
    const onSelectVersion = vi.fn();
    await show(HISTORY, { detail: true, onSelectVersion });
    expect(screen.getByRole("img", { name: en.fleetCatalog.cadenceChartLabel("3", 13, "Nov 21") })).toBeTruthy();

    fireEvent.change(screen.getByRole("searchbox", { name: en.fleetCatalog.historySearch }), { target: { value: "1.9" } });
    const rows = Array.from(screen.getByRole("table").querySelectorAll("tbody tr"));
    expect(rows.map((row) => row.querySelector("td")?.textContent)).toEqual(["1.9"]);
    const manifest = screen.getByRole("link", { name: (name) => name.includes(en.fleetCatalog.historyManifestLabel("1.9")) });
    expect(manifest.getAttribute("href")).toBe(
      `https://github.com/fleetdm/fleet/blob/${"b".repeat(40)}/ee/maintained-apps/outputs/example%40esr/darwin.json`
    );
    expect(screen.getByRole("link", { name: /^Manifest at this commit for 1\.9, / })).toBe(manifest); // WCAG 2.5.3, in both languages:
    for (const words of [en.fleetCatalog, de.fleetCatalog]) expect(words.historyManifestLabel("1.9").startsWith(words.historyManifest)).toBe(true);
    expect(screen.getAllByRole("button").map((button) => button.textContent)).toEqual([en.fleetCatalog.historyCompare("1.9")]);
    fireEvent.click(screen.getByRole("button", { name: en.fleetCatalog.historyCompare("1.9") }));
    expect(onSelectVersion).toHaveBeenCalledExactlyOnceWith("1.9");

    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "9.9" } });
    expect(screen.getByText(en.fleetCatalog.historySearchNone)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("says an incomplete history has gaps, above the read's status line, and gives no median", async () => {
    await show({ ...HISTORY, historyComplete: false }, { detail: true });

    const gaps = screen.getByText(en.fleetCatalog.cadenceGaps);
    const status = screen.getByText(/goes further back than this read reached\.$/);
    expect(gaps.compareDocumentPosition(status)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
    expect(screen.queryByText(en.fleetCatalog.cadenceMedianGap)).toBeNull();
  });

  it("reads the median gap in the reader's language", async () => {
    locale.current = "de";
    await show(HISTORY, { detail: true });

    expect(screen.getByText("44,6 Tage")).toBeTruthy();
    expect(en.fleetCatalog.cadenceDays("1", true)).toBe("1 day");
  });
});
