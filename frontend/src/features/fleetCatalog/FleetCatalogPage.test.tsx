// @vitest-environment jsdom
/** The Fleet catalog tab after its read lands (#794): which of its states the page draws, and what Check now does.
 *  `catalogView.test.ts` holds the decisions as functions; this holds that the page asks them and prints the answer,
 *  which server rendering cannot show, because every state here is on the far side of an effect. The API module and
 *  the permission are stubbed; nothing is fetched. */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { FleetCatalogPage } from "@/features/fleetCatalog/FleetCatalogPage";
import type { FleetCatalog, FleetCatalogState, FleetCatalogTitle, FleetTitleHistory } from "@/features/fleetCatalog/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});

const api = vi.hoisted(() => ({
  getFleetCatalog: vi.fn(),
  refreshFleetCatalog: vi.fn(),
  getTitleHistory: vi.fn(),
  readTitleHistory: vi.fn()
}));
vi.mock("@/features/fleetCatalog/api", () => api);

const permission = vi.hoisted(() => ({ held: true }));
vi.mock("@/features/auth/store", () => ({ useHasPermission: () => permission.held }));

const ALPHA: FleetCatalogTitle = {
  slug: "alpha",
  name: "Alpha",
  bundleId: "com.example.alpha",
  latestVersion: "2.0",
  previousVersion: "1.9",
  versionChangedAt: "2026-11-14T09:00:00Z",
  firstSeenAt: "2026-11-01T09:00:00Z",
  deviceCount: 3,
  devicesBehind: 1,
  devicesCurrent: 2,
  inCatalogSince: null,
  versionBefore: null,
  historyReadAt: null
};
const GAMMA: FleetCatalogTitle = {
  ...ALPHA,
  slug: "gamma",
  name: "Gamma",
  bundleId: "com.example.gamma",
  previousVersion: null,
  versionChangedAt: null,
  deviceCount: 0,
  devicesBehind: 0,
  devicesCurrent: 0
};
const READ: FleetCatalogState = {
  checkedAt: "2026-11-15T12:00:00Z",
  changedAt: "2026-11-15T12:00:00Z",
  outcome: "ok",
  detail: null,
  appCount: 953,
  historyCheckedAt: null,
  historyOutcome: null,
  historyDetail: null
};
const catalog = (overrides: Partial<FleetCatalog> = {}): FleetCatalog => ({
  enabled: true,
  source: "fleetdm/fleet",
  state: READ,
  items: [ALPHA],
  total: 1,
  page: 1,
  pageSize: 5000,
  installedTitles: 1,
  installedTitlesWithHistory: 0,
  ...overrides
});
const NEVER_READ: FleetTitleHistory = {
  slug: "alpha",
  name: "Alpha",
  latestVersion: "2.0",
  historyReadAt: null,
  historySince: null,
  historyThrough: null,
  historyComplete: false,
  historyDetail: null,
  versions: []
};
const HISTORY: FleetTitleHistory = {
  ...NEVER_READ,
  historyReadAt: "2026-11-21T12:00:00Z",
  historySince: "2025-03-12T21:51:14Z",
  historyThrough: "2026-11-18T02:27:27Z",
  historyComplete: true,
  versions: [
    { version: "2.0", seenAt: "2026-11-18T02:27:27Z", commitSha: "6".repeat(40), previousVersion: "1.9" },
    { version: "1.9", seenAt: "2025-03-12T21:51:14Z", commitSha: "4".repeat(40), previousVersion: null }
  ]
};

const refreshed = vi.fn();
const COUNTS = { alpha: 2, gamma: 0 };

/** The search and the box held as the Fleet titles view holds them, the box ticked; Alpha is on 2 of the filter's Macs. */
function Scoped() {
  const [search, setSearch] = useState("");
  const [installedOnly, setInstalledOnly] = useState(true);
  return <FleetCatalogPage scope={{ search, setSearch, installedOnly, setInstalledOnly, counts: COUNTS, onRefresh: refreshed }} />;
}

/** Renders the page and lets the first read land. */
async function open(answer: FleetCatalog) {
  api.getFleetCatalog.mockResolvedValue(answer);
  await act(async () => {
    render(<MemoryRouter><Scoped /></MemoryRouter>);
  });
}

beforeEach(() => {
  refreshed.mockReset();
  permission.held = true;
  api.getFleetCatalog.mockReset();
  api.refreshFleetCatalog.mockReset();
  api.getTitleHistory.mockReset();
  api.readTitleHistory.mockReset();
});
afterEach(cleanup);

describe("the Fleet catalog tab", () => {
  it("says the catalog has not been read yet, which is not an empty catalog, and offers the check", async () => {
    await open(catalog({ state: null, items: [], total: 0, installedTitles: 0 }));

    expect(screen.getByRole("status").textContent).toBe(en.fleetCatalog.statusNever);
    expect(screen.getByText(en.fleetCatalog.emptyNeverCheckedCanCheck)).toBeTruthy();
    expect(screen.getByRole("button", { name: en.fleetCatalog.checkNow })).toBeTruthy();
    expect(api.getFleetCatalog).toHaveBeenCalledExactlyOnceWith(false); // the whole catalog, which the box filters as held
  });

  it("lists the titles with Macs counted, and a version move with the version before it", async () => {
    await open(catalog());

    const row = screen.getByText("Alpha").closest("tr");
    expect(row?.textContent).toContain("com.example.alpha");
    expect(row?.textContent).toContain("2.0");
    expect(row?.textContent).toContain(", from 1.9");
    expect(screen.getByRole("status").textContent).toContain("It lists 953 Mac apps.");
    expect(screen.getByText(en.fleetCatalog.footer(1, 953, 1))).toBeTruthy();
  });

  it("keeps the titles read earlier under a failed check's own sentence, and hides the check from a reader", async () => {
    permission.held = false;
    const sentence = "No answer from api.github.com (Name or service not known). Nothing was changed.";
    await open(catalog({ state: { ...READ, outcome: "unreachable", detail: sentence, checkedAt: "2026-11-15T13:00:00Z" } }));

    const status = screen.getByRole("status").textContent ?? "";
    expect(status).toContain("did not get an answer.");
    expect(status).toContain(sentence);
    expect(status).toContain("The 953 titles held here are as read");
    expect(screen.getByText("Alpha")).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.fleetCatalog.checkNow })).toBeNull();
  });

  it("shows a title on none of the filter's Macs once the box is unticked, without reading again, with a dash, not a zero, for no Mac", async () => {
    await open(catalog({ items: [ALPHA, GAMMA], total: 2 }));
    expect(screen.queryByText("Gamma")).toBeNull();

    await act(async () => {
      fireEvent.click(screen.getByRole("checkbox"));
    });

    expect(api.getFleetCatalog).toHaveBeenCalledExactlyOnceWith(false);
    const cells = Array.from(screen.getByText("Gamma").closest("tr")?.querySelectorAll("td") ?? []).map((cell) => cell.textContent);
    expect(cells).toEqual([`Gamma${en.fleetCatalog.sourceLink}`, "com.example.gamma", "2.0", "0", "0", "-", en.fleetCatalog.notMoved]);
    const source = screen.getByRole("link", { name: en.fleetCatalog.sourceLabel("Gamma") });
    expect(source.getAttribute("href")).toBe("https://github.com/fleetdm/fleet/blob/main/ee/maintained-apps/outputs/gamma/darwin.json");
    expect(source.getAttribute("target")).toBe("_blank");
  });

  it("tells a search that missed among installed titles from an empty catalog", async () => {
    await open(catalog());

    await act(async () => {
      fireEvent.change(screen.getByPlaceholderText(en.fleetCatalog.searchPlaceholder), { target: { value: "zzz" } });
    });

    expect(screen.getByRole<HTMLInputElement>("checkbox").checked).toBe(true); // `Scoped` ticks the box
    expect(screen.getByText(en.fleetCatalog.emptyNoMatchInstalled)).toBeTruthy();
    expect(screen.queryByText("Alpha")).toBeNull();
  });

  it("says no title is on a Mac the filter selects, naming the box by its own label in both languages", async () => {
    await open(catalog({ items: [GAMMA] }));
    expect(screen.getByText(en.fleetCatalog.emptyNoneInstalled(953))).toBeTruthy();
    for (const words of [en.fleetCatalog, de.fleetCatalog]) expect(words.emptyNoneInstalled(953)).toContain(words.installedOnly);
  });

  it("shows the server's sentence when Check now is refused, and reads the page again either way", async () => {
    await open(catalog());
    const refusal = "api.github.com refused the request (403): its limit for requests without a sign-in is 60 an hour.";
    api.refreshFleetCatalog.mockRejectedValue(new ApiError(409, refusal));

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: en.fleetCatalog.checkNow }));
    });

    expect(screen.getByText(refusal)).toBeTruthy();
    expect(api.getFleetCatalog).toHaveBeenCalledTimes(2); // a failed check still wrote what it found
    expect(refreshed).toHaveBeenCalledOnce(); // and the counts for the filter are read again
  });

  it("dates the latest version from the version history when it has one, and says how far the history has got", async () => {
    await open(
      catalog({
        items: [{ ...ALPHA, inCatalogSince: "2026-11-18T02:27:27Z", versionBefore: "1.9.4", historyReadAt: "2026-11-21T12:00:00Z" }],
        installedTitlesWithHistory: 1,
        state: { ...READ, historyCheckedAt: "2026-11-21T12:00:00Z", historyOutcome: "ok" }
      })
    );

    expect(screen.getByText("Alpha").closest("tr")?.textContent).toContain(", from 1.9.4");
    expect(screen.getByRole("status").textContent).toContain(en.fleetCatalog.historyProgress(1, 1));
  });

  it("shows why the history read is holding back, in the server's words", async () => {
    const sentence = "Paused until 14:05 UTC: GitHub says 20 of this address's 60 requests an hour are left.";
    await open(catalog({ state: { ...READ, historyCheckedAt: "2026-11-21T13:30:00Z", historyOutcome: "waiting", historyDetail: sentence } }));

    expect(screen.getByRole("status").textContent).toContain(sentence);
  });

  it("opens a title's history from its row, and Read history reads it and lists the versions newest first", async () => {
    await open(catalog());
    api.getTitleHistory.mockResolvedValue(NEVER_READ);

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Alpha/ }));
    });
    expect(api.getTitleHistory).toHaveBeenCalledExactlyOnceWith("alpha");
    expect(screen.getByText(en.fleetCatalog.historyNotRead)).toBeTruthy();

    api.readTitleHistory.mockResolvedValue(HISTORY);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: en.fleetCatalog.historyRead }));
    });

    expect(api.readTitleHistory).toHaveBeenCalledExactlyOnceWith("alpha");
    const panel = screen.getByTestId("fleet-history-alpha");
    const versions = Array.from(panel.querySelectorAll(":scope tbody tr")).map((row) => row.querySelector("td")?.textContent);
    expect(versions).toEqual(["2.0", "1.9"]);
    expect(panel.querySelector("a")?.getAttribute("href")).toBe(`https://github.com/fleetdm/fleet/commit/${"6".repeat(40)}`);
    expect(panel.textContent).toContain(en.fleetCatalog.historyReplacedNone);
    expect(api.getFleetCatalog).toHaveBeenCalledTimes(2); // the row's date and the progress line are read again
    expect(screen.getByRole("button", { name: en.fleetCatalog.historyReadAgain })).toBeTruthy();
  });

  it("shows the server's sentence when a history read is refused, and offers no read to a reader", async () => {
    await open(catalog());
    api.getTitleHistory.mockResolvedValue(NEVER_READ);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Alpha/ }));
    });
    const refusal = "Not read: GitHub says 20 of this address's 60 requests an hour are left. Try again after 14:05 UTC.";
    api.readTitleHistory.mockRejectedValue(new ApiError(409, refusal));

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: en.fleetCatalog.historyRead }));
    });
    expect(screen.getByText(refusal)).toBeTruthy();

    cleanup();
    permission.held = false;
    await open(catalog());
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Alpha/ }));
    });
    expect(screen.queryByRole("button", { name: en.fleetCatalog.historyRead })).toBeNull();
  });
});
