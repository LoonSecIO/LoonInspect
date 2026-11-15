// @vitest-environment jsdom
/** The Fleet catalog tab after its read lands (#794): which of its states the page draws, and what Check now does.
 *  `catalogView.test.ts` holds the decisions as functions; this holds that the page asks them and prints the answer,
 *  which server rendering cannot show, because every state here is on the far side of an effect. The API module and
 *  the permission are stubbed; nothing is fetched. */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/config/api";
import { FleetCatalogPage } from "@/features/fleetCatalog/FleetCatalogPage";
import type { FleetCatalog, FleetCatalogState, FleetCatalogTitle } from "@/features/fleetCatalog/types";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});

const api = vi.hoisted(() => ({ getFleetCatalog: vi.fn(), refreshFleetCatalog: vi.fn() }));
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
  devicesCurrent: 2
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
  appCount: 953
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
  ...overrides
});

/** Renders the page and lets the first read land. */
async function open(answer: FleetCatalog) {
  api.getFleetCatalog.mockResolvedValue(answer);
  await act(async () => {
    render(<FleetCatalogPage />);
  });
}

beforeEach(() => {
  permission.held = true;
  api.getFleetCatalog.mockReset();
  api.refreshFleetCatalog.mockReset();
});
afterEach(cleanup);

describe("the Fleet catalog tab", () => {
  it("says the catalog has not been read yet, which is not an empty catalog, and offers the check", async () => {
    await open(catalog({ state: null, items: [], total: 0, installedTitles: 0 }));

    expect(screen.getByRole("status").textContent).toBe(en.fleetCatalog.statusNever);
    expect(screen.getByText(en.fleetCatalog.emptyNeverCheckedCanCheck)).toBeTruthy();
    expect(screen.getByRole("button", { name: en.fleetCatalog.checkNow })).toBeTruthy();
    expect(api.getFleetCatalog).toHaveBeenCalledExactlyOnceWith(true); // installed titles only, by default
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

  it("asks for the whole catalog when the box is unticked, and shows a dash, not a zero, for a title on no Mac", async () => {
    await open(catalog());
    api.getFleetCatalog.mockResolvedValue(catalog({ items: [ALPHA, GAMMA], total: 2 }));

    await act(async () => {
      fireEvent.click(screen.getByRole("checkbox"));
    });

    expect(api.getFleetCatalog).toHaveBeenLastCalledWith(false);
    const cells = Array.from(screen.getByText("Gamma").closest("tr")?.querySelectorAll("td") ?? []).map((cell) => cell.textContent);
    expect(cells).toEqual(["Gamma", "com.example.gamma", "2.0", "0", "-", en.fleetCatalog.notMoved]);
  });

  it("tells a search that missed among installed titles from an empty catalog", async () => {
    await open(catalog());

    await act(async () => {
      fireEvent.change(screen.getByPlaceholderText(en.fleetCatalog.searchPlaceholder), { target: { value: "zzz" } });
    });

    expect(screen.getByText(en.fleetCatalog.emptyNoMatchInstalled)).toBeTruthy();
    expect(screen.queryByText("Alpha")).toBeNull();
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
  });
});
