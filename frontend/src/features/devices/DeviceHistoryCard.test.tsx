// @vitest-environment jsdom
/** Device history's previous different value (#617): hover, keyboard focus and a tap open it, the pointer can travel
 *  onto its action, and the action selects that state, on whichever page holds it, through the card's own selection,
 *  so the timeline and the values move together. The API module is stubbed; nothing is fetched. */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DeviceHistoryCard } from "@/features/devices/DeviceHistoryCard";
import type { HistoryDetail, HistoryPage, PreviousRead } from "@/features/devices/history";
import { historyEnglish as copy } from "@/features/devices/historyCopy";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: t } = await import("@/i18n/en");
  return { useLocale: () => ({ t, locale: "en" }) };
});
vi.mock("@/features/auth/store", () => ({ useAuthStore: (pick: (s: object) => unknown) => pick({ user: { id: "a1", tenant: { id: "t1" } } }) }));
const api = vi.hoisted(() => ({ loadHistory: vi.fn(), loadHistoryPoint: vi.fn(), loadPreviousValue: vi.fn() }));
vi.mock("@/features/devices/history", async (original) => ({ ...(await original<typeof import("@/features/devices/history")>()), ...api }));

const at = (id: string, day: number) => ({ id, kind: "inventory" as const, observedAt: `2026-11-${day}T12:00:00Z`, collectedAt: `2026-11-${day}T18:00:00Z` });
const PAGES: Record<string, HistoryPage> = {
  1: { items: [at("p:new", 14), at("p:mid", 13)], hasMore: true, page: 1 },
  "p:old": { items: [at("p:old", 10)], hasMore: false, page: 2 }, // the page the server counts for p:old, past the first
};
const VAULT = { key: "disk_encryption.fileVault2Enabled", label: "FileVault enabled", section: "disk_encryption", field: "fileVault2Enabled", enabled: true, before: null };
const detail = (id: string): HistoryDetail => ({ ...at(id, 1), spanId: "s", choices: [], baseline: false, assessment: null,
  summary: { status: "unavailable", text: null, provider: null, reason: null },
  values: [{ ...VAULT, state: "present", value: id !== "p:old" }, { ...VAULT, key: "security.firewallEnabled", enabled: false, state: "disabled", value: null }] });
const FOUND: PreviousRead = { previous: { ...at("p:old", 10), state: "present", value: false }, searched: 13, complete: true };
const OBSERVED = new Date("2026-11-10T12:00:00Z").toLocaleString("en");
const mouse = { pointerType: "mouse" };

/** Lets every stubbed read land and the card paint it: the timeline, then the selected state, then a lookup. */
const settle = async () => { for (let i = 0; i < 2; i++) await act(() => new Promise((resolve) => setTimeout(resolve, 0))); };
async function open(answer: PreviousRead | Error) {
  api.loadHistory.mockImplementation(async (_: number, page: number | string) => PAGES[page]);
  api.loadHistoryPoint.mockImplementation(async (_: number, id: string) => detail(id));
  api.loadPreviousValue.mockImplementation(async () => { if (answer instanceof Error) throw answer; return answer; });
  render(<MemoryRouter><DeviceHistoryCard deviceId={7} /></MemoryRouter>);
  await settle();
  return screen.getByRole("button", { name: /^FileVault: Enabled\./ });
}
const shown = (value: HTMLElement) => document.getElementById(value.getAttribute("aria-controls") ?? "")?.textContent ?? null;
const action = () => screen.queryByRole("button", { name: copy.previous.select });
afterEach(cleanup);
afterEach(() => vi.clearAllMocks());

describe("the previous different value of a Device history value (#617)", () => {
  it("opens on hover, stays open while the pointer travels onto its action, and the action selects that state on its page", async () => {
    const value = await open(FOUND);
    fireEvent.pointerEnter(value, mouse);
    await settle();
    expect(api.loadPreviousValue).toHaveBeenCalledWith(7, "p:new", "disk_encryption.fileVault2Enabled");
    expect(shown(value)).toBe(`${copy.previous.label}: Disabled${copy.observed}: ${OBSERVED}${copy.previous.select}`); // never the collection clock
    fireEvent.pointerLeave(value, { ...mouse, relatedTarget: action() }); // out of the value, into its own detail
    fireEvent.click(action()!);
    await settle();
    expect([api.loadHistory.mock.lastCall, api.loadHistoryPoint.mock.lastCall]).toEqual([[7, "p:old"], [7, "p:old"]]);
    expect(screen.getByRole("button", { pressed: true }).getAttribute("aria-label")).toContain(OBSERVED);
    expect([screen.getByText(copy.historical), screen.getByRole("button", { name: /^FileVault: Disabled\./ })]).toHaveLength(2);
  });

  it("opens on keyboard focus, keeps focus inside, and closes on Escape or when the pointer leaves", async () => {
    const value = await open(FOUND);
    fireEvent.pointerEnter(value, mouse);
    await settle();
    fireEvent.pointerLeave(value, mouse);
    expect(action()).toBeNull();
    act(() => value.focus());
    expect(value.getAttribute("aria-expanded")).toBe("true");
    act(() => action()!.focus());
    expect(action()).toBe(document.activeElement);
    fireEvent.keyDown(document.activeElement!, { key: "Escape" });
    expect([action(), document.activeElement]).toEqual([null, value]);
    expect(api.loadPreviousValue).toHaveBeenCalledTimes(1); // read once per selected state, however often it opens
  });

  it("toggles on a tap, says missing evidence is missing, and selects a state on the loaded page without paging", async () => {
    const value = await open({ previous: { ...at("p:mid", 13), state: "not_recorded", value: null }, searched: 1, complete: true });
    // A browser's order for a tap: the touch enters, presses and leaves, then the click lands.
    const tap = () => [fireEvent.pointerEnter, fireEvent.pointerDown, fireEvent.pointerLeave, fireEvent.click].map((fire) => fire(value, { pointerType: "touch" }));
    tap();
    await settle();
    expect(shown(value)).toContain(`${copy.previous.label}: ${copy.states.not_recorded}${copy.previous.missing}`);
    tap();
    expect(action()).toBeNull();
    tap();
    fireEvent.click(action()!);
    await settle();
    expect([api.loadHistory.mock.calls.length, api.loadHistoryPoint.mock.lastCall]).toEqual([1, [7, "p:mid"]]);
  });

  it("offers no action when nothing earlier differs, says how far a cut-off read went, and retries a failed read", async () => {
    for (const [answer, says] of [[{ previous: null, searched: 3, complete: true }, copy.previous.none],
      [{ previous: null, searched: 200, complete: false }, copy.previous.notRead(200)]] as const) {
      fireEvent.pointerEnter(await open(answer), mouse);
      await settle();
      expect([screen.getByText(says).tagName, action()]).toEqual(["P", null]);
      cleanup();
    }
    const value = await open(new Error("offline"));
    expect(screen.queryByRole("button", { name: /^Firewall:/ })).toBeNull(); // disabled in the Change Log: nothing to open
    fireEvent.pointerEnter(value, mouse);
    await settle();
    expect(shown(value)).toContain(copy.previous.failed);
    api.loadPreviousValue.mockResolvedValue(FOUND);
    fireEvent.click(screen.getByRole("button", { name: copy.retry }));
    await settle();
    expect(action()).not.toBeNull();
  });
});
