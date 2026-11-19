// @vitest-environment jsdom
/** Device history's previous different value (#617): hover, keyboard focus and a tap open it, the pointer can travel onto
 *  its action, and the action selects that state, on the page holding it, through the card's own selection. API stubbed. */

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
const PAGES: Record<number, HistoryPage> = { 1: { items: [at("p:new", 14), at("p:mid", 13)], hasMore: true, page: 1 },
  2: { items: [at("p:old", 10)], hasMore: false, page: 2 } };
const VAULT = { key: "disk_encryption.fileVault2Enabled", label: "FileVault enabled", section: "disk_encryption", field: "fileVault2Enabled", enabled: true, before: null };
const detail = (id: string): HistoryDetail => ({ ...at(id, 1), spanId: "s", choices: [], baseline: false, assessment: null,
  summary: { status: "unavailable", text: null, provider: null, reason: null },
  values: [{ ...VAULT, state: "present", value: id !== "p:old" }, { ...VAULT, key: "security.firewallEnabled", enabled: false, state: "disabled", value: null }] });
const FOUND: PreviousRead = { previous: { ...at("p:old", 10), state: "present", value: false, page: 2 }, searched: 13, complete: true };
const OBSERVED = new Date("2026-11-10T12:00:00Z").toLocaleString("en");
const mouse = { pointerType: "mouse" };

const settle = async () => { for (let i = 0; i < 2; i++) await act(() => new Promise((resolve) => setTimeout(resolve, 0))); };
async function open(answer: PreviousRead | Error) {
  api.loadHistory.mockImplementation(async (_: number, page: number) => PAGES[page]);
  api.loadHistoryPoint.mockImplementation(async (_: number, id: string) => detail(id));
  api.loadPreviousValue.mockImplementation(async () => { if (answer instanceof Error) throw answer; return answer; });
  render(<MemoryRouter><DeviceHistoryCard deviceId={7} /></MemoryRouter>);
  await settle();
  return screen.getByRole("button", { name: /^FileVault: Enabled\./ });
}
const shown = (value: HTMLElement) => document.getElementById(value.getAttribute("aria-controls") ?? "")?.textContent ?? null;
const action = () => screen.queryByRole("button", { name: copy.previous.select });
// A press as WebKit (Safari, iOS) makes it: it focuses no button, so unless the mousedown is prevented it clears focus first.
const press = async (el: HTMLElement) => { if (fireEvent.mouseDown(el)) act(() => (document.activeElement as HTMLElement).blur()); fireEvent.click(el); await settle(); };
afterEach(cleanup);
afterEach(() => vi.clearAllMocks());

describe("the previous different value of a Device history value (#617)", () => {
  it("opens on hover, stays open while the pointer travels onto its action, and the action selects that state on its page and focuses its dot", async () => {
    const value = await open(FOUND);
    fireEvent.pointerEnter(value, mouse);
    await settle();
    expect(api.loadPreviousValue).toHaveBeenCalledWith(7, "p:new", "disk_encryption.fileVault2Enabled");
    expect(shown(value)).toBe(`${copy.previous.label}: Disabled${copy.observed}: ${OBSERVED}${copy.previous.select}`); // never the collection clock
    fireEvent.pointerLeave(value, mouse); // leaving the whole box closes it; coming back does not read again
    expect(action()).toBeNull();
    fireEvent.pointerEnter(value, mouse);
    fireEvent.pointerLeave(value, { ...mouse, relatedTarget: action() }); // out of the value, into its own detail
    await press(action()!);
    expect([api.loadPreviousValue.mock.calls.length, api.loadHistory.mock.lastCall, api.loadHistoryPoint.mock.lastCall]).toEqual([1, [7, 2], [7, "p:old"]]);
    expect(["pressed", "label"].map((a) => document.activeElement?.getAttribute(`aria-${a}`))).toEqual(["true", expect.stringContaining(OBSERVED)]);
    expect([screen.getByText(copy.historical), screen.getByRole("button", { name: /^FileVault: Disabled\./ })]).toHaveLength(2);
  });

  it("opens on focus and keeps it inside until Escape, toggles on a tap, says missing evidence is missing, and selects on its page; Retry drops a lost state", async () => {
    const value = await open({ previous: { ...at("p:mid", 13), state: "not_recorded", value: null, page: 1 }, searched: 1, complete: true });
    act(() => value.focus());
    await settle();
    expect(shown(value)).toContain(`${copy.previous.label}: ${copy.states.not_recorded}${copy.previous.missing}`);
    act(() => action()!.focus());
    fireEvent.keyDown(document.activeElement!, { key: "Escape" }); // from inside the detail: closed, focus back on the value
    expect([action(), document.activeElement]).toEqual([null, value]);
    // A browser's order for a tap: the touch enters, presses and leaves, then its mouse press and click land.
    const tap = () => { [fireEvent.pointerEnter, fireEvent.pointerDown, fireEvent.pointerLeave].forEach((fire) => fire(value, { pointerType: "touch" })); return press(value); };
    await tap();
    expect(action()).not.toBeNull();
    await tap();
    expect(action()).toBeNull();
    await tap();
    api.loadHistoryPoint.mockRejectedValueOnce(new Error("gone")); // That state leaves the history before the jump reads it,
    await press(action()!);
    expect([api.loadHistory.mock.calls.length, api.loadHistoryPoint.mock.lastCall]).toEqual([1, [7, "p:mid"]]);
    api.loadHistory.mockResolvedValue({ items: [at("p:new", 14)], hasMore: false, page: 1 }); // and the reloaded page lacks it:
    await press(screen.getByRole("button", { name: copy.retry })); // the card's Retry selects that page's newest state.
    expect(api.loadHistoryPoint.mock.lastCall).toEqual([7, "p:new"]);
  });

  it("offers no action when nothing earlier differs, says how far a cut-off read went, retries a failed read, and keeps a target a page off", async () => {
    for (const [answer, says] of [[{ previous: null, searched: 3, complete: true }, copy.previous.none],
      [{ previous: null, searched: 200, complete: false }, copy.previous.notRead(200)]] as const) {
      fireEvent.pointerEnter(await open(answer), mouse);
      await settle();
      expect([screen.getByText(says).tagName, action()]).toEqual(["P", null]);
      cleanup();
    }
    const value = await open(new Error("offline"));
    expect(screen.queryByRole("button", { name: /^Firewall:/ })).toBeNull(); // disabled in the Change Log: nothing to open
    await press(value); // A click: the value holds focus while Retry is pressed.
    expect(shown(value)).toContain(copy.previous.failed);
    api.loadPreviousValue.mockResolvedValue({ ...FOUND, previous: { ...FOUND.previous!, page: 1 } }); // Counted before a newer state pushed it on,
    await press(screen.getByRole("button", { name: copy.retry }));
    await press(action()!); // so the jump lands a page early: page 1 has no p:old dot, yet the card still selects p:old.
    expect(api.loadHistoryPoint.mock.lastCall).toEqual([7, "p:old"]);
  });
});
