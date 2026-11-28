// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { ExplainButton, ExplainMenuProvider } from "./ExplainMenu";
import { useExplainable, type ExplainTarget } from "./useExplainable";

const target = { kind: "attribute_value", subject: { deviceId: 7, key: "os_version" } };
const outer = { kind: "group_membership", subject: { deviceId: 7, groupId: 3 } };
const rendered = vi.fn();
const onRow = vi.fn();
const onKey = vi.fn();

function Marked() {
  rendered();
  const props = useExplainable(target);
  return <div {...props} onClick={onRow}><span>Example value</span><a href="#example">Nested link</a><ExplainButton target={target} /></div>;
}

/** A marked row holding a marked value, and a mark with no ask inside it. */
function Awkward() {
  const row = useExplainable(outer);
  const value = useExplainable(target);
  const bare = useExplainable(target);
  return <>
    <div {...row}><div {...value}><span>Inner value</span><ExplainButton target={target} /></div><span>Row text</span><ExplainButton target={outer} /></div>
    <div {...bare}><span>Bare value</span></div>
  </>;
}

type Handler = (target: ExplainTarget, opener: HTMLElement) => void;
function page(onExplain: Handler, aiAvailable: boolean, marked: boolean, children = <Marked />) {
  return <LocaleProvider><div onKeyDown={onKey}><ExplainMenuProvider aiAvailable={aiAvailable} onExplain={onExplain}>
    {marked && children}
    <div>Other value</div>
  </ExplainMenuProvider></div></LocaleProvider>;
}

function show(aiAvailable = true, handler?: (target: ExplainTarget, opener: HTMLElement) => void) {
  const onExplain = vi.fn(handler);
  const view = render(page(onExplain, aiAvailable, true));
  return {
    onExplain,
    marked: screen.getByText("Example value").parentElement!,
    other: screen.getByText("Other value"),
    ask: screen.getByRole("button"),
    unmark: () => view.rerender(page(onExplain, aiAvailable, false)),
    swap: (next: Handler) => view.rerender(page(next, aiAvailable, true))
  };
}

afterEach(() => { cleanup(); localStorage.clear(); vi.clearAllMocks(); });

it("intercepts marked text and leaves unmarked text, nested links and Shift to the browser", () => {
  const { other, marked, ask, onExplain } = show();
  expect(fireEvent.contextMenu(other)).toBe(true);
  expect(fireEvent.contextMenu(screen.getByRole("link"))).toBe(true);
  expect(fireEvent.contextMenu(marked, { shiftKey: true })).toBe(true);
  expect(screen.queryByRole("menu")).toBeNull();
  expect(fireEvent.contextMenu(screen.getByText("Example value"))).toBe(false);
  const item = screen.getByRole("menuitem", { name: "Explain this" });
  expect(document.activeElement).toBe(item);
  fireEvent.click(item);
  expect(onExplain).toHaveBeenCalledExactlyOnceWith(target, ask);
  expect(screen.queryByRole("menu")).toBeNull();
});

it("adds one tab stop for a marked value, the ask, and none on the value itself", () => {
  const { marked, ask } = show();
  expect(marked.hasAttribute("tabindex")).toBe(false);
  expect(marked.hasAttribute("aria-haspopup")).toBe(false);
  expect(ask.tabIndex).toBe(0);
});

it.each([{ key: "F10", shiftKey: true }, { key: "ContextMenu" }])(
  "opens on $key from the ask, holds focus on the one action and restores it on Escape", keys => {
    const { ask } = show();
    ask.focus();
    expect(fireEvent.keyDown(ask, { key: "F10" })).toBe(true);
    expect(fireEvent.keyDown(screen.getByRole("link"), keys)).toBe(true);
    expect(screen.queryByRole("menu")).toBeNull();
    expect(fireEvent.keyDown(ask, keys)).toBe(false);
    const item = screen.getByRole("menuitem");
    expect(document.activeElement).toBe(item);
    for (const key of ["ArrowDown", "ArrowUp", "Home", "End"]) expect(fireEvent.keyDown(item, { key })).toBe(false);
    onKey.mockClear();
    expect(fireEvent.keyDown(item, { key: "Escape" })).toBe(false);
    expect(onKey).not.toHaveBeenCalled(); // an enclosing dialog must not close with the menu
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(ask);
  }
);

it("keeps focus where it is when the menu is clicked, and cancels the menu's own context menu", () => {
  const { marked } = show();
  fireEvent.contextMenu(marked);
  const item = screen.getByRole("menuitem");
  // WebKit blurs a focused button on mouse down unless the press is cancelled, and the menu
  // closes on blur: uncancelled, the menu is gone before the click (Safari, the Mac app).
  expect(fireEvent.mouseDown(item)).toBe(false);
  expect(item.tabIndex).toBe(-1);
  expect(fireEvent.contextMenu(item)).toBe(false);
  fireEvent.pointerDown(item);
  expect(screen.getByRole("menu")).toBeTruthy();
  fireEvent.focusOut(item, { relatedTarget: null });
  expect(screen.queryByRole("menu")).toBeNull();
});

it("puts focus back on the opener before the handler runs, and hands the opener over", () => {
  let focused: Element | null = null;
  const { ask, onExplain } = show(true, () => { focused = document.activeElement; });
  ask.focus();
  fireEvent.keyDown(ask, { key: "ContextMenu" });
  fireEvent.click(screen.getByRole("menuitem"));
  expect(focused).toBe(ask);
  expect(onExplain).toHaveBeenCalledExactlyOnceWith(target, ask);
});

it("closes on Tab and on a keyboard scroll with focus back on the opener, and on a press outside", () => {
  const { ask, marked, other } = show();
  ask.focus();
  fireEvent.keyDown(ask, { key: "ContextMenu" });
  expect(fireEvent.keyDown(screen.getByRole("menuitem"), { key: "Tab" })).toBe(false);
  expect(screen.queryByRole("menu")).toBeNull();
  expect(document.activeElement).toBe(ask);
  fireEvent.keyDown(ask, { key: "ContextMenu" });
  fireEvent.scroll(other);
  expect(screen.queryByRole("menu")).toBeNull();
  expect(document.activeElement).toBe(ask);
  fireEvent.contextMenu(marked);
  fireEvent.pointerDown(other);
  expect(screen.queryByRole("menu")).toBeNull();
});

it("goes when the element it was opened on goes", async () => {
  const { marked, unmark, onExplain } = show();
  fireEvent.contextMenu(marked);
  expect(screen.getByRole("menu")).toBeTruthy();
  unmark();
  await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
  expect(onExplain).not.toHaveBeenCalled();
});

it.each([["en", "What is this?"], ["de", "Was ist das?"]])(
  "offers facts in %s with AI off through both menu and visible control", (locale, label) => {
    localStorage.setItem("locale", locale);
    const { marked, ask, onExplain } = show(false);
    fireEvent.contextMenu(marked);
    fireEvent.click(screen.getByRole("menuitem", { name: label }));
    fireEvent.click(screen.getByRole("button", { name: label }));
    expect(onExplain.mock.calls).toEqual([[target, ask], [target, ask]]);
  }
);

it("keeps the ask's click from the row, the newest handler, and marked elements still while it opens and closes", () => {
  const first = vi.fn();
  const { ask, marked, swap } = show(true, first);
  fireEvent.click(ask);
  expect(onRow).not.toHaveBeenCalled();
  expect(first).toHaveBeenCalledTimes(1);
  const before = rendered.mock.calls.length;
  fireEvent.contextMenu(marked);
  fireEvent.keyDown(screen.getByRole("menuitem"), { key: "Escape" });
  expect(rendered.mock.calls.length).toBe(before);
  const second = vi.fn();
  swap(second);
  fireEvent.click(ask);
  expect([first.mock.calls.length, second.mock.calls.length]).toEqual([1, 1]);
});

it("opens for the mark that was pressed when marks nest, and returns focus to a mark with no ask", () => {
  let focused: Element | null = null;
  const onExplain = vi.fn<Handler>(() => { focused = document.activeElement; });
  render(page(onExplain, true, true, <Awkward />));
  const [innerAsk, rowAsk] = screen.getAllByRole("button");
  // Identity, not equality: the two asks are the same markup, and equal as nodes.
  const last = () => onExplain.mock.lastCall!;
  fireEvent.contextMenu(screen.getByText("Row text"));
  fireEvent.click(screen.getByRole("menuitem"));
  expect([last()[0] === outer, last()[1] === rowAsk, focused === rowAsk]).toEqual([true, true, true]);
  fireEvent.contextMenu(screen.getByText("Inner value"));
  fireEvent.click(screen.getByRole("menuitem"));
  expect([last()[0] === target, last()[1] === innerAsk, focused === innerAsk]).toEqual([true, true, true]);
  const bare = screen.getByText("Bare value").parentElement!;
  fireEvent.contextMenu(bare);
  fireEvent.click(screen.getByRole("menuitem"));
  expect(last()[1]).toBe(bare);
  expect(focused).toBe(bare);
  expect(bare.tabIndex).toBe(-1);
});
