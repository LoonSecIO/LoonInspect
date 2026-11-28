// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { ExplainButton, ExplainMenuProvider } from "./ExplainMenu";
import { useExplainable, type ExplainTarget } from "./useExplainable";

const target = { kind: "attribute_value", subject: { deviceId: 7, key: "os_version" } };

function Marked() {
  const props = useExplainable(target);
  return <div {...props}><span>Example value</span><a href="#example">Nested link</a><ExplainButton target={target} /></div>;
}

function page(onExplain: (target: ExplainTarget, opener: HTMLElement) => void, aiAvailable: boolean, marked: boolean) {
  return <LocaleProvider><ExplainMenuProvider aiAvailable={aiAvailable} onExplain={onExplain}>
    {marked && <Marked />}
    <div>Other value</div>
  </ExplainMenuProvider></LocaleProvider>;
}

function show(aiAvailable = true, handler?: (target: ExplainTarget, opener: HTMLElement) => void) {
  const onExplain = vi.fn(handler);
  const view = render(page(onExplain, aiAvailable, true));
  return {
    onExplain,
    marked: screen.getByText("Example value").parentElement!,
    other: screen.getByText("Other value"),
    ask: screen.getByRole("button"),
    unmark: () => view.rerender(page(onExplain, aiAvailable, false))
  };
}

afterEach(() => { cleanup(); localStorage.clear(); });

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
    expect(fireEvent.keyDown(item, { key: "Escape" })).toBe(false);
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
