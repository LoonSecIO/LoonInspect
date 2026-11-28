// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { ExplainButton, ExplainMenuProvider } from "./ExplainMenu";
import { useExplainable } from "./useExplainable";

const target = { kind: "attribute_value", subject: { deviceId: 7, key: "os_version" } };

function Fixture() {
  const props = useExplainable(target);
  return <>
    <div {...props}><span>Example value</span><a href="#example">Nested link</a><ExplainButton target={target} /></div>
    <div>Other value</div>
  </>;
}

function show(aiAvailable = true) {
  const onExplain = vi.fn();
  render(<LocaleProvider><ExplainMenuProvider aiAvailable={aiAvailable} onExplain={onExplain}>
    <Fixture />
  </ExplainMenuProvider></LocaleProvider>);
  return { onExplain, marked: screen.getByText("Example value").parentElement!, other: screen.getByText("Other value") };
}

afterEach(() => { cleanup(); localStorage.clear(); });

it("intercepts marked text and leaves unmarked text, nested links and Shift to the browser", () => {
  const { other, marked, onExplain } = show();
  expect(fireEvent.contextMenu(other)).toBe(true);
  expect(fireEvent.contextMenu(screen.getByRole("link"))).toBe(true);
  expect(fireEvent.contextMenu(marked, { shiftKey: true })).toBe(true);
  expect(screen.queryByRole("menu")).toBeNull();
  expect(fireEvent.contextMenu(screen.getByText("Example value"))).toBe(false);
  const item = screen.getByRole("menuitem", { name: "Explain this" });
  expect(document.activeElement).toBe(item);
  fireEvent.click(item);
  expect(onExplain).toHaveBeenCalledExactlyOnceWith(target);
  expect(screen.queryByRole("menu")).toBeNull();
});

it.each([{ key: "F10", shiftKey: true }, { key: "ContextMenu" }])(
  "opens on $key, cycles the one action and restores keyboard focus on Escape", keys => {
    const { marked } = show();
    marked.focus();
    expect(fireEvent.keyDown(marked, { key: "F10" })).toBe(true);
    expect(fireEvent.keyDown(marked, keys)).toBe(false);
    const item = screen.getByRole("menuitem");
    for (const key of ["ArrowDown", "ArrowUp"]) {
      expect(fireEvent.keyDown(item, { key })).toBe(false);
      expect(document.activeElement).toBe(item);
    }
    fireEvent.keyDown(item, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(marked);
  }
);

it("dismisses on outside pointer down and scrolling a descendant", () => {
  const { marked, other } = show();
  fireEvent.contextMenu(marked);
  fireEvent.pointerDown(other);
  expect(screen.queryByRole("menu")).toBeNull();
  fireEvent.contextMenu(marked);
  fireEvent.scroll(other);
  expect(screen.queryByRole("menu")).toBeNull();
});

it.each([["en", "What is this?"], ["de", "Was ist das?"]])(
  "offers facts in %s with AI off through both menu and visible control", (locale, label) => {
    localStorage.setItem("locale", locale);
    const { marked, onExplain } = show(false);
    fireEvent.contextMenu(marked);
    fireEvent.click(screen.getByRole("menuitem", { name: label }));
    fireEvent.click(screen.getByRole("button", { name: label }));
    expect(onExplain.mock.calls).toEqual([[target], [target]]);
  }
);
