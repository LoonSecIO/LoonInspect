import { createContext, useContext, type KeyboardEvent, type MouseEvent } from "react";

export interface ExplainTarget {
  kind: string;
  subject: Readonly<Record<string, string | number>>;
}

export interface ExplainMenuState {
  target: ExplainTarget;
  /** Where focus goes back to: the ask button of the marked element, when it has one. */
  opener: HTMLElement;
  x: number;
  y: number;
}

export const ExplainContext = createContext<{
  label: string;
  open: (menu: ExplainMenuState) => void;
  choose: (target: ExplainTarget, opener: HTMLElement) => void;
} | null>(null);

export function useExplainMenu() {
  const context = useContext(ExplainContext);
  if (!context) throw new Error("Explain controls require ExplainMenuProvider");
  return context;
}

// A link or a control inside a marked element keeps its own menu and its own keys. The ask
// button is the one control that belongs to the mark.
const OWNERS = "[data-explainable], a[href], button:not([data-explain-ask]), input, textarea, select, [contenteditable=true]";

function marks(event: { target: EventTarget; currentTarget: Element }) {
  return (event.target as Element).closest(OWNERS) === event.currentTarget;
}

/** Spread on the value or row, with an ExplainButton for the same target inside it. The
 *  button is the keyboard's way in, so the marked element is not a tab stop of its own: a
 *  page that marks fifty values gains fifty stops, not a hundred. */
export function useExplainable(target: ExplainTarget) {
  const { open } = useExplainMenu();
  return {
    "data-explainable": "",
    onContextMenu(event: MouseEvent<HTMLElement>) {
      if (event.shiftKey || event.defaultPrevented || !marks(event)) return;
      event.preventDefault();
      const marked = event.currentTarget;
      const opener = marked.querySelector<HTMLElement>("[data-explain-ask]") ?? marked;
      open({ target, opener, x: event.clientX, y: event.clientY });
    },
    onKeyDown(event: KeyboardEvent<HTMLElement>) {
      if (event.defaultPrevented || !marks(event)) return;
      if (event.key !== "ContextMenu" && !(event.shiftKey && event.key === "F10")) return;
      event.preventDefault();
      const opener = event.target as HTMLElement;
      const { left, bottom } = opener.getBoundingClientRect();
      open({ target, opener, x: left, y: bottom });
    }
  };
}
