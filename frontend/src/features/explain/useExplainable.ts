import { createContext, useContext, type KeyboardEvent, type MouseEvent } from "react";

export interface ExplainTarget {
  kind: string;
  subject: Readonly<Record<string, string | number>>;
}

export interface ExplainMenuState {
  target: ExplainTarget;
  opener: HTMLElement;
  x: number;
  y: number;
}

export const ExplainContext = createContext<{
  label: string;
  open: (menu: ExplainMenuState) => void;
  choose: (target: ExplainTarget) => void;
} | null>(null);

export function useExplainMenu() {
  const context = useContext(ExplainContext);
  if (!context) throw new Error("Explain controls require ExplainMenuProvider");
  return context;
}

/** Spread on the value or row. Place an ExplainButton with the same target inside it. */
export function useExplainable(target: ExplainTarget) {
  const { open } = useExplainMenu();
  return {
    "data-explainable": "",
    "aria-haspopup": "menu" as const,
    tabIndex: 0,
    onContextMenu(event: MouseEvent<HTMLElement>) {
      if (event.shiftKey || event.defaultPrevented) return;
      // Preserve native actions for a link or control inside a marked row.
      const owner = (event.target as Element).closest("[data-explainable], a[href], button, input, textarea, select, [contenteditable=true]");
      if (owner !== event.currentTarget) return;
      event.preventDefault();
      open({ target, opener: event.currentTarget, x: event.clientX, y: event.clientY });
    },
    onKeyDown(event: KeyboardEvent<HTMLElement>) {
      if (event.target !== event.currentTarget || event.defaultPrevented) return;
      if (event.key !== "ContextMenu" && !(event.shiftKey && event.key === "F10")) return;
      event.preventDefault();
      const opener = event.currentTarget;
      const { left, bottom } = opener.getBoundingClientRect();
      open({ target, opener, x: left, y: bottom });
    }
  };
}
