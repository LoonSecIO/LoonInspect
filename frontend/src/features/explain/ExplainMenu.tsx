import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type PropsWithChildren } from "react";
import { CircleQuestionMark } from "lucide-react";
import { createPortal } from "react-dom";
import { useLocale } from "@/i18n/LocaleContext";
import { ExplainContext, useExplainMenu, type ExplainMenuState, type ExplainTarget } from "./useExplainable";
import "./explainMenu.css";

export function ExplainButton({ target }: { target: ExplainTarget }) {
  const { choose, label } = useExplainMenu();
  return <button type="button" data-explain-ask="" aria-label={label} title={label}
    className="explain-ask inline-flex size-6 items-center justify-center rounded-full text-sm hover:bg-accent"
    onClick={(event) => { event.stopPropagation(); choose(target, event.currentTarget); }}>
    <CircleQuestionMark aria-hidden="true" size={16} />
  </button>;
}

function refocus(opener: HTMLElement) {
  if (!opener.isConnected) return;
  // A mark with no ask inside it cannot take focus. Let it, for this return and without
  // making it a tab stop, or focus falls to <body> and a dialog opened next closes to nowhere.
  if (opener.tabIndex < 0 && !opener.hasAttribute("tabindex")) opener.setAttribute("tabindex", "-1");
  opener.focus({ preventScroll: true });
}

export function ExplainMenuProvider({ aiAvailable, onExplain, children }: PropsWithChildren<{
  aiAvailable: boolean;
  /** `opener` already has focus again when this runs, so a dialog opened from here records
   *  it as the place to return to. */
  onExplain: (target: ExplainTarget, opener: HTMLElement) => void;
}>) {
  const { t } = useLocale();
  const label = aiAvailable ? t.explain.action : t.explain.facts;
  const [menu, setMenu] = useState<ExplainMenuState | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const item = useRef<HTMLButtonElement>(null);
  const handler = useRef(onExplain);
  useEffect(() => { handler.current = onExplain; }, [onExplain]);

  useLayoutEffect(() => {
    if (!menu || !box.current) return;
    const node = box.current;
    node.style.left = Math.max(0, Math.min(menu.x, document.documentElement.clientWidth - node.offsetWidth)) + "px";
    node.style.top = Math.max(0, Math.min(menu.y, document.documentElement.clientHeight - node.offsetHeight)) + "px";
    item.current?.focus({ preventScroll: true });
  }, [menu, label]);

  useEffect(() => {
    if (!menu) return;
    const outside = (event: PointerEvent) => {
      if (!box.current?.contains(event.target as Node)) setMenu(null);
    };
    // A keyboard scroll (Page Down) happens with focus inside the menu, which is about to go.
    const scrolled = () => {
      if (box.current?.contains(document.activeElement)) refocus(menu.opener);
      setMenu(null);
    };
    // The marked element can go while its menu is open: a refetch, or a route change under a
    // provider mounted in the layout. A menu left standing would send the last page's target.
    const gone = new MutationObserver(() => {
      if (!menu.opener.isConnected) setMenu(null);
    });
    document.addEventListener("pointerdown", outside, true);
    window.addEventListener("scroll", scrolled, true);
    gone.observe(document.body, { childList: true, subtree: true });
    return () => {
      document.removeEventListener("pointerdown", outside, true);
      window.removeEventListener("scroll", scrolled, true);
      gone.disconnect();
    };
  }, [menu]);

  const choose = useCallback((target: ExplainTarget, opener: HTMLElement) => {
    setMenu(null);
    refocus(opener);
    handler.current(target, opener);
  }, []);
  // Stable while the label is: every marked element reads this, and a new object on each
  // open and close would re-render all of them.
  const value = useMemo(() => ({ label, open: setMenu, choose }), [label, choose]);

  return <ExplainContext.Provider value={value}>
    {children}
    {menu && createPortal(
      <div role="menu" aria-label={label} ref={box}
        className="fixed z-50 w-max max-w-full rounded-md border bg-popover p-1 text-popover-foreground shadow-md"
        // A click inside must not move focus. WebKit blurs a focused button on mouse down, and
        // a menu that closes on blur was gone before the click arrived (Safari, the Mac app).
        onMouseDown={event => event.preventDefault()}
        // On Windows the Menu key's own contextmenu arrives on key up, at the item.
        onContextMenu={event => event.preventDefault()}
        onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) setMenu(null); }}
        onKeyDown={event => {
          if (event.key === "Escape" || event.key === "Tab") {
            event.preventDefault();
            event.stopPropagation();
            setMenu(null);
            refocus(menu.opener);
          } else if (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Home" || event.key === "End") {
            event.preventDefault();
            item.current?.focus();
          }
        }}>
        <button type="button" role="menuitem" tabIndex={-1} ref={item}
          className="rounded-sm px-3 py-1.5 text-sm hover:bg-accent focus:bg-accent"
          onClick={() => choose(menu.target, menu.opener)}>{label}</button>
      </div>, document.body)}
  </ExplainContext.Provider>;
}
