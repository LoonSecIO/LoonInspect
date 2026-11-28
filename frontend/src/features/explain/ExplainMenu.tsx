import { useEffect, useLayoutEffect, useRef, useState, type PropsWithChildren } from "react";
import { CircleQuestionMark } from "lucide-react";
import { createPortal } from "react-dom";
import { useLocale } from "@/i18n/LocaleContext";
import { ExplainContext, useExplainMenu, type ExplainMenuState, type ExplainTarget } from "./useExplainable";
import "./explainMenu.css";

export function ExplainButton({ target }: { target: ExplainTarget }) {
  const { choose, label } = useExplainMenu();
  return <button type="button" aria-label={label} title={label}
    className="explain-ask inline-flex size-6 items-center justify-center rounded-full text-sm hover:bg-accent"
    onClick={(event) => { event.stopPropagation(); choose(target); }}>
    <CircleQuestionMark aria-hidden="true" size={16} />
  </button>;
}

export function ExplainMenuProvider({ aiAvailable, onExplain, children }: PropsWithChildren<{
  aiAvailable: boolean;
  onExplain: (target: ExplainTarget) => void;
}>) {
  const { t } = useLocale();
  const label = aiAvailable ? t.explain.action : t.explain.facts;
  const [menu, setMenu] = useState<ExplainMenuState | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const item = useRef<HTMLButtonElement>(null);

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
    const close = () => setMenu(null);
    document.addEventListener("pointerdown", outside, true);
    window.addEventListener("scroll", close, true);
    return () => {
      document.removeEventListener("pointerdown", outside, true);
      window.removeEventListener("scroll", close, true);
    };
  }, [menu]);

  function choose(target: ExplainTarget) {
    setMenu(null);
    onExplain(target);
  }

  return <ExplainContext.Provider value={{ label, open: setMenu, choose }}>
    {children}
    {menu && createPortal(
      <div role="menu" aria-label={label} ref={box}
        className="fixed z-50 w-max max-w-full rounded-md border bg-popover p-1 text-popover-foreground shadow-md"
        onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) setMenu(null); }}
        onKeyDown={event => {
          if (event.key === "Escape") {
            event.preventDefault();
            event.stopPropagation();
            setMenu(null);
            menu.opener.focus({ preventScroll: true });
          } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            item.current?.focus();
          }
        }}>
        <button type="button" role="menuitem" ref={item}
          className="rounded-sm px-3 py-1.5 text-sm hover:bg-accent focus:bg-accent"
          onClick={() => choose(menu.target)}>{label}</button>
      </div>, document.body)}
  </ExplainContext.Provider>;
}
