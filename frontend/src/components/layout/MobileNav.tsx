import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Menu, X } from "lucide-react";
import { NavTree } from "@/components/layout/NavTree";
import { useNavigation } from "@/components/layout/useNavigation";
import { BuildVersion } from "@/features/system/BuildVersion";
import { useLocale } from "@/i18n/LocaleContext";

/** Tailwind's `md`, the breakpoint the sidebar returns at (`md:flex` in Sidebar.tsx).
 *  Mirrored here so the drawer closes itself when the viewport crosses it — a phone
 *  rotated, a window widened — rather than lingering open, with the page's scroll
 *  locked, behind a sidebar that has just come back. */
const SIDEBAR_RETURNS = "(min-width: 48rem)";

const buttonClasses =
  "flex h-9 w-9 items-center justify-center rounded-md border border-input bg-background hover:bg-accent";

/**
 * The navigation below `md` (#141): a menu button in the navbar and the same tree the
 * sidebar draws, in a drawer. Reachability only — the pages themselves have had no
 * pass for a narrow viewport, and that is a separate issue by design.
 *
 * Hand-rolled like the sidebar-mode popover rather than a dependency: a backdrop that
 * closes it, Escape that closes it, focus moved to the close button on open and back to
 * the menu button on close, and the page's scroll held while it is up. It is portalled
 * to `<body>` because the navbar's `backdrop-blur` makes the header the containing block
 * for anything `fixed` inside it, which would pin the drawer to a 56px strip.
 */
export function MobileNav() {
  const { t } = useLocale();
  const items = useNavigation();
  const [open, setOpen] = useState(false);
  const openButton = useRef<HTMLButtonElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;

    const trigger = openButton.current;
    closeButton.current?.focus();

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const sidebarReturns = window.matchMedia(SIDEBAR_RETURNS);
    const onViewportChange = (event: MediaQueryListEvent) => {
      if (event.matches) setOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    sidebarReturns.addEventListener("change", onViewportChange);

    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", onKeyDown);
      sidebarReturns.removeEventListener("change", onViewportChange);
      trigger?.focus();
    };
  }, [open]);

  const close = () => setOpen(false);

  return (
    <>
      <button
        ref={openButton}
        type="button"
        aria-label={t.common.openMenu}
        aria-expanded={open}
        aria-controls="mobile-navigation"
        onClick={() => setOpen(true)}
        className={`${buttonClasses} md:hidden`}
      >
        <Menu className="h-4 w-4" />
      </button>

      {open &&
        createPortal(
          <div className="fixed inset-0 z-50 md:hidden">
            <div className="absolute inset-0 bg-black/50" aria-hidden="true" onClick={close} />
            <div
              id="mobile-navigation"
              role="dialog"
              aria-modal="true"
              aria-label={t.common.menu}
              className="absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col overflow-y-auto border-r bg-background p-4 shadow-lg"
            >
              <div className="mb-3 flex items-center justify-between">
                <span className="font-semibold">{t.common.menu}</span>
                <button
                  ref={closeButton}
                  type="button"
                  aria-label={t.common.closeMenu}
                  onClick={close}
                  className={buttonClasses}
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <NavTree items={items} onNavigate={close} />
              <div className="mt-auto pt-4">
                <BuildVersion />
              </div>
            </div>
          </div>,
          document.body
        )}
    </>
  );
}
