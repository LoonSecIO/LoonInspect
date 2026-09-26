import { useEffect, useState, type RefObject } from "react";

/**
 * A modal's hold on the page (#141, #686): the navigation drawer and the submission dialog, one copy for both.
 *
 * While it is open, focus moves in (to `initial`, else to its first control), Tab wraps at the ends of its
 * controls, focus that lands behind it comes back, Escape closes it wherever focus is, and the page behind does
 * not scroll. On close the scroll comes back and focus returns to the button that opened it. One at a time: a
 * modal opened over another would read as focus behind it. Hand-rolled rather than a dependency, as the drawer was.
 */

/** What Tab can reach inside a modal, in document order: the drawer's list since #141, unchanged. */
export const CONTROLS = 'a[href], button:not([disabled]), select:not([disabled]), input:not([disabled]), textarea:not([disabled])';

type Held = RefObject<HTMLElement | null>;
type Modal = { container: Held; trigger: Held; initial?: Held; onClose: () => void };

/** Where Tab moves focus at the ends of a modal's controls: past the last to the first, and with Shift before
 *  the first round to the last. Anywhere else it is null, and the browser takes the step. */
export function wrapTab<T>(controls: readonly T[], active: unknown, shift: boolean): T | null {
  if (controls.length === 0) return null;
  const first = controls[0];
  const last = controls[controls.length - 1];
  if (shift && active === first) return last;
  if (!shift && active === last) return first;
  return null;
}

/** `useModal`'s effect, apart from React so the node lane can drive it with a stand-in page (#285: no DOM). It
 *  returns the close. */
export function holdModal(page: Document, { container, trigger, initial, onClose }: Modal): () => void {
  const controls = () => Array.from(container.current?.querySelectorAll<HTMLElement>(CONTROLS) ?? []);
  const opener = trigger.current;
  const view = page.defaultView;
  const scrolled = { x: view?.scrollX ?? 0, y: view?.scrollY ?? 0 };
  (initial ? initial.current : controls()[0])?.focus();

  const previousOverflow = page.body.style.overflow;
  page.body.style.overflow = "hidden";

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") onClose();
    if (event.key === "Tab") {
      const next = wrapTab(controls(), page.activeElement, event.shiftKey);
      if (next) {
        event.preventDefault();
        next.focus();
      }
    }
  };
  // Focus that lands behind the modal comes back to its first control, and the page to where it was held. The
  // wrap above cannot see this case: a control that goes away with focus on it (the dialog's Send, once answered)
  // leaves focus on the page, and the browser's next Tab steps behind the modal, scrolling to what it lands on.
  const onFocusIn = (event: FocusEvent) => {
    const box = container.current;
    if (!box || box.contains(event.target as Node)) return;
    controls()[0]?.focus();
    view?.scrollTo(scrolled.x, scrolled.y);
  };
  page.addEventListener("keydown", onKeyDown);
  page.addEventListener("focusin", onFocusIn);

  return () => {
    page.body.style.overflow = previousOverflow;
    page.removeEventListener("keydown", onKeyDown);
    page.removeEventListener("focusin", onFocusIn);
    opener?.focus();
  };
}

/** A modal's open state and, while it is true, its hold on the page. The three refs are the caller's own. */
export function useModal(container: Held, trigger: Held, initial?: Held) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    return holdModal(document, { container, trigger, initial, onClose: () => setOpen(false) });
  }, [open, container, trigger, initial]);
  return [open, setOpen] as const;
}
