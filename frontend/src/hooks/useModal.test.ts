/** The modal hold (#686; the drawer's since #141). Node lane (#285): no DOM, so the page, the modal and its
 *  controls are stand-ins that record what the hold does to them. Real focus and a real Tab key are the browser
 *  half, walked by hand (the pull request's Validation names the steps). */

import { describe, expect, it, vi } from "vitest";
import { CONTROLS, holdModal, wrapTab } from "@/hooks/useModal";

type Spot = { name: string; focus: () => void };
type Heard = (event: object) => void;

/** A page holding a modal of `names`, the trigger that opened it, and one control behind it. */
function stage(names = ["first", "middle", "last"], initial?: string) {
  const heard = new Map<string, Heard>();
  const page = {
    body: { style: { overflow: "auto" } },
    activeElement: null as Spot | null,
    defaultView: { scrollX: 0, scrollY: 240, scrollTo: vi.fn() },
    addEventListener: (type: string, listener: Heard) => void heard.set(type, listener),
    removeEventListener: (type: string, listener: Heard) => void (heard.get(type) === listener && heard.delete(type))
  };
  const spot = (name: string): Spot => {
    const made: Spot = { name, focus: () => void (page.activeElement = made) };
    return made;
  };
  const controls = names.map(spot);
  const [trigger, behind] = [spot("trigger"), spot("behind")];
  const box = { querySelectorAll: (selector: string) => (selector === CONTROLS ? controls : []), contains: (node: unknown) => controls.includes(node as Spot) };
  const ref = (current: object) => ({ current: current as HTMLElement });
  const onClose = vi.fn();
  const close = holdModal(page as unknown as Document,
    { container: ref(box), trigger: ref(trigger), initial: initial ? ref(controls[names.indexOf(initial)]) : undefined, onClose });
  /** A key on the page; true when the hold took the step from the browser. */
  const press = (key: string, shiftKey = false) => {
    const event = { key, shiftKey, preventDefault: vi.fn() };
    heard.get("keydown")?.(event);
    return event.preventDefault.mock.calls.length > 0;
  };
  const land = (target: Spot) => {
    page.activeElement = target;
    heard.get("focusin")?.({ target });
  };
  return { page, heard, controls, behind, onClose, close, press, land, at: () => page.activeElement?.name };
}

describe("a modal's hold on the page", () => {
  it("moves focus to its first control and holds the scroll; closing gives the scroll back and focus to the trigger", () => {
    const held = stage();
    expect([held.at(), held.page.body.style.overflow]).toEqual(["first", "hidden"]);
    held.close();
    expect([held.at(), held.page.body.style.overflow, held.heard.size]).toEqual(["trigger", "auto", 0]);
  });

  it("moves focus to the control the modal names instead (the drawer's close button)", () => {
    expect(stage(["first", "close", "last"], "close").at()).toBe("close");
  });

  it("closes on Escape wherever focus is, and on no other key", () => {
    const held = stage();
    held.press("Enter");
    expect(held.onClose).not.toHaveBeenCalled();
    for (const where of [null, held.behind, held.controls[1]]) {
      held.page.activeElement = where;
      held.press("Escape");
    }
    expect(held.onClose).toHaveBeenCalledTimes(3);
  });

  it("wraps Tab at the ends of its controls and leaves every other step to the browser", () => {
    const held = stage();
    held.controls[2].focus();
    expect([held.press("Tab"), held.at()]).toEqual([true, "first"]);
    expect([held.press("Tab", true), held.at()]).toEqual([true, "last"]);
    held.controls[1].focus();
    expect([held.press("Tab"), held.press("Tab", true), held.at()]).toEqual([false, false, "middle"]);
  });

  it("brings focus that lands behind it back to its first control, and the page back to where it was held", () => {
    const held = stage();
    held.land(held.controls[2]);
    expect([held.at(), held.page.defaultView.scrollTo.mock.calls]).toEqual(["last", []]);
    held.land(held.behind);
    expect([held.at(), held.page.defaultView.scrollTo.mock.calls]).toEqual(["first", [[0, 240]]]);
  });

  it("hears nothing once closed", () => {
    const held = stage();
    held.close();
    held.press("Escape");
    held.land(held.behind);
    expect([held.onClose.mock.calls.length, held.at()]).toEqual([0, "behind"]);
  });
});

describe("Tab at the ends", () => {
  it("goes past the last to the first and before the first to the last, and nowhere else", () => {
    const three = ["a", "b", "c"];
    expect([wrapTab(three, "c", false), wrapTab(three, "a", true), wrapTab(["a"], "a", false), wrapTab(["a"], "a", true)]).toEqual(["a", "c", "a", "a"]);
    expect([wrapTab(three, "a", false), wrapTab(three, "c", true), wrapTab(three, "b", false), wrapTab(three, null, false), wrapTab([], null, true)])
      .toEqual([null, null, null, null, null]);
  });

  it("reaches what the drawer's always did (#141): links, and enabled buttons, selects, inputs and text areas", () => {
    expect(CONTROLS).toBe("a[href], button:not([disabled]), select:not([disabled]), input:not([disabled]), textarea:not([disabled])");
  });
});
