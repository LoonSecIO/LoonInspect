import { describe, expect, it } from "vitest";
import { pageView } from "./pageView";

const judged = { vulnJudged: true };
const unjudged = { vulnJudged: false };

/** The page's render gate, held here because the frontend lane is node-only by design
 *  (#285) and a torn-down `<input>` is otherwise a defect only a rendered page can find. */
describe("pageView", () => {
  it("keeps the controls mounted while the read they started is in flight", () => {
    // The defect: gated on a settled read, the search box unmounts on the keystroke that
    // asked for the next one, and the operator has to click back in to refine the term.
    expect(pageView("loading", judged).controls).toBe(true);
    expect(pageView("failed", judged).controls).toBe(true);
    // What is in flight shows in the table's body, not by blanking the box above it.
    expect(pageView("loading", judged).rows).toBe(false);
    expect(pageView("ready", judged)).toMatchObject({ controls: true, rows: true, notJudged: false });
  });

  it("claims nothing about the corpus until a read has come back", () => {
    expect(pageView("loading", null).banner).toBe(false);
    expect(pageView("failed", null).banner).toBe(false);
    expect(pageView("ready", judged).banner).toBe(true);
    // The refusal is the one state that says *nothing is answering* without a response.
    expect(pageView("silent", null).banner).toBe(true);
  });

  it("a refusal closes the list, and an answer from before it does not outlive it", () => {
    expect(pageView("silent", judged)).toMatchObject({ banner: true, controls: false, rows: false, notJudged: false });
  });

  it("loaded and not yet judged is one sentence and no list", () => {
    expect(pageView("ready", unjudged)).toMatchObject({ banner: true, controls: false, rows: false, notJudged: true });
    // Never said on the strength of a read that has not landed.
    expect(pageView("loading", unjudged).notJudged).toBe(false);
  });
});
