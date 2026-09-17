import { describe, expect, it } from "vitest";
import { answeringKeys } from "./corpusStore";

/** The one decision this store makes (#529), held where the node lane can hold it: what the
 *  navigation tree is handed, for each of the three reads. */
describe("answeringKeys", () => {
  it("answers only for a date from a read that landed", () => {
    expect([...answeringKeys("read", "2026-09-17")]).toEqual(["corpus"]);
    expect([...answeringKeys("read", null)]).toEqual([]);
  });

  it("a read that failed, and one still in flight, are empty — never 'off'", () => {
    // Both hide the entry, and neither is evidence that the corpus is silent: `read` keeps
    // them distinguishable from `read`+`null` for anything that ever needs to say why (#150).
    expect([...answeringKeys("failed", null)]).toEqual([]);
    expect([...answeringKeys("loading", null)]).toEqual([]);
    // A date left over from a previous answer cannot list the entry under either of them.
    expect([...answeringKeys("failed", "2026-09-17")]).toEqual([]);
    expect([...answeringKeys("loading", "2026-09-17")]).toEqual([]);
  });
});
