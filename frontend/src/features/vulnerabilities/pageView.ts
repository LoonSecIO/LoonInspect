/**
 * What the Vulnerabilities page draws, decided in one place so the node lane can hold it
 * (#529).
 *
 * The rule that is easy to get wrong, and was: **the controls follow the answer in hand,
 * never the request in flight.** A search box gated on "a read is settled" unmounts on the
 * operator's own keystroke — the `<input>` DOM node is destroyed and the caret with it — so
 * refining `chrome` to `chromium` costs a click back into the box every time. What is in
 * flight belongs in the table's body instead, and CONTRIBUTING.md's #479 rule is what turns
 * it on: during the render that moved the input, never from the effect a debounce later.
 */

export type Load = "loading" | "ready" | "silent" | "failed";

/** The one field of `CatalogListResponse` this decision turns on. */
export interface Judged {
  vulnJudged: boolean;
}

export interface PageView {
  /** The corpus banner. `corpusAsOf === null` in it *says* nothing is answering for this
   *  organization, so it waits for a read that came back: a request in flight and one that
   *  failed are not evidence of silence — the rule `corpusStore` keeps for the sidebar. */
  banner: boolean;
  /** The search box, the heading, the table and the pager. */
  controls: boolean;
  /** The table's body is the settled answer for the inputs in hand. */
  rows: boolean;
  /** An epoch is answering and nothing here has been judged against it yet: one sentence
   *  and no list, because every row would read *outside the corpus* (§4a). */
  notJudged: boolean;
}

export function pageView(load: Load, answer: Judged | null): PageView {
  // `silent` is the 409: nothing answers for this organization, so the banner and its *why*
  // block stand alone and an answer from before the tier moved may not outlive it.
  const answering = load !== "silent" && answer !== null && answer.vulnJudged;
  return {
    banner: load === "silent" || answer !== null,
    controls: answering,
    rows: answering && load === "ready",
    notJudged: load === "ready" && answer !== null && !answer.vulnJudged
  };
}
