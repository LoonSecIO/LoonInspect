import type { CatalogTitleRef } from "@/features/catalog/types";

/**
 * The Jamf Patch answer as a page reads it (#313) — pure, so the rules a cell paints by
 * are pinned in the frontend test lane (`patchAnswer.test.ts`) rather than checked by eye,
 * for the reason `patchLaggards.ts` and `sinceAnchor.ts` are pure.
 *
 * The answer has three subjects and the columns sit next to each other as if they were
 * about one thing (`docs/jamf-patch-matching.md` §7). `patchState` and `latestVersion`
 * are the REFERENCE title's — the one that says latest, else the rolling title. #68's
 * sentence — `patchAvailableSince` and `releasesMissed` — is the SENTENCE title's, the one
 * line whose first missed update is earliest. On Wireshark 4.2.0 those are different
 * titles: `latestVersion` reads 4.6.8 off "Wireshark" and `releasesMissed` reads 14 off
 * "Wireshark 4.2", whose own latest is 4.2.14. Printed side by side they say "14 releases
 * behind 4.6.8", which is true of neither. So a described answer names the subject of
 * each half, and only when there is more than one title to be ambiguous between — the
 * wire's rule (#311), applied at render time.
 */

export type PatchState = "latest" | "behind" | "ahead" | "unknown";

/** The columns every surface that paints the answer shares — `InstalledApp` on the device
 *  page and `CatalogEntry` on the catalog and record pages both satisfy this. */
export interface PatchAnswer {
  jamfTitleIds: string[] | null;
  jamfTitles: CatalogTitleRef[];
  patchState: PatchState | null;
  patchAvailable: boolean | null;
  patchAvailableSince: string | null;
  releasesMissed: number | null;
  latestVersion: string | null;
  eaAssumed: boolean | null;
  referenceTitleId: string | null;
  sentenceTitleId: string | null;
}

/** A matched title as a page prints it: the id always, the name when the catalog could
 *  name it. A null name is rendered as the id in a monospace face with a hint — never as
 *  a name, and never dropped, so the count of titles on the page is the count that
 *  matched. */
export interface TitleLine {
  id: string;
  name: string | null;
}

/** #68's sentence: a date and a count, never a day count. `subject` is the line both
 *  halves come from, named only when several titles matched. */
export interface PatchSentence {
  since: string | null;
  missed: number | null;
  subject: TitleLine | null;
}

export interface DescribedPatchAnswer {
  state: PatchState;
  /** Every matched title, in the stored order: fully-evaluated first, then by name. */
  titles: TitleLine[];
  /** Present only while a patch is available — `ahead` and `latest` carry no sentence. */
  sentence: PatchSentence | null;
  /** What the vendor ships now, per the reference title; `subject` named when several matched. */
  latest: { version: string; subject: TitleLine | null } | null;
  /** True only when the row says so. A null `eaAssumed` (judged before the column existed)
   *  shows no marker and asserts nothing, which is the only honest rendering of "unknown". */
  assumed: boolean;
}

/** The matched titles by name, in stored order, with the id standing in where the catalog
 *  could not name one. */
export function namedTitles(answer: Pick<PatchAnswer, "jamfTitleIds" | "jamfTitles">): TitleLine[] {
  const names = new Map(answer.jamfTitles.map((title) => [title.id, title.name] as const));
  return (answer.jamfTitleIds ?? []).map((id) => ({ id, name: names.get(id) ?? null }));
}

export function describePatchAnswer(answer: PatchAnswer): DescribedPatchAnswer | null {
  if (!answer.patchState) return null;
  const titles = namedTitles(answer);
  // One title needs no subject: it is the subject, and naming it would repeat the titles
  // line. A subject id the titles do not contain cannot happen on a judged row (the wire
  // refuses it); it renders as no subject rather than as a name from nowhere.
  const subject = (id: string | null): TitleLine | null =>
    titles.length > 1 && id !== null ? (titles.find((title) => title.id === id) ?? null) : null;
  return {
    state: answer.patchState,
    titles,
    sentence:
      answer.patchAvailable === true
        ? { since: answer.patchAvailableSince, missed: answer.releasesMissed, subject: subject(answer.sentenceTitleId) }
        : null,
    latest: answer.latestVersion ? { version: answer.latestVersion, subject: subject(answer.referenceTitleId) } : null,
    assumed: answer.eaAssumed === true
  };
}
