import { describePatchAnswer, type PatchAnswer, type TitleLine } from "@/features/catalog/patchAnswer";
import type { AppUpdate, AppVulnerability } from "@/features/vulnerabilities/types";

/**
 * What a cell prints beside a build's findings when an update would change them (#482) —
 * pure, so the rules are pinned in the frontend test lane rather than checked by eye, for
 * the reason `patchAnswer.ts` gives.
 *
 * **Every line names its own title, and ONE line is built.** The answer has a subject and
 * the columns sit next to each other as if it did not (#311/#313): on Wireshark 4.2.0,
 * "Wireshark" names 4.6.8 and "Wireshark 4.2" names 4.2.14, so a difference read as the
 * other title's is true of neither. Attribution is therefore built and pinned, and the
 * return is a LIST so a second entry can join it. But only the REFERENCE title's target is
 * built: the row stores one `vuln_target_key`, so 4.2.14 — the update most admins would
 * actually push — gets no line and is not mentioned. #482's done-when asks for a line per
 * named title and this is short of it; the missing half needs a stored answer per
 * `app_catalog_title_matches` row, which `installed_apps` has no path to and which is a
 * new stored shape rather than a clause here. **Unruled cut, raised on the PR and asked on
 * #482.** Until it is ruled, no name in this file or its test may claim the rule is
 * implemented.
 *
 * **Nothing at all unless the build itself is `covered`.** §4g's three renderings do not
 * collapse and this is not a fourth state: `off` and `unknown_app` carry no counts, so
 * there is nothing to close and a difference there would be a count read off a row nobody
 * answered.
 */
export interface UpdateLine {
  /** The release the update would land on. */
  version: string;
  /** The matched title that names that release, when more than one title matched. */
  subject: TitleLine | null;
  /** The corpus holds no row for the target: *outside the corpus*, never *closes all*. */
  unknown: boolean;
  /** Exact — a difference of the two id lists — and present only when neither was capped. */
  closes: number | null;
  opens: number | null;
  /** The difference of the uncapped totals, for a capped pair. Positive closes findings. */
  net: number | null;
}

export function describeUpdate(
  vuln: AppVulnerability,
  update: AppUpdate | null | undefined,
  answer: PatchAnswer
): UpdateLine[] {
  if (vuln.assessment !== "covered" || !update) return [];
  const latest = describePatchAnswer(answer)?.latest ?? null;
  // One entry, and the list shape is not a promise that there will be more: the second
  // line — the in-branch target, "Wireshark 4.2" → 4.2.14 — is not built, and the
  // docstring above says whose ruling that is waiting on.
  return [
    {
      version: update.version,
      // Only the subject for THIS release. A subject read off a patch answer that has
      // moved since the row was judged would name the wrong title, which is the exact
      // misreading #311 exists to remove.
      subject: latest && latest.version === update.version ? latest.subject : null,
      unknown: update.assessment === "unknown_app",
      closes: update.closes,
      opens: update.opens,
      net: update.net
    }
  ];
}
