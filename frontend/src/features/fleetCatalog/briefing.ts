import type { PromptError } from "@/features/changes/types";

/** The migration briefing's codes (#910), in its order: the report's six app counts, then the Macs in the device filter. The
 *  answer carries a code and a count, never a sentence, so planningCopy.ts words each one. */
export const BRIEFING_CODES = ["apps_overdue", "apps_with_kev", "ambiguous_apps", "incomplete_comparisons", "recurring_review",
  "exact_candidates", "scoped_macs"] as const;
export type BriefingCode = (typeof BRIEFING_CODES)[number];

/** `POST /api/fleet-catalog/briefing`. `selected` is the provider's choice, in its order; `fallback` is the report's first counts,
 *  and `reason` says why: `nothing_to_rank` (only the Mac count, so nothing was sent and no provider is named), `unusable` (no
 *  choice in the reply) or `error` (`error.message` is the adapter's sentence). */
export interface Briefing {
  outcome: "selected" | "fallback";
  highlights: { code: BriefingCode; count: number }[];
  provider: string | null;
  model: string | null;
  reason: "nothing_to_rank" | "unusable" | "error" | null;
  error: PromptError | null;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isText = (value: unknown): value is string => typeof value === "string";
const FALLBACKS: readonly unknown[] = ["nothing_to_rank", "unusable", "error"];

/** Whether a 200's body is that answer, checked before anything reads it, as `isPromptResult` checks the Prompt bar's. Refused: a
 *  code this page cannot word, a count that is not a whole number, a fallback with no reason, an `error` with no sentence, and a
 *  lead that names who answered with no provider and model to name. */
export function isBriefing(value: unknown): value is Briefing {
  if (!isRecord(value) || !Array.isArray(value.highlights)) return false;
  const { outcome, reason, provider, model, error } = value;
  return value.highlights.every(line => isRecord(line) && BRIEFING_CODES.includes(line.code as BriefingCode) && Number.isInteger(line.count))
    && (outcome === "selected" ? reason === null : outcome === "fallback" && FALLBACKS.includes(reason))
    && (provider === null || isText(provider)) && (model === null || isText(model))
    && ((outcome !== "selected" && reason !== "unusable") || (isText(provider) && isText(model)))
    && (error === null ? reason !== "error" : isRecord(error) && isText(error.kind) && isText(error.message));
}
