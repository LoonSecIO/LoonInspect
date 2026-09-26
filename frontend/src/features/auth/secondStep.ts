import { ApiError } from "@/config/api";
import type { MfaChallenge } from "@/features/auth/types";
import type { Translations } from "@/i18n/en";

/** The sign-in page's second step (#653), as data: the challenge the password earned, which
 *  input shows (a six-digit code or a recovery code), what is typed, and the last refusal.
 *  null is the password step, so starting over keeps nothing of the challenge. */
export interface SecondStep {
  challenge: MfaChallenge;
  recovery: boolean;
  code: string;
  error: string | null;
}

export type SecondStepAction =
  | { type: "challenged"; challenge: MfaChallenge }
  | { type: "typed"; code: string }
  | { type: "switched" }
  | { type: "sent" }
  | { type: "refused"; error: string }
  | { type: "start-over" };

/** How LoginPage moves the step, as a reducer so each move is testable without a DOM. */
export function secondStep(step: SecondStep | null, action: SecondStepAction): SecondStep | null {
  if (action.type === "challenged") return { challenge: action.challenge, recovery: false, code: "", error: null };
  if (step === null || action.type === "start-over") return null;
  if (action.type === "typed") return { ...step, code: action.code };
  // The two shapes share nothing: half a six-digit code is not half a recovery code.
  if (action.type === "switched") return { ...step, recovery: !step.recovery, code: "", error: null };
  // Cleared as the password step clears its line, so a second refusal is announced afresh.
  if (action.type === "sent") return { ...step, error: null };
  // A refused six-digit code is wrong or spent and the next try is a new one; a recovery
  // code stays, so a typo in it can be seen.
  return { ...step, code: step.recovery ? step.code : "", error: action.error };
}

/** What the second step says when it is refused. A 401 carries the server's own sentence (a
 *  wrong or spent code, or a challenge past its five minutes), shown as it came, which is the
 *  wording docs/troubleshooting.md §20 is written against; a lockout reads as it does on the
 *  password step. Nothing is invented for a refusal that arrives without a sentence. */
export function secondStepError(caught: unknown, copy: Translations["auth"]): string {
  if (!(caught instanceof ApiError)) return copy.genericError;
  if (caught.status === 429) return copy.lockedOut;
  return caught.status === 401 && caught.detail ? caught.detail : copy.genericError;
}
