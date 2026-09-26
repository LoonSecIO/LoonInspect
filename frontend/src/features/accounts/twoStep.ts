import { ApiError } from "@/config/api";
import { confirmMfa, enrolMfa } from "@/features/accounts/api";
import type { MfaEnrolment } from "@/features/accounts/types";

/**
 * My Account's two-step set-up panel (#653) as a pure state machine the node test lane can
 * walk: closed → scan (QR code and key) → codes → closed. The recovery codes live only in
 * `codes`, so closing the panel drops them. `refresh` asks the page to read the status
 * again: after a confirm, and after a 409, which means the page's status is stale.
 */
export type Panel =
  | { step: "closed"; error: string | null }
  | { step: "scan"; enrolment: MfaEnrolment; error: string | null }
  | { step: "codes"; codes: string[] };

export type Move = { panel: Panel; refresh: boolean };

export const CLOSED: Panel = { step: "closed", error: null };

// The server's sentence says what to check; `fallback` is for an answer that never came.
const sentence = (caught: unknown, fallback: string): string =>
  caught instanceof ApiError && caught.detail ? caught.detail : fallback;
const conflict = (caught: unknown): boolean => caught instanceof ApiError && caught.status === 409;

export async function startSetUp(fallback: string): Promise<Move> {
  try {
    return { panel: { step: "scan", enrolment: await enrolMfa(), error: null }, refresh: false };
  } catch (caught) {
    return { panel: { step: "closed", error: sentence(caught, fallback) }, refresh: conflict(caught) };
  }
}

export async function confirmCode(enrolment: MfaEnrolment, code: string, fallback: string): Promise<Move> {
  try {
    const confirmed = await confirmMfa(code);
    return { panel: { step: "codes", codes: confirmed.recoveryCodes }, refresh: true };
  } catch (caught) {
    // A 409: nothing waits for a code any more. Anything else (a wrong code) keeps the QR code up.
    if (conflict(caught)) return { panel: { step: "closed", error: sentence(caught, fallback) }, refresh: true };
    return { panel: { step: "scan", enrolment, error: sentence(caught, fallback) }, refresh: false };
  }
}
