import { sentence } from "@/features/accounts/twoStep";
import { submissionStatus, withdrawSubmission, type SubmissionCaseOut } from "@/features/submissions/api";

/** The case list's decisions (#623), pure so the node lane pins them: when Refresh may ask again, which cases
 *  it asks about, what one act answers, what each row button does, and where the answer lands. */

/** The service reads a case's status once a minute, and never before a time it gave (`retryAt`). */
export const FLOOR_MS = 60_000;

/** Whole seconds until Refresh may ask again; 0 when it may now. */
export function refreshWait(item: SubmissionCaseOut, now: number): number {
  const floor = item.lastStatusAt ? Date.parse(item.lastStatusAt) + FLOOR_MS : 0;
  return Math.max(0, Math.ceil((Math.max(floor, item.retryAt ? Date.parse(item.retryAt) : 0) - now) / 1000));
}

/** Never a case the service has not received or has expired, where the route asks nothing, nor a withdrawn one, which is final. */
export const asksStatus = (item: SubmissionCaseOut): boolean => !["pending", "expired", "withdrawn"].includes(item.state);

export type Outcome = { item: SubmissionCaseOut } | { error: string };
const flying = new Set<string>();

/** One act on one case: the answer, or the server's own sentence (a 429 names its seconds), else `fallback`.
 *  A press while that case's act is in flight sends nothing and answers null, so a double click posts once. */
export async function act(kind: "status" | "withdraw", id: string, fallback: string): Promise<Outcome | null> {
  if (flying.has(id)) return null;
  flying.add(id);
  try {
    return { item: await (kind === "status" ? submissionStatus : withdrawSubmission)(id) };
  } catch (caught) {
    return { error: sentence(caught, fallback) };
  } finally {
    flying.delete(id);
  }
}

/** One case's act in flight, its withdrawal question open, or the refusal its last act got. */
export type RowAct = { busy?: boolean; confirming?: boolean; error?: string };
export type Handlers = Record<"refresh" | "ask" | "withdraw" | "cancel", (id: string) => Promise<void> | void>;

/** The row's four buttons. Asking and cancelling only mark the row. Refresh and Withdraw post one act, keeping an open question
 *  up (its buttons disabled) while it flies; then the refusal stays under the row, or `settle` takes the answer and its time. */
export function handlers(setActs: (next: (all: Record<string, RowAct>) => Record<string, RowAct>) => void, fallback: string, settle: (item: SubmissionCaseOut, at: number) => void): Handlers {
  const mark = (id: string, row: RowAct) => setActs((all) => ({ ...all, [id]: row }));
  const run = (id: string, kind: "status" | "withdraw") => {
    setActs((all) => ({ ...all, [id]: { confirming: all[id]?.confirming, busy: true } }));
    return act(kind, id, fallback).then((outcome) => {
      if (outcome === null) return; // that case's act is already in flight
      if ("error" in outcome) return mark(id, { error: outcome.error });
      mark(id, {});
      settle(outcome.item, Date.now());
    });
  };
  return { refresh: (id) => run(id, "status"), ask: (id) => mark(id, { confirming: true }), withdraw: (id) => run(id, "withdraw"), cancel: (id) => mark(id, {}) };
}

/** The answer takes its row's place; the order the server sent, newest first, stays. */
export const replaceCase = (cases: SubmissionCaseOut[], item: SubmissionCaseOut): SubmissionCaseOut[] =>
  cases.map((each) => (each.id === item.id ? item : each));
