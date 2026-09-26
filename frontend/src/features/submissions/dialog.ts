import { sentence } from "@/features/accounts/twoStep";
import type { CatalogEntry } from "@/features/catalog/types";
import { previewSubmission, sendSubmission, SUBMISSION_PLATFORMS } from "@/features/submissions/api";
import type { SubmissionCaseOut, SubmissionIn, SubmissionKind, SubmissionPreviewOut } from "@/features/submissions/api";

/** The submission dialog (#623) as data, so the node lane walks every move. The row names the case, the
 *  administrator types three optional fields; a preview is kept with the body it was asked for, and an edit drops
 *  it and both one-time boxes. No text rule is checked here: the server's sentence is the rule (troubleshooting §21). */
export type Named = Pick<SubmissionIn, "kind" | "appName" | "bundleId" | "platform" | "versions" | "finding" | "findingRelease">;
export type Typed = { publicUrl: string; text: string; contact: string };
export type Shown = { body: SubmissionIn; answer: SubmissionPreviewOut };
export type Dialog = { typed: Typed; shown: Shown | null; permission: boolean; override: boolean; busy: boolean; error: string | null; sent: SubmissionCaseOut | null };
export type Move = { type: "typed"; field: keyof Typed; value: string } | { type: "ticked"; box: "permission" | "override"; on: boolean }
  | { type: "asked" } | { type: "previewed"; shown: Shown } | { type: "sent"; sent: SubmissionCaseOut } | { type: "refused"; error: string };

export const OPENED: Dialog = { typed: { publicUrl: "", text: "", contact: "" }, shown: null, permission: false, override: false, busy: false, error: null, sent: null };
export const HTTPS = /^https:\/\/[!-~]+$/; // backend/app/schemas/submissions.py's `Url`
export const TEXT_LIMIT = 2000;

/** An empty field goes as null, which the contract reads as absent. */
export const bodyOf = (named: Named, typed: Typed): SubmissionIn =>
  ({ ...named, publicUrl: typed.publicUrl.trim() || null, text: typed.text || null, contact: typed.contact.trim() || null });

export function dialog(state: Dialog, move: Move): Dialog {
  switch (move.type) {
    case "typed": return { ...state, typed: { ...state.typed, [move.field]: move.value }, shown: null, permission: false, override: false };
    case "ticked": return move.box === "permission" ? { ...state, permission: move.on } : { ...state, override: move.on };
    case "asked": return { ...state, busy: true, error: null };
    case "previewed": return { ...state, busy: false, shown: move.shown, permission: false, override: false };
    case "sent": return { ...state, busy: false, sent: move.sent };
    case "refused": return { ...state, busy: false, error: move.error };
  }
}

/** Send's one condition: a preview of exactly the body these fields make, permission, the override where the
 *  exclusion list names the app, nothing in flight, and no answer yet past `pending` (a retry is the same case). */
export const canSend = (state: Dialog, body: SubmissionIn): boolean =>
  state.shown !== null && JSON.stringify(state.shown.body) === JSON.stringify(body) && state.permission &&
  (state.shown.answer.excludedBy === null || state.override) && !state.busy && (state.sent?.state ?? "pending") === "pending";

/** One request at a time: a press while one is in flight sends nothing, so a double click sends once. */
export function oneAtATime(dispatch: (move: Move) => void) {
  let flying = false;
  return async (ask: () => Promise<Move>) => {
    if (flying) return;
    flying = true;
    dispatch({ type: "asked" });
    dispatch(await ask().finally(() => (flying = false)));
  };
}

const refused = (fallback: string) => (caught: unknown): Move => ({ type: "refused", error: sentence(caught, fallback) });
export const askPreview = (body: SubmissionIn, fallback: string): Promise<Move> =>
  previewSubmission(body).then((answer): Move => ({ type: "previewed", shown: { body, answer } }), refused(fallback));
/** The previewed body as it was shown, with permission and, where the list names the app, the override. */
export const askSend = ({ body, answer }: Shown, override: boolean, fallback: string): Promise<Move> =>
  sendSubmission({ ...body, permission: true, excludedOverride: override && answer.excludedBy !== null })
    .then((sent): Move => ({ type: "sent", sent }), refused(fallback));

/** The case one catalog row names: that build's own strings, never the other versions the fleet shows; null on
 *  a platform the service does not take, or a row with no version to name. A correction adds its finding. */
export function caseOf(entry: CatalogEntry, kind: SubmissionKind): Named | null {
  const platform = SUBMISSION_PLATFORMS.find((name) => name === entry.platform);
  const versions = [...new Set([entry.version, entry.shortVersion].filter((version): version is string => !!version))];
  return platform && versions.length > 0 ? { kind, appName: entry.name, bundleId: entry.bundleId || null, platform, versions } : null;
}

/** Request coverage: an `unknown_app` build, an administrator, and the preview on, whatever the sharing choice. */
export const coverageFor = (entry: CatalogEntry, canWrite: boolean, enabled: boolean): Named | null =>
  canWrite && enabled && entry.vuln.assessment === "unknown_app" ? caseOf(entry, "coverage") : null;
