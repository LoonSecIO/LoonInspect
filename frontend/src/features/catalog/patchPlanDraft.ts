export type ReviewDraft = { revision: number; values: Record<string, string> };
/** Every draft key starts with this, followed by organization, account and plan. */
export const REVIEW_DRAFT_PREFIX = "looninspect.patch-review.";

// A tab that refuses browser storage still keeps notes through client-side navigation.
const memory = new Map<string, ReviewDraft | null>();
const pending = new Set<string>();
let warningSuspensions = 0;
const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
function syncWarning() {
  window.removeEventListener("beforeunload", warn);
  if (pending.size && !warningSuspensions) window.addEventListener("beforeunload", warn);
}
export function watchReviewDraft(key: string) { pending.add(key); syncWarning(); }

export function readReviewDraft(key: string): ReviewDraft | null {
  if (memory.has(key)) return memory.get(key) ?? null;
  try {
    const value = JSON.parse(sessionStorage.getItem(key) ?? "null");
    if (value && Number.isInteger(value.revision) && value.revision >= 1 && value.values && !Array.isArray(value.values)
      && ["owner", "window", "pilot", "recovery", "exceptions", "approval"].every(field => typeof value.values[field] === "string")) return value;
  } catch { /* An unavailable browser store has no restorable persisted draft. */ }
  return null;
}

export function rememberReviewDraft(key: string, draft: ReviewDraft): boolean {
  watchReviewDraft(key);
  try { sessionStorage.setItem(key, JSON.stringify(draft)); memory.delete(key); return true; }
  catch { memory.set(key, draft); return false; }
}

export function forgetReviewDraft(key: string): boolean {
  pending.delete(key); syncWarning();
  try { sessionStorage.removeItem(key); memory.delete(key); return true; }
  catch { memory.set(key, null); return false; }
}

/** An explicit sign-out leaves no account's notes in this tab and disarms their unload and
 *  organization-switch prompts for whoever signs in next. A 401 does not call this, so a
 *  user whose session expired gets their draft back after signing in again. */
export function clearReviewDrafts(): void {
  pending.clear(); memory.clear(); syncWarning();
  let keys: string[];
  try { keys = Array.from({ length: sessionStorage.length }, (_, i) => sessionStorage.key(i) ?? "").filter(key => key.startsWith(REVIEW_DRAFT_PREFIX)); }
  catch { return; /* No readable browser store: the drafts lived only in memory, cleared above. */ }
  for (const key of keys) {
    try { sessionStorage.removeItem(key); } catch { memory.set(key, null); }
  }
}

/** A tenant switch changes the server session before reloading, so any cancellation belongs before that request. */
export function confirmReviewDraftSessionChange(): boolean {
  return !pending.size || window.confirm("Switch organization? Unsaved review notes stay in this browser tab when browser storage is available. Notes held only in memory will be lost on reload; save or copy them before continuing.");
}

/** Suppress our warning only for the reload after a session change; never clear another account's drafts. */
export function suspendReviewDraftUnloadWarning(): () => void {
  warningSuspensions += 1;
  syncWarning();
  let active = true;
  return () => {
    if (!active) return;
    active = false;
    warningSuspensions -= 1;
    syncWarning();
  };
}

export function forgetSubmittedReviewDraft(key: string, submitted: ReviewDraft): boolean {
  const current = readReviewDraft(key);
  if (!current || current.revision !== submitted.revision
    || ["owner", "window", "pilot", "recovery", "exceptions", "approval"].some(field => current.values[field] !== submitted.values[field])) return true;
  return forgetReviewDraft(key);
}
