import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import type { Provider } from "@/features/ai/api";
import { askPrompt, getPromptStatus } from "@/features/changes/api";
import { PromptAnswer } from "@/features/changes/PromptAnswer";
import {
  browserZone,
  failureReason,
  filtersOnArrival,
  isPromptStatus,
  MAX_QUESTION_CHARS,
  modelOptions,
  proposedFilters,
  providerLabel,
  readReply,
  replyDisposition,
  stillShowing,
  type AskSettled,
  type PageAt
} from "@/features/changes/prompt";
import type { ChangeFilters, PromptResult, PromptStatus } from "@/features/changes/types";
import { useLocale } from "@/i18n/LocaleContext";

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50";

// The address bar, not the router: the router's location lags a navigation by a
// transition, and that lag is the window `replyDisposition` closes.
const pageAt = (): PageAt => ({ pathname: window.location.pathname, search: window.location.search });

interface PromptBarProps {
  /** The page's filters now. An answer about filters the page no longer shows is hidden. */
  filters: ChangeFilters;
  /** Replaces the page's filters: every key present, the cleared ones as undefined. */
  onApply: (next: Partial<ChangeFilters>) => void;
  /** Told whether the bar holds anything the page's Clear would empty — text in the box,
   *  a question in flight, or an answer — each time that changes. A new session is empty. */
  onUse?: (inUse: boolean) => void;
  /** A new value starts a new session — the page's Clear: the box and its answer empty,
   *  and a question still in flight is dropped. The status and the Model picked stay. */
  session?: number;
}

/**
 * The Changes Prompt bar. A question goes to this server, which sends it — and nothing
 * of the fleet — to a provider saved in Settings › AI; filter settings come back and the
 * controls below move to them, so the model's reading is always on screen and always
 * editable. Postgres does the filtering and the counting, never the model.
 *
 * An answer the server had to correct in a way that widens it comes back as a proposal
 * instead (ruled 1C, #436): the corrections, what its filters would show, and an Apply
 * button; the controls move only when the operator presses it.
 *
 * Shown only when the server says it can be used: the AI flag on, the AI-inference
 * consent granted, a provider saved. Settings › AI names which of the three is missing.
 *
 * The status read lives here and the question lives in `PromptSession`, so a Clear starts
 * a new session without reading the status again — the bar would vanish while it loaded
 * and the page below it would jump.
 */
export function PromptBar({ filters, onApply, onUse, session = 0 }: PromptBarProps) {
  const { t } = useLocale();
  const tp = t.changes.prompt;

  const [status, setStatus] = useState<PromptStatus | null>(null);
  // Kept as the error rather than its sentence, so the sentence follows the locale. A
  // null error is a body that arrived but was not the status (`failureReason` reads it).
  const [statusFailure, setStatusFailure] = useState<{ error: unknown } | null>(null);
  const [provider, setProvider] = useState<Provider | null>(null);

  useEffect(() => {
    let cancelled = false;
    // Two handlers rather than a trailing catch, so only the request's own failure is
    // read as one; a body that is not the status is unreadable, never "did not answer".
    getPromptStatus().then(
      (loaded: unknown) => {
        if (cancelled) return;
        if (!isPromptStatus(loaded)) {
          setStatusFailure({ error: null });
          return;
        }
        setStatus(loaded);
        setProvider(loaded.providers[0]?.provider ?? null);
      },
      (error: unknown) => {
        // `available: false` is silence — the bar is an addition to the filters, and
        // Settings › AI says what it waits on. A read that failed is not that answer.
        if (!cancelled) setStatusFailure({ error });
      }
    );
    return () => {
      cancelled = true;
    };
  }, []);

  if (statusFailure !== null) {
    return <p className="text-xs text-muted-foreground">{tp.statusFailed(failureReason(statusFailure.error, tp))}</p>;
  }
  if (!status?.available || provider === null) return null;

  return (
    <PromptSession
      key={session}
      providers={status.providers}
      provider={provider}
      onProvider={setProvider}
      filters={filters}
      onApply={onApply}
      onUse={onUse}
    />
  );
}

interface PromptSessionProps {
  providers: PromptStatus["providers"];
  provider: Provider;
  onProvider: (provider: Provider) => void;
  filters: ChangeFilters;
  onApply: (next: Partial<ChangeFilters>) => void;
  onUse?: (inUse: boolean) => void;
}

/**
 * One session of the bar: the question, its answer, and the question in flight. The
 * page's Clear replaces it with a new one (a new `key`), and this one's unmount aborts
 * what it had in flight — so a reply that lands after a Clear is dropped, never applied
 * over the page the operator just cleared.
 */
function PromptSession({ providers, provider, onProvider, filters, onApply, onUse }: PromptSessionProps) {
  const { t } = useLocale();
  const tp = t.changes.prompt;
  const questionId = useId();
  const modelId = useId();

  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [result, setResult] = useState<PromptResult | null>(null);
  const [applied, setApplied] = useState<Partial<ChangeFilters> | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  // An answer that came back after the operator moved the filters by hand: not applied.
  const [stale, setStale] = useState(false);

  // The question in flight. Aborted when the bar goes away, the page's Clear starts a new
  // session, or a newer question replaces it, so its reply is dropped: a reply that landed
  // after the operator had left the Changes page used to call `onApply` anyway, and the
  // router's navigate took them back. The abort alone leaves the router's transition
  // open — see `replyDisposition`.
  const inFlight = useRef<AbortController | null>(null);
  useEffect(() => () => inFlight.current?.abort(), []);

  // The page's `onApply` as of its latest render rather than the Enter press: the reply
  // lands seconds later, and the page may have moved in between.
  const latestApply = useRef(onApply);
  useEffect(() => {
    latestApply.current = onApply;
  });

  // Whether this session holds anything the page's Clear would clear: text in the box, a
  // question in flight, or an answer on screen. Reported as it changes, not latched on
  // first use, so erasing the box disables Clear again instead of offering a press that
  // does nothing.
  const inUse = question !== "" || asking || result !== null || refusal !== null || stale;
  useEffect(() => {
    onUse?.(inUse);
  }, [inUse, onUse]);

  // Enter submits the form; nothing is sent per keystroke. Apple's on-device model is one
  // lock for the whole Mac, so typing must not queue a call for every letter.
  async function handleAsk(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const text = question.trim();
    if (!text || asking) return;
    // The box is disabled while asking, so this is the backstop rather than the path.
    inFlight.current?.abort();
    const controller = new AbortController();
    inFlight.current = controller;
    const askedAt = pageAt();
    setAsking(true);
    setRefusal(null);
    setResult(null);
    setApplied(null);
    setStale(false);
    // Settled before anything reads it: a rejection is the request's own failure, and a
    // body is checked before use, so a 200 that is not the answer is never misread as a
    // question that did not reach the server (`readReply`).
    // The zone goes with the question so "today" and "since Monday" mean the operator's day (#444).
    const settled: AskSettled = await askPrompt({ question: text, provider, zone: browserZone() }, controller.signal).then(
      (body: unknown): AskSettled => ({ ok: true, body }),
      (error: unknown): AskSettled => ({ ok: false, error })
    );
    const latest = inFlight.current === controller;
    if (latest && !controller.signal.aborted) {
      inFlight.current = null;
      setAsking(false);
    }
    // Aborted, replaced, or the operator already on another page: dropped, not a failure.
    const disposition = replyDisposition(askedAt, pageAt(), controller.signal.aborted, latest);
    if (disposition === "drop") return;
    const reading = readReply(settled, tp);
    if ("refusal" in reading) {
      setRefusal(reading.refusal);
      return;
    }
    const response = reading.result;
    // Only an applied answer moves the page on arrival. A proposal (a correction widened
    // the model's answer, ruled 1C) waits for its Apply button, so it is shown even if
    // the filters moved while it was out: it overwrites nothing until a person says so.
    const next = filtersOnArrival(response);
    // Stale only matters when there is something to apply: an endpoint failure or an
    // answer that was not filters moves nothing, and still says why the question failed.
    if (next !== null && disposition === "stale") {
      setStale(true);
      return;
    }
    // Auto-apply (ruled 2026-09-14): the controls move, and the normal fetch runs.
    if (next !== null) {
      setApplied(next);
      latestApply.current(next);
    }
    setResult(response);
  }

  // A proposal's Apply button: the operator's own press, on the filters the proposal
  // shows, so it replaces whatever the page shows now, as a hand-set filter would.
  function applyProposal() {
    const next = result === null ? null : proposedFilters(result);
    if (next === null) return;
    setApplied(next);
    latestApply.current(next);
  }

  const label = providerLabel(provider, t.ai.providerLabels);
  const current = applied === null || stillShowing(applied, filters);

  return (
    <div className="space-y-2">
      <form className="flex flex-wrap items-end gap-3" aria-busy={asking} onSubmit={(event) => void handleAsk(event)}>
        {/* Labelled by `for`/`id` rather than by nesting alone, so the box is named by
            "Prompt" and not by its placeholder. */}
        <div className="min-w-64 flex-1 space-y-1 text-sm">
          <label htmlFor={questionId} className="block text-muted-foreground">
            {tp.label}
          </label>
          <input
            id={questionId}
            className={`${inputClasses} w-full`}
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder={tp.placeholder}
            maxLength={MAX_QUESTION_CHARS}
            disabled={asking}
          />
        </div>
        {/* Always shown, one saved provider or three: it is the only place on this page
            that says which card and which model will answer. With one saved it was hidden,
            and nothing on screen named what the question went to until the answer did. */}
        {/* max-w-full: a select is as wide as its longest option, and "Apple Foundation
            Models via Docker Desktop · system" is wider than a phone's column. */}
        <div className="min-w-0 max-w-full space-y-1 text-sm">
          <label htmlFor={modelId} className="block text-muted-foreground">
            {tp.model}
          </label>
          <select
            id={modelId}
            className={`${inputClasses} max-w-full`}
            value={provider}
            disabled={asking}
            onChange={(e) => onProvider(e.target.value as Provider)}
          >
            {modelOptions(providers, t.ai.providerLabels).map((option) => (
              <option key={option.value} value={option.value}>
                {option.text}
              </option>
            ))}
          </select>
        </div>
        <Button type="submit" size="sm" disabled={asking || question.trim() === ""}>
          {tp.ask}
        </Button>
      </form>
      <p role="status" className="text-xs text-muted-foreground">
        {asking ? tp.asking(label) : null}
      </p>
      <PromptAnswer
        result={current ? result : null}
        refusal={refusal}
        stale={stale}
        applied={applied !== null}
        onApplyProposal={applyProposal}
      />
    </div>
  );
}
