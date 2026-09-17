import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { Button } from "@/components/ui/button";
import type { Provider } from "@/features/ai/api";
import { bannerKind, failureReason, isPromptStatus, MAX_QUESTION_CHARS, modelOptions, providerLabel, type AskSettled } from "@/features/changes/prompt";
import type { PromptStatus } from "@/features/changes/types";
import { findingIdIn, findingRoute } from "@/features/vulnerabilities/findingId";
import {
  askLever,
  filtersOnArrival,
  getLeverStatus,
  leverReadback,
  readLever,
  readLeverReply,
  stillShows,
  writeLever,
  type LeverShown,
  type VulnPromptFilters,
  type VulnPromptResult
} from "@/features/vulnerabilities/prompt";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * The Vulnerabilities page's search box and its **AI** lever (#534).
 *
 * Off — the default, and what a browser that has never seen the lever gets — the box is what
 * #529 and #533 built: what is typed narrows the lists by name, bundle id and version, and an
 * id shape routes to that id's own page on Enter. On, Enter sends the question to this server,
 * which sends it, and nothing of the fleet, to a provider saved in Settings › AI; this page's
 * filters come back and move. Postgres filters and counts, never the model.
 *
 * The lever is drawn only while the server says the bar is available — the flag, the consent, a
 * saved provider. Otherwise there is no lever and no mention of one. An id is never asked
 * about: whatever the lever says, an id on Enter is a lookup, so nothing leaves the pod for it.
 */

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50";

interface SearchBoxProps {
  term: string;
  onTerm: (next: string) => void;
  /** Told each time the box changes what it is: a search box, or a question box. The page
   *  reads its `q` from the box in the first case and from an applied answer in the second. */
  onMode: (asks: boolean) => void;
  /** The page's whole filter state, as an applied or freshly-applied proposal sets it. */
  onApply: (filters: VulnPromptFilters) => void;
  /** What the page shows now, whole: an answer that no longer describes it goes (`stillShows`). */
  shown: LeverShown;
}

export function SearchBox({ term, onTerm, onMode, onApply, shown }: SearchBoxProps) {
  const { t } = useLocale();
  const copy = t.vulnerabilities;
  // The shared mechanism's shared words: the two bars fail the same ways (`prompt.ts`).
  const tp = t.changes.prompt;
  const navigate = useNavigate();
  const boxId = useId();
  const modelId = useId();

  const [status, setStatus] = useState<PromptStatus | null>(null);
  const [statusFailure, setStatusFailure] = useState<{ error: unknown } | null>(null);
  const [provider, setProvider] = useState<Provider | null>(null);
  const [on, setOn] = useState(readLever);
  const [asking, setAsking] = useState(false);
  const [result, setResult] = useState<VulnPromptResult | null>(null);
  const [applied, setApplied] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const inFlight = useRef<AbortController | null>(null);

  useEffect(() => {
    let cancelled = false;
    getLeverStatus().then(
      (loaded: unknown) => {
        if (cancelled) return;
        // A body that is not the status is unreadable, never "did not answer".
        if (!isPromptStatus(loaded)) return setStatusFailure({ error: null });
        setStatus(loaded);
        setProvider(loaded.providers[0]?.provider ?? null);
      },
      (error: unknown) => !cancelled && setStatusFailure({ error })
    );
    return () => {
      cancelled = true;
      inFlight.current?.abort();
    };
  }, []);

  const available = status?.available === true && provider !== null;
  const asks = available && on;
  useEffect(() => {
    onMode(asks);
    // The page's own callback identity is not a reason to re-announce the mode.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [asks]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // An id is a lookup whatever the lever says, and nothing leaves the pod for one (#533).
    const route = findingRoute("Enter", term);
    if (route) return navigate(route);
    const text = term.trim();
    if (!asks || provider === null || !text || asking) return;
    inFlight.current?.abort();
    const controller = new AbortController();
    inFlight.current = controller;
    setAsking(true);
    setRefusal(null);
    setResult(null);
    setApplied(false);
    const settled: AskSettled = await askLever({ question: text, provider }, controller.signal).then(
      (body: unknown): AskSettled => ({ ok: true, body }),
      (error: unknown): AskSettled => ({ ok: false, error })
    );
    if (controller.signal.aborted || inFlight.current !== controller) return;
    inFlight.current = null;
    setAsking(false);
    const reading = readLeverReply(settled, tp);
    if ("refusal" in reading) return setRefusal(reading.refusal);
    setResult(reading.result);
    // Auto-apply (ruling 2); a proposal waits for its button (ruling 9).
    const next = filtersOnArrival(reading.result);
    if (next) {
      setApplied(true);
      onApply(next);
    }
  }

  function applyProposal() {
    if (result?.outcome !== "proposed" || !result.filters) return;
    setApplied(true);
    onApply(result.filters);
  }

  const at = result?.filters ?? null;
  // Asked of `stillShows`, which is pinned: all three filter dimensions and the order the page
  // WILL rank by, never the raw one.
  const movedOn = applied && at !== null && !stillShows(at, shown);
  // Slot 1's own chain (`bannerKind`), not a second reading of it: `invalid` is decided before
  // `filters === null`, and a refusal always arrives with no filters. This page shows no banner
  // for the three states that are an answer — its proposal, caveat and readback are below.
  const kind = result === null ? null : bannerKind(result, applied);
  const banner =
    kind === "error" ? tp.unavailable : kind === "invalid" ? tp.invalid(copy.aiLeverName) : kind === "unparseable" ? tp.unparseable : null;

  return (
    <div className="space-y-2">
      <form className="flex flex-wrap items-end gap-3" aria-busy={asking} onSubmit={(event) => void handleSubmit(event)}>
        <div className="min-w-64 flex-1 space-y-1 text-sm">
          <label htmlFor={boxId} className="sr-only">
            {asks ? copy.aiLabel : copy.searchPlaceholder}
          </label>
          <input
            id={boxId}
            className={`${inputClasses} w-full`}
            placeholder={asks ? copy.aiPlaceholder : copy.searchPlaceholder}
            value={term}
            maxLength={asks ? MAX_QUESTION_CHARS : undefined}
            disabled={asking}
            onChange={(event) => onTerm(event.target.value)}
          />
        </div>
        {/* No lever unless the server says the bar is available, and no mention of one. */}
        {available && (
          <label className="flex items-center gap-2 pb-2 text-sm">
            <input
              type="checkbox"
              checked={on}
              onChange={(event) => {
                setOn(event.target.checked);
                writeLever(event.target.checked);
                // Flipping it starts over: an answer describes a question this box is no
                // longer asking, and off, what is in the box is about to be the search.
                setResult(null);
                setRefusal(null);
                setApplied(false);
              }}
            />
            {copy.aiLever}
          </label>
        )}
        {asks && provider !== null && (
          <>
            {/* The Model list as the Changes bar shows it (ruling 7): one option per saved
                card, so what will answer is on screen before anything is asked. */}
            <div className="min-w-0 max-w-full space-y-1 text-sm">
              <label htmlFor={modelId} className="block text-muted-foreground">
                {tp.model}
              </label>
              <select
                id={modelId}
                className={`${inputClasses} max-w-full`}
                value={provider}
                disabled={asking}
                onChange={(event) => setProvider(event.target.value as Provider)}
              >
                {modelOptions(status?.providers ?? [], t.ai.providerLabels).map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.text}
                  </option>
                ))}
              </select>
            </div>
            <Button type="submit" size="sm" disabled={asking || term.trim() === ""}>
              {tp.ask}
            </Button>
          </>
        )}
      </form>

      {statusFailure !== null && <p className="text-xs text-muted-foreground">{tp.statusFailed(failureReason(statusFailure.error, tp))}</p>}
      {asks && <p className="text-xs text-muted-foreground">{copy.aiHint}</p>}
      {/* Said where the typing is, because the lists below have gone back to unfiltered: no
          build's name, bundle id or version contains a CVE id. */}
      {findingIdIn(term) !== null && <p className="text-sm text-muted-foreground">{copy.searchIdHint}</p>}

      <p role="status" className="text-xs text-muted-foreground">
        {asking && provider !== null ? tp.asking(providerLabel(provider, t.ai.providerLabels)) : null}
      </p>
      {refusal !== null && (
        <p className="text-sm">
          <span className="font-medium">{tp.unavailable}</span> {refusal}
        </p>
      )}
      {result !== null && !movedOn && (
        <div className="space-y-1 rounded-lg border bg-card p-3 text-sm">
          {banner !== null && <p className="font-medium">{banner}</p>}
          {/* The server's sentence for a failure or a refusal — never the model's words. */}
          {result.error !== null && <p className="text-muted-foreground">{result.error.message}</p>}
          {result.outcome === "proposed" && !applied && (
            <>
              <p className="font-medium">{tp.proposalLead(result.widening.length)}</p>
              <p className="text-muted-foreground">{tp.proposalNext}</p>
            </>
          )}
          {result.filters !== null && (
            <p>{(result.outcome === "proposed" && !applied ? copy.aiWouldShow : copy.aiShowing)(leverReadback(result.filters, copy))}</p>
          )}
          {result.summary !== null && (
            <p className="text-muted-foreground">{result.summary.total === 0 ? copy.aiNone : copy.aiTotal(result.summary.total)}</p>
          )}
          {/* The one model-written string in the answer, rendered as text and nothing else. */}
          {result.unsupported !== null && (
            <p className="text-muted-foreground">
              {result.outcome === "proposed" && !applied ? tp.proposalCloseAsAllowed : tp.closeAsAllowed} {result.unsupported}
            </p>
          )}
          {result.repairs.length > 0 && (
            <details>
              <summary className="cursor-pointer text-muted-foreground">{tp.repairs(result.repairs.length)}</summary>
              <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
                {result.repairs.map((repair) => (
                  <li key={repair}>{repair}</li>
                ))}
              </ul>
            </details>
          )}
          {result.outcome === "proposed" && !applied && (
            <Button type="button" size="sm" onClick={applyProposal}>
              {tp.applyProposal}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
