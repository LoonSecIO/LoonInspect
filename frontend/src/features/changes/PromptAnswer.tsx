import { Button } from "@/components/ui/button";
import { answerLines, bannerKind, providerLabel, readback } from "@/features/changes/prompt";
import type { PromptResult } from "@/features/changes/types";
import { useLocale } from "@/i18n/LocaleContext";

const mutedClasses = "rounded-md border bg-muted/40 px-4 py-3 text-sm text-muted-foreground";

interface PromptAnswerProps {
  result: PromptResult | null;
  /** Why the question got no answer: a refusal the server sent as an HTTP error (409,
   *  422) in its own sentence, as written, or the bar's sentence for a request that
   *  failed on the way (`askFailureText`). */
  refusal: string | null;
  /** The answer came back after the operator moved the filters by hand, so it was not
   *  applied (`replyDisposition`). One line in its place, never the answer itself. */
  stale: boolean;
  /** Whether the bar has moved the page to this answer's filters: on arrival for an
   *  applied answer, on the Apply button for a proposal. */
  applied: boolean;
  /** A proposal's Apply button: moves the page to its filters (`proposedFilters`). */
  onApplyProposal: () => void;
}

/**
 * What the Prompt bar says back: the handoff's banner states, the response box, and a
 * line naming who answered and how long it took. A proposal — an answer a correction
 * widened, so it was not run (ruled 1C, #436) — shows the corrections that widened it,
 * what its filters would show, and the button that applies them; applied, it reads as any
 * answer does.
 *
 * Every string here is a React text node, never parsed as markup (threat model S4).
 * `unsupported` is the model's own words and the server's sentences are the server's;
 * both are shown exactly as typed, never interpreted.
 */
export function PromptAnswer({ result, refusal, stale, applied, onApplyProposal }: PromptAnswerProps) {
  const { t } = useLocale();
  const tc = t.changes;
  const tp = tc.prompt;

  if (refusal !== null) {
    return (
      <div role="status" className={mutedClasses}>
        <p className="font-medium text-foreground">{tp.unavailable}</p>
        <p>{refusal}</p>
      </div>
    );
  }
  // The readback and the counts would describe filters the page is not showing, and
  // applying them would undo what the operator just set; so neither, only why.
  if (stale) {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        {tp.staleReply}
      </p>
    );
  }
  if (!result) return null;

  const kind = bannerKind(result, applied);
  const lines = kind === "readback" || kind === "unsupported" ? (result.summary ? answerLines(result.summary, tc) : []) : [];

  return (
    <div className="space-y-2">
      {kind === "error" && (
        <div role="status" className={mutedClasses}>
          <p className="font-medium text-foreground">{tp.unavailable}</p>
          {result.error && <p>{result.error.message}</p>}
        </div>
      )}
      {/* A question the filters cannot answer: nothing ran and the filters are as they
          were. The lead says so; the server's sentence says why and what to ask. */}
      {kind === "invalid" && (
        <div role="status" className={mutedClasses}>
          <p className="font-medium text-foreground">{tp.invalid(tp.barName)}</p>
          {result.error && <p>{result.error.message}</p>}
        </div>
      )}
      {kind === "unparseable" && (
        <div role="status" className={mutedClasses}>
          <p className="font-medium text-foreground">{tp.unparseable}</p>
          {result.error && <p>{result.error.message}</p>}
        </div>
      )}
      {/* Nothing has run: the lead says why and what to do, the corrections that widened
          the answer follow in the server's words, then the model's caveat if it gave one,
          then what the filters would show. The caveat is part of what to check before
          applying, so it does not wait for the button. The counts do, and the answer box
          follows it. */}
      {kind === "proposal" && result.filters && (
        <div role="status" className="space-y-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm">
          <p>
            <strong>{tp.proposalLead(result.widening.length)}</strong> {tp.proposalNext}
          </p>
          {result.widening.length > 0 && (
            <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
              {result.widening.map((repair, index) => (
                <li key={index}>{repair}</li>
              ))}
            </ul>
          )}
          {result.unsupported && (
            <p>
              <strong>{tp.proposalCloseAsAllowed}</strong> {result.unsupported}
            </p>
          )}
          <p className="text-muted-foreground">{readback(result.filters, tc, "proposed")}</p>
          <Button type="button" size="sm" onClick={onApplyProposal}>
            {tp.applyProposal}
          </Button>
        </div>
      )}
      {/* The important case: the controls answered a narrower question than the one
          asked, so the banner says so before the readback says what was shown. */}
      {kind === "unsupported" && result.filters && (
        <div role="status" className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm">
          <p>
            <strong>{tp.closeAsAllowed}</strong> {result.unsupported}
          </p>
          <p className="mt-1 text-muted-foreground">{readback(result.filters, tc)}</p>
        </div>
      )}
      {kind === "readback" && result.filters && (
        <div role="status" className="rounded-md border border-primary/20 bg-primary/5 px-4 py-3 text-sm">
          {readback(result.filters, tc)}
        </div>
      )}

      {lines.length > 0 && (
        <div className="rounded-lg border bg-card px-4 py-3 text-sm">
          <p className="font-medium">{lines[0]}</p>
          {lines.length > 1 && (
            <ul className="mt-1 space-y-0.5">
              {lines.slice(1).map((line, index) => (
                <li key={index}>{line}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        {providerLabel(result.provider, t.ai.providerLabels)} · {result.model} · {result.latencyMs} ms
      </p>
      {/* Every correction, once there is an answer on the page; a proposal lists the ones
          that widened it above, and the rest follow when it is applied. */}
      {kind !== "proposal" && result.repairs.length > 0 && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">{tp.repairs(result.repairs.length)}</summary>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            {result.repairs.map((repair, index) => (
              <li key={index}>{repair}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
