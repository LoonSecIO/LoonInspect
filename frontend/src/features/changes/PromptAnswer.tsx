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
}

/**
 * What the Prompt bar says back: the handoff's banner states, the response box, and a
 * line naming who answered and how long it took.
 *
 * Every string here is a React text node, never parsed as markup (threat model S4).
 * `unsupported` is the model's own words and the server's sentences are the server's;
 * both are shown exactly as typed, never interpreted.
 */
export function PromptAnswer({ result, refusal, stale }: PromptAnswerProps) {
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

  const kind = bannerKind(result);
  const lines = kind === "readback" || kind === "unsupported" ? (result.summary ? answerLines(result.summary, tc) : []) : [];

  return (
    <div className="space-y-2">
      {kind === "error" && (
        <div role="status" className={mutedClasses}>
          <p className="font-medium text-foreground">{tp.unavailable}</p>
          {result.error && <p>{result.error.message}</p>}
        </div>
      )}
      {kind === "unparseable" && (
        <div role="status" className={mutedClasses}>
          <p className="font-medium text-foreground">{tp.unparseable}</p>
          {result.error && <p>{result.error.message}</p>}
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
      {result.repairs.length > 0 && (
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
