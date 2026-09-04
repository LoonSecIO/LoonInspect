import { useCallback, useEffect, useState } from "react";
import type { Destination } from "@/features/destinations/types";
import type { ConnectionStatus } from "@/features/overview/connectionStatus";
import { coarseAge, formatDue, shortRunId } from "@/features/overview/connectionStatus";
import { formatUtc } from "@/features/overview/heroRun";
import { useLocale } from "@/i18n/LocaleContext";

/** How long the copy confirmation stands in for the "full sweep" segment. */
const COPIED_VISIBLE_MS = 2000;

/**
 * The status strip (#105) — one thin line per connection, the first pixels on every
 * configured pod:
 *
 * ```
 * Jamf Pro (acme.jamfcloud.com) · 412 devices · inventory as of 2026-08-29 14:32 UTC
 * (2h ago) · run 8f3a…c1 full sweep, +3 webhook sweeps since · next sweep 02:00 UTC
 * · Splunk OK 14:35 UTC
 * ```
 *
 * **It states facts and never turns red.** No colour, no icons, no badges — a breach of
 * any threshold is a Needs Attention row (#106), and a strip that could go red would
 * make that panel the second place to look instead of the only one. The per-connection
 * device count lives here and nowhere else: it is a completeness check ("is the whole
 * fleet in?"), not a hero number, and this product has no fleet-size tile.
 *
 * All the deciding happens in `connectionStatus.ts`; this file only chooses words. That
 * split is the point — #285 has something to test, and this component has nothing that
 * can be silently wrong.
 */
export function StatusStrip({
  statuses,
  destinations,
  failed
}: {
  statuses: ConnectionStatus[];
  /** `null` means the session cannot read destinations. The destination segment is then
   *  omitted rather than rendered empty — "no destinations" and "you may not see them"
   *  are different sentences and the second one is not the strip's to say. */
  destinations: Destination[] | null;
  /** One of the strip's own sources refused. Every fact on this line would be stale, so
   *  the line says so instead of printing them. */
  failed: boolean;
}) {
  const { t } = useLocale();
  const ts = t.overview.strip;
  const now = new Date();

  // Which jobID was last copied, so the confirmation is per-line rather than global on a
  // pod with two connections. It replaces "full sweep" for a moment and then gives the
  // word back — a permanent "job ID copied" would cost the line the one segment that
  // says what kind of run the stamp names.
  const [copied, setCopied] = useState<string | null>(null);
  const copy = useCallback((jobId: string) => {
    // Best-effort: an insecure origin or a browser that refuses clipboard access leaves
    // the `title` as the way to read the full id, which is why it is there as well.
    void navigator.clipboard?.writeText(jobId).then(
      () => setCopied(jobId),
      () => undefined
    );
  }, []);
  useEffect(() => {
    if (copied === null) return;
    const handle = window.setTimeout(() => setCopied(null), COPIED_VISIBLE_MS);
    return () => window.clearTimeout(handle);
  }, [copied]);

  const ago = (iso: string): string | null => {
    const age = coarseAge(iso, now);
    if (age === null) return null;
    if (age.unit === "now") return ts.agoNow;
    if (age.unit === "minutes") return ts.agoMinutes(age.value);
    if (age.unit === "hours") return ts.agoHours(age.value);
    return ts.agoDays(age.value);
  };

  const deliveryOf = (destination: Destination): string => {
    const success = destination.lastSuccessAt;
    const failure = destination.lastFailureAt;
    if (success === null) return ts.destinationNothingYet(destination.name);
    // A newer failure than the last success is still stated as a fact — when the last
    // event actually landed — and never as an alarm. #106 raises the row.
    if (failure !== null && Date.parse(failure) > Date.parse(success)) {
      return ts.destinationLastDelivered(destination.name, formatDue(success, now));
    }
    return ts.destinationOk(destination.name, formatDue(success, now));
  };

  // Destinations are pod-wide, so on a two-connection pod these segments repeat on both
  // lines. Accepted deliberately: the ruled template puts delivery inside the connection
  // sentence, and a second line shape to say it once would cost more than the repetition.
  const enabledDestinations = (destinations ?? []).filter((destination) => destination.enabled);

  if (failed) {
    // Not `text-destructive`: the strip never turns red, and a source that stopped
    // answering is not a finding about the fleet. It is muted, and it is *said* —
    // vanishing would read as "nothing to report", which is the one thing it does not
    // mean.
    return (
      <section className="rounded-lg border bg-card px-5 py-4 text-sm text-muted-foreground shadow-sm">
        {ts.loadError}
      </section>
    );
  }

  return (
    <section className="space-y-1 rounded-lg border bg-card px-5 py-4 text-sm text-card-foreground shadow-sm">
      {statuses.map((status) => {
        // Bound before the JSX so the null check narrows inside the click handler too —
        // a closure would otherwise force a non-null assertion on the one field whose
        // absence this component has a whole sentence for.
        const sweep = status.fullSweep;
        const asOf = status.inventoryAsOf;

        return (
          // Each separator travels with the segment it introduces, the rule `BaselineLine`
          // set: the alternative leaves a lone "·" on its own line whenever the line wraps.
          <div key={status.connectionId} className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="font-medium">{ts.identity(status.name, status.host)}</span>

            <span className="text-muted-foreground">
              · {status.deviceCount === null ? ts.noInventoryYet : ts.devices(status.deviceCount)}
            </span>

            {/* Only beside a count. "Inventory as of" is what makes the count a
                measurement rather than a number, and one without the other is the half
                that misleads — the strip's count is the projection written at the end of
                the run named below it, and this segment is the sentence that says so. */}
            {asOf !== null && status.deviceCount !== null ? (
              <span className="text-muted-foreground">· {ts.inventoryAsOf(formatUtc(asOf), ago(asOf) ?? "")}</span>
            ) : null}

            <span className="text-muted-foreground">
              ·{" "}
              {sweep === null ? (
                // Said rather than omitted. A missing segment is invisible, and "no full
                // sweep has ever completed" is precisely the state this endpoint exists
                // to stop the page from hiding behind a webhook run.
                ts.noFullSweepYet
              ) : (
                <>
                  {t.overview.runPrefix}{" "}
                  <button
                    type="button"
                    onClick={() => copy(sweep.id)}
                    title={sweep.id}
                    className="cursor-pointer font-mono text-xs underline decoration-dotted underline-offset-4"
                  >
                    {shortRunId(sweep.id)}
                  </button>{" "}
                  {copied === sweep.id ? ts.copied : ts.fullSweep}
                  {/* Rendered only above zero: this clause is a correction to the stamp,
                      and a correction of nothing is not a fact worth printing. */}
                  {status.webhookSweepsSince > 0 ? `, ${ts.webhookSweepsSince(status.webhookSweepsSince)}` : null}
                </>
              )}
            </span>

            <span className="text-muted-foreground">
              ·{" "}
              {!status.isActive
                ? ts.sweepsPaused
                : status.nextDueAt === null
                  ? ts.noScheduledSweep
                  : ts.nextSweep(formatDue(status.nextDueAt, now))}
            </span>

            {enabledDestinations.map((destination) => (
              <span key={destination.id} className="text-muted-foreground">
                · {deliveryOf(destination)}
              </span>
            ))}
          </div>
        );
      })}
    </section>
  );
}
