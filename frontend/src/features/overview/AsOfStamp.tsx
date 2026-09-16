import { useEffect, useState } from "react";
import { coarseAge } from "@/features/overview/connectionStatus";
import { formatUtc } from "@/features/overview/heroRun";
import { useLocale } from "@/i18n/LocaleContext";

/** A minute is the finest grain `coarseAge` reports; anything faster re-renders for nothing. */
const TICK_MS = 60_000;

/**
 * `as of 2026-09-16 14:32 UTC (2h ago)` — the stamp under a tile, and #117's hard line:
 * every tile ages visibly so a dead refresh can never read as calm. **It carries its own
 * clock, and that is the point**: a page left open on a wall re-renders nothing, so
 * without the interval the age would freeze at the last render and a board whose data
 * stopped arriving hours ago would go on reading as current. It dates the *read*, which
 * is the browser's clock, not the inventory's — a viewer-readable inventory freshness
 * fact is the open ruling on #115.
 *
 * `null` renders nothing — a stamp over no answer dates a number that is not there.
 */
export function AsOfStamp({ asOf }: { asOf: string | null }) {
  const { t } = useLocale();
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const handle = window.setInterval(() => setNow(new Date()), TICK_MS);
    return () => window.clearInterval(handle);
  }, []);

  if (asOf === null) return null;
  const age = coarseAge(asOf, now);
  if (age === null) return null;
  const ts = t.overview.strip;
  const word =
    age.unit === "now" ? ts.agoNow
    : age.unit === "minutes" ? ts.agoMinutes(age.value)
    : age.unit === "hours" ? ts.agoHours(age.value)
    : ts.agoDays(age.value);

  return <p className="mt-2 text-xs text-muted-foreground">{t.overview.asOfStamp(formatUtc(asOf), word)}</p>;
}
