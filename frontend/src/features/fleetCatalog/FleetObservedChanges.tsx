import type { ObservedChanges } from "@/features/fleetCatalog/migrationTypes";
import { useLocale } from "@/i18n/LocaleContext";

const note = "text-xs text-muted-foreground";

/** #900's observed upgrades, at the foot of Installed builds (#907): what the change log recorded on the selected Macs, then how
 *  long after Fleet dated a version they took it up. Null timing was not measured; 0 pairs was measured, and paired none. */
export function FleetObservedChanges({ observed }: { observed: ObservedChanges }) {
  const { t, locale } = useLocale();
  const words = t.fleetDetail, n = (value: number) => value.toLocaleString(locale);
  const { versionChanges: changes, macs, lastAt, adoptionSamples: samples, medianDaysAfterFleetPublication: median } = observed;
  return <div className="space-y-1 border-t pt-3 text-sm">
    <p>{words.observedCount(n(changes), changes === 1, n(macs), macs === 1, n(observed.windowDays))}
      {lastAt && <span className="ml-1 text-muted-foreground">{words.observedLast(new Date(lastAt).toLocaleDateString(locale))}</span>}</p>
    <p className={note}>{words.observedSource}</p>
    <h4 className="pt-2 font-medium">{words.observedTitle}</h4>
    <p>{samples === null ? words.observedNotMeasured
      : median !== null && samples > 0 ? words.observedLag(n(median), median === 1, n(samples), samples === 1) : words.observedNoLag}</p>
    <p className={note}>{words.observedNote}</p>
  </div>;
}
