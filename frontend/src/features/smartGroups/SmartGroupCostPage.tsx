import { Fragment, useEffect, useMemo, useState } from "react";
import { listSmartGroupCost } from "@/features/smartGroups/api";
import type { OperatorClass, SmartGroupCost } from "@/features/smartGroups/types";
import { useLocale } from "@/i18n/LocaleContext";

// Order matters: it is the server's ranking, restated so the legend and the band tiles
// read heaviest-first like the table does. The page never re-ranks — the server owns
// the order, and a second ordering here would be a second heuristic to keep honest.
const BANDS: OperatorClass[] = ["regex", "substring", "unknown", "dependent", "exact", "none"];

// Deliberately not the red/amber/green of the patch pages. Nothing here is a finding:
// an expensive smart group is not a vulnerability, and colouring it like one would make
// a heuristic look like a verdict.
const BAND_TONE: Record<OperatorClass, string> = {
  regex: "bg-foreground/15 text-foreground",
  substring: "bg-foreground/10 text-foreground",
  unknown: "bg-foreground/10 text-foreground",
  dependent: "bg-muted text-muted-foreground",
  exact: "bg-muted text-muted-foreground",
  none: "bg-muted text-muted-foreground"
};

function formatDate(value: string): string {
  return new Date(value).toLocaleDateString();
}

export function SmartGroupCostPage() {
  const { t } = useLocale();
  const [groups, setGroups] = useState<SmartGroupCost[]>([]);
  const [advisory, setAdvisory] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    listSmartGroupCost()
      .then((response) => {
        if (cancelled) return;
        setGroups(response.items);
        setAdvisory(response.advisory);
      })
      .catch(() => {
        if (!cancelled) setError(t.smartGroupCost.errorLoading);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [t]);

  const bandCounts = useMemo(() => {
    const counts = new Map<OperatorClass, number>();
    for (const group of groups) counts.set(group.band, (counts.get(group.band) ?? 0) + 1);
    return counts;
  }, [groups]);

  const bandLabels: Record<OperatorClass, string> = {
    regex: t.smartGroupCost.bandRegex,
    substring: t.smartGroupCost.bandSubstring,
    unknown: t.smartGroupCost.bandUnknown,
    dependent: t.smartGroupCost.bandDependent,
    exact: t.smartGroupCost.bandExact,
    none: t.smartGroupCost.bandNone
  };

  const bandHelp: Record<OperatorClass, string> = {
    regex: t.smartGroupCost.bandRegexHelp,
    substring: t.smartGroupCost.bandSubstringHelp,
    unknown: t.smartGroupCost.bandUnknownHelp,
    dependent: t.smartGroupCost.bandDependentHelp,
    exact: t.smartGroupCost.bandExactHelp,
    none: t.smartGroupCost.bandNoneHelp
  };

  function toggle(id: string) {
    setExpanded((open) => (open.includes(id) ? open.filter((each) => each !== id) : [...open, id]));
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.smartGroupCost.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.smartGroupCost.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.smartGroupCost.description}</p>
      </div>

      {/* Not a dismissible banner and not a tooltip. The ranking is a claim about
          somebody else's server, so the caveat sits above the table it qualifies and
          stays there. The server sends its own wording too; both are shown, because
          the page's copy is translated and the API's is what a script would quote. */}
      <div className="rounded-lg border bg-muted/30 p-4 text-sm">
        <p className="font-medium">{t.smartGroupCost.advisoryTitle}</p>
        <p className="mt-1 text-muted-foreground">{t.smartGroupCost.advisoryBody}</p>
        {advisory && <p className="mt-2 text-xs text-muted-foreground">{advisory}</p>}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {BANDS.map((band) => (
          <div key={band} className="rounded-lg border bg-card p-3">
            <p className="text-xs text-muted-foreground">{bandLabels[band]}</p>
            <p className="text-2xl font-semibold tabular-nums">{bandCounts.get(band) ?? 0}</p>
            <p className="mt-1 text-xs text-muted-foreground">{bandHelp[band]}</p>
          </div>
        ))}
      </div>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.smartGroupCost.tableRank}</th>
              <th className="px-4 py-2 font-medium">{t.smartGroupCost.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.smartGroupCost.tableBand}</th>
              <th className="px-4 py-2 font-medium">{t.smartGroupCost.tableCriteria}</th>
              <th className="px-4 py-2 font-medium">{t.smartGroupCost.tableDepth}</th>
              <th className="px-4 py-2 font-medium">{t.smartGroupCost.tableObserved}</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.smartGroupCost.loading}
                </td>
              </tr>
            )}
            {!loading && error && (
              <tr>
                <td className="px-4 py-4 text-destructive" colSpan={6}>
                  {error}
                </td>
              </tr>
            )}
            {!loading && !error && groups.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.smartGroupCost.empty}
                </td>
              </tr>
            )}
            {!loading &&
              !error &&
              groups.map((group, index) => (
                <Fragment key={group.id}>
                  <tr className="border-b last:border-0">
                    <td className="px-4 py-2 tabular-nums text-muted-foreground">{index + 1}</td>
                    <td className="px-4 py-2 font-medium">
                      <button
                        type="button"
                        className="text-left hover:underline"
                        onClick={() => toggle(group.id)}
                        aria-expanded={expanded.includes(group.id)}
                      >
                        {group.name ?? t.smartGroupCost.unnamed}
                      </button>
                      {group.criteria.some((criterion) => criterion.operatorClass === "unknown") && (
                        <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                          {t.smartGroupCost.unknownOperatorBadge}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`rounded px-2 py-0.5 text-xs ${BAND_TONE[group.band]}`}>{bandLabels[group.band]}</span>
                    </td>
                    <td className="px-4 py-2 tabular-nums">{group.criteriaCount}</td>
                    <td className="px-4 py-2 tabular-nums">{group.maxDepth}</td>
                    <td className="px-4 py-2 text-muted-foreground">{formatDate(group.lastObservedAt)}</td>
                  </tr>
                  {expanded.includes(group.id) && (
                    <tr className="border-b bg-muted/20 last:border-0">
                      <td className="px-4 py-3" colSpan={6}>
                        {group.criteria.length === 0 ? (
                          <p className="text-sm text-muted-foreground">{t.smartGroupCost.noCriteria}</p>
                        ) : (
                          <table className="w-full text-xs">
                            <thead className="text-left text-muted-foreground">
                              <tr>
                                <th className="py-1 pr-4 font-medium">{t.smartGroupCost.criterionOrder}</th>
                                <th className="py-1 pr-4 font-medium">{t.smartGroupCost.criterionField}</th>
                                <th className="py-1 pr-4 font-medium">{t.smartGroupCost.criterionOperator}</th>
                                <th className="py-1 pr-4 font-medium">{t.smartGroupCost.criterionClass}</th>
                                <th className="py-1 pr-4 font-medium">{t.smartGroupCost.criterionValue}</th>
                              </tr>
                            </thead>
                            <tbody>
                              {group.criteria.map((criterion) => (
                                <tr key={`${group.id}-${criterion.priority}-${criterion.name}`}>
                                  <td className="py-1 pr-4 tabular-nums text-muted-foreground">
                                    {criterion.priority + 1}
                                    {criterion.conjunction ? ` · ${criterion.conjunction}` : ""}
                                    {criterion.depth > 0 ? ` · ${t.smartGroupCost.criterionDepth(criterion.depth)}` : ""}
                                  </td>
                                  <td className="py-1 pr-4">
                                    {criterion.name}
                                    {criterion.extensionAttribute && (
                                      <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                                        {t.smartGroupCost.extensionAttributeBadge}
                                      </span>
                                    )}
                                  </td>
                                  {/* Jamf's own word for the operator, unedited: the
                                      classification beside it is ours, and a reader has
                                      to be able to disagree with it. */}
                                  <td className="py-1 pr-4 font-mono">{criterion.operator}</td>
                                  <td className="py-1 pr-4">{bandLabels[criterion.operatorClass]}</td>
                                  <td className="py-1 pr-4 font-mono break-all">{criterion.value}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
          </tbody>
        </table>
      </div>

      <p className="text-sm text-muted-foreground">{t.smartGroupCost.total(groups.length)}</p>
    </section>
  );
}
