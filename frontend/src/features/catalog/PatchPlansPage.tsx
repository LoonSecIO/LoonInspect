import { useMemo } from "react";
import { Link, useSearchParams } from "react-router";
import { PatchPlanWorkspace } from "./PatchPlanWorkspace";
import { defaultScope } from "./patchPlanTypes";
import { applicationFilters, applicationScopeFromParams, installedAppsPath } from "./patchPlanNavigation";

export function PatchPlansPage() {
  const [params, setParams] = useSearchParams();
  const scope = params.get("deviceScope") ?? JSON.stringify(defaultScope);
  const applicationScope = useMemo(() => applicationScopeFromParams(params), [params]);
  const selected = [...new Set(params.getAll("appHash"))];
  return <section className="space-y-4">
    <header><h1 className="text-2xl font-semibold">Patch Plans</h1>
      <p className="mt-1 text-sm text-muted-foreground">Plan, investigate and review application updates for a saved inventory scope.</p></header>
    <p className="text-sm text-muted-foreground">Open a saved plan or select applications from your scoped inventory.
      {" "}<Link className="underline" to={`${installedAppsPath}?${applicationFilters(params)}`}>Choose installed apps</Link>
    </p>
    <PatchPlanWorkspace scope={scope} applicationScope={applicationScope} selected={selected} planId={params.get("plan")}
      onClear={() => setParams(previous => { const next = new URLSearchParams(previous); next.delete("appHash"); return next; }, { replace: true })}
      onOpen={id => setParams(previous => { const next = new URLSearchParams(previous); next.delete("appHash");
        if (id) next.set("plan", id); else next.delete("plan"); return next; })} />
  </section>;
}
