import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { listJamfPatchTitles } from "@/features/jamfPatch/api";
import { AppPicker } from "@/features/patchPolicy/AppPicker";
import { pickerApps, type CatalogTitle } from "@/features/patchPolicy/apps";
import { SLIDER_STOPS, isSliderStop, type ReadResult, type SliderStop } from "@/features/patchPolicy/replay";
import { REPLAY_INDEX, loadReplay } from "@/features/patchPolicy/replayIndex";
import { ReplayView } from "@/features/patchPolicy/ReplayView";
import { useLocale } from "@/i18n/LocaleContext";

/**
 * Posture › Patch policy (#614, first slice): pick an app, move the policy slider, read how many of the
 * app's CVEs a Mac on that policy never saw. This component is the page's data half and nothing else:
 * it reads Jamf's patch catalog for the picker, loads the picked app's replay file, and keeps the app
 * and the stop in the address so a link opens the same view. `AppPicker` and `ReplayView` draw.
 *
 * It is a reference analysis of a hypothetical Mac. Nothing here reads this organization's inventory:
 * the catalog read takes title names and bundle IDs and ignores the device counts that ride with them.
 */
export function PatchPolicyPage() {
  const { t } = useLocale();
  const copy = t.patchPolicy;
  const [params, setParams] = useSearchParams();
  const appId = params.get("app") ?? REPLAY_INDEX[0].id;
  const entry = REPLAY_INDEX.find((each) => each.id === appId) ?? null;
  const asked = params.get("policy");
  const stop: SliderStop = isSliderStop(asked) ? asked : SLIDER_STOPS[0];

  // `null` until the catalog read lands. A read that FAILED is not an empty catalog (#150), so each has its sentence.
  const [titles, setTitles] = useState<CatalogTitle[] | null>(null);
  const [catalogFailed, setCatalogFailed] = useState(false);
  // Keyed by the app it answers for, so a replay is never drawn under another app's name while the
  // next one loads, and the effect has nothing to reset (#15).
  const [read, setRead] = useState<{ id: string; result: ReadResult } | null>(null);
  const result = entry && read?.id === entry.id ? read.result : null;

  useEffect(() => {
    let cancelled = false;
    listJamfPatchTitles()
      .then((response) => void (cancelled || setTitles(response.items)))
      .catch(() => void (cancelled || (setTitles([]), setCatalogFailed(true))));
    return () => void (cancelled = true);
  }, []);

  useEffect(() => {
    if (!entry) return;
    let cancelled = false;
    void loadReplay(entry).then((answer) => void (cancelled || setRead({ id: entry.id, result: answer })));
    return () => void (cancelled = true);
  }, [entry]);

  const apps = useMemo(() => pickerApps(titles ?? [], REPLAY_INDEX), [titles]);
  // Replaced, not pushed: a drag across the slider is one visit, not six.
  const set = (key: string, value: string) =>
    setParams((current) => { const next = new URLSearchParams(current); next.set(key, value); return next; }, { replace: true });

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{copy.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{copy.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{copy.description}</p>
      </div>
      <div className="grid gap-6 lg:grid-cols-[18rem_minmax(0,1fr)]">
        {/* Stays beside the replay on a wide screen, under the navbar, while the tables scroll. */}
        <div className="space-y-2 lg:sticky lg:top-24 lg:self-start">
          <AppPicker apps={apps} selected={entry?.id ?? null} onSelect={(id) => set("app", id)} copy={copy} />
          {titles === null && <p className="text-xs text-muted-foreground">{copy.catalogLoading}</p>}
          {catalogFailed && <p className="text-xs text-destructive">{copy.catalogFailed}</p>}
          {titles?.length === 0 && !catalogFailed && <p className="text-xs text-muted-foreground">{copy.catalogEmpty}</p>}
        </div>
        {!entry && <p className="text-sm">{copy.unknownApp(appId)}</p>}
        {entry && !result && <p className="text-sm text-muted-foreground">{copy.replayLoading}</p>}
        {entry && result?.refusal && (
          <div className="space-y-1 text-sm">
            <p className="text-destructive">{copy.refusedLead(entry.name)} {copy.refused(result.refusal)}</p>
            <p>{copy.refusedCheck}</p>
          </div>
        )}
        {entry && result?.replay && (
          <ReplayView replay={result.replay} appName={entry.name} stop={stop} onStop={(next) => set("policy", next)} copy={copy} />
        )}
      </div>
    </section>
  );
}
