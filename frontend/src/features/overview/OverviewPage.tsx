import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { listDestinations } from "@/features/destinations/api";
import { listConnections, listRuns, listSyncStatus } from "@/features/mdm/api";
import type { MdmSyncStatus, Run } from "@/features/mdm/types";
import { FirstSyncHero } from "@/features/overview/FirstSyncHero";
import { SetupStepper } from "@/features/overview/SetupStepper";
import { findBaselineRun, findRunningHeroRun, formatUtc, runDuration } from "@/features/overview/heroRun";
import { useLocale } from "@/i18n/LocaleContext";

/** How often the page asks whether a full sync has started. Only while nothing is being
 *  watched live — once there is a run, its own poller is the one asking. */
const RUN_WATCH_INTERVAL_MS = 15000;

/** The line the hero leaves behind, and the last thing this page says about setup. The
 *  jobID is spelled out rather than shortened: it is the value an operator pastes into
 *  Splunk to find every event this baseline produced. */
function BaselineLine({ run }: { run: Run | null }) {
  const { t } = useLocale();

  return (
    <section className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border bg-card px-5 py-4 text-sm text-card-foreground shadow-sm">
      {run ? (
        <>
          <span>{t.overview.baselineEstablished(formatUtc(run.finishedAt ?? run.startedAt))}</span>
          <span className="text-muted-foreground">·</span>
          <span className="text-muted-foreground">
            {t.overview.runPrefix} <code className="font-mono text-xs">{run.id}</code>
          </span>
          <span className="text-muted-foreground">·</span>
          <span className="text-muted-foreground">
            {t.overview.baselineCounts(run.deviceCount, run.groupCount, runDuration(run))}
          </span>
        </>
      ) : null}
      <Link to="/devices" className="font-medium underline underline-offset-4">
        {t.overview.seeYourFleet}
      </Link>
    </section>
  );
}

/**
 * The front door (#104). Three states, each decided by what the endpoints say:
 *
 * - **Nothing connected yet.** The stepper *is* the page. No dashboard skeletons, no
 *   greyed tiles, no "0 devices" — an empty pod has not measured zero devices, it has
 *   not measured anything, and a dashboard shape full of zeroes says the opposite.
 * - **A full sync in flight.** The hero becomes the run: elapsed, counters, engine log.
 * - **Settled.** One line naming the baseline, and the way into the fleet. The stepper
 *   does not come back — the state that produced it is gone for good.
 *
 * The panels of #105–#110 land beside `<BaselineLine>` in the settled state; nothing
 * here has to move for them to.
 */
export function OverviewPage() {
  const { t } = useLocale();
  // Everything the stepper checks is CONNECTION_READ-gated server-side, and the optional
  // step needs DESTINATION_READ on top. Asking anyway would spend three 403s to learn
  // what the session already knows.
  const canReadConnections = useHasPermission(PERMISSIONS.CONNECTION_READ);
  const canReadDestinations = useHasPermission(PERMISSIONS.DESTINATION_READ);

  const [loading, setLoading] = useState(true);
  const [failedToLoad, setFailedToLoad] = useState(false);
  const [connected, setConnected] = useState(false);
  const [statuses, setStatuses] = useState<MdmSyncStatus[]>([]);
  const [destinationAdded, setDestinationAdded] = useState<boolean | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  // The run the hero is pointed at, and how it ended if it has. `watching` is never
  // cleared by a refresh: a failed sync must stay on screen until something replaces it,
  // not disappear on the next tick because it is no longer running.
  const [watching, setWatching] = useState<Run | null>(null);
  const [outcome, setOutcome] = useState<Run | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const adoptRunning = useCallback((rows: Run[]) => {
    const running = findRunningHeroRun(rows);
    if (!running) return;
    setWatching((held) => (held?.id === running.id ? held : running));
    setOutcome((held) => (held?.id === running.id ? held : null));
  }, []);

  const refresh = useCallback(
    async (quiet = false) => {
      if (!canReadConnections) {
        setLoading(false);
        return;
      }
      if (!quiet) setLoading(true);
      try {
        const [connections, syncStatuses, recentRuns, destinations] = await Promise.all([
          listConnections(),
          listSyncStatus(),
          listRuns(undefined, 50),
          canReadDestinations ? listDestinations() : Promise.resolve(null)
        ]);
        if (!mounted.current) return;
        setConnected(connections.length > 0);
        setStatuses(syncStatuses);
        setRuns(recentRuns);
        setDestinationAdded(destinations === null ? null : destinations.length > 0);
        adoptRunning(recentRuns);
        setFailedToLoad(false);
      } catch {
        // A pod whose endpoints are down has not finished setup either — but it has not
        // "not started" it. Saying so beats showing step one unchecked (#150's rule:
        // failure must never read as emptiness).
        if (mounted.current && !quiet) setFailedToLoad(true);
      } finally {
        if (mounted.current) setLoading(false);
      }
    },
    [adoptRunning, canReadConnections, canReadDestinations]
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onHeroFinished = useCallback(
    (run: Run) => {
      setOutcome(run);
      // The run row now carries the final counts and the baseline may have just come
      // into existence; re-read rather than infer.
      void refresh(true);
    },
    [refresh]
  );

  // Whether the hero currently owns the page. A succeeded run hands the page to the
  // settled line; a failed one keeps it, so the failure is not silently swallowed.
  const heroRun = watching && outcome?.status !== "succeeded" ? watching : null;

  // While no run is being watched, this page is the only thing that would notice a
  // scheduled sweep starting. One small request every fifteen seconds, and none at all
  // while the tab is in the background.
  useEffect(() => {
    if (!canReadConnections || heroRun !== null) return;
    const tick = () => {
      if (document.hidden) return;
      void refresh(true);
    };
    const handle = window.setInterval(tick, RUN_WATCH_INTERVAL_MS);
    return () => window.clearInterval(handle);
  }, [canReadConnections, heroRun, refresh]);

  if (!canReadConnections) {
    return (
      <section className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">{t.overview.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.overview.title}</h1>
        <p className="max-w-2xl text-muted-foreground">{t.overview.setupHiddenForRole}</p>
        <Link to="/devices" className="inline-block font-medium underline underline-offset-4">
          {t.overview.seeYourFleet}
        </Link>
      </section>
    );
  }

  if (loading) {
    // Deliberately not a dashboard skeleton: a shape that resolves into "you have
    // nothing" is a worse first impression than one line that resolves into a stepper.
    return <p className="text-sm text-muted-foreground">{t.overview.loading}</p>;
  }

  if (failedToLoad) {
    return (
      <section className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">{t.overview.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.overview.title}</h1>
        <p className="text-sm text-destructive">{t.overview.loadError}</p>
      </section>
    );
  }

  if (heroRun) return <FirstSyncHero run={heroRun} onFinished={onHeroFinished} />;

  const settledBaseline =
    findBaselineRun(runs) ??
    (outcome?.status === "succeeded" && outcome.comparison === "baseline" ? outcome : null);
  // A sync has landed if the connection says so, or if a full sweep of ours succeeded.
  // Either is evidence; neither is a browser remembering that someone clicked.
  const synced =
    statuses.some((status) => status.lastSyncAt !== null) ||
    settledBaseline !== null ||
    outcome?.status === "succeeded";

  if (!connected || !synced) {
    return <SetupStepper connected={connected} synced={synced} destinationAdded={destinationAdded} />;
  }

  return (
    <section className="space-y-6">
      <div className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">{t.overview.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.overview.title}</h1>
      </div>
      <BaselineLine run={settledBaseline} />
      {/* #105–#110 (status strip, needs attention, changes, new in fleet, hygiene,
          patch laggards) compose in here. */}
    </section>
  );
}
