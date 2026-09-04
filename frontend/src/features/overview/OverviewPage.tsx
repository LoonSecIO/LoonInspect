import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { listDestinations } from "@/features/destinations/api";
import type { Destination } from "@/features/destinations/types";
import { listCollections, listConnections, listRunSummaries, listRuns, listSyncStatus } from "@/features/mdm/api";
import type { Collection, MdmConnection, MdmSyncStatus, Run, RunSummary } from "@/features/mdm/types";
import { ChangesFeed } from "@/features/overview/ChangesFeed";
import { FirstSyncHero } from "@/features/overview/FirstSyncHero";
import { SetupStepper } from "@/features/overview/SetupStepper";
import { StatusStrip } from "@/features/overview/StatusStrip";
import { buildConnectionStatuses } from "@/features/overview/connectionStatus";
import { findBaselineRun, findRunningHeroRun, formatUtc, runDuration } from "@/features/overview/heroRun";
import { useLocale } from "@/i18n/LocaleContext";

/** How often the page asks whether a full sync has started. Only while nothing is being
 *  watched live — once there is a run, its own poller is the one asking. The status
 *  strip rides this same tick rather than bringing a poller of its own: it says nothing
 *  that changes faster than a sweep does. */
const RUN_WATCH_INTERVAL_MS = 15000;

/** What `<StatusStrip>` is built from — replaced as one value so the line never renders
 *  half-joined. See the state declaration for why that matters. */
interface StripSources {
  connections: MdmConnection[];
  runSummaries: RunSummary[];
  collectionsByConnection: Map<number, Collection[]>;
}

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
          {/* Each separator travels with the segment it introduces; the alternative
              leaves a lone "·" on its own line whenever the card wraps. */}
          <span className="text-muted-foreground">
            · {t.overview.runPrefix} <code className="font-mono text-xs">{run.id}</code>
          </span>
          <span className="text-muted-foreground">
            · {t.overview.baselineCounts(run.deviceCount, run.groupCount, runDuration(run))}
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
 * The status strip (#105) is the first thing in the settled state, above the baseline
 * line — "the first pixels on every configured pod". The rest of #106–#110 land below
 * it; nothing here has to move for them to.
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
  // The destination rows themselves, not just "is there one". The stepper only ever
  // needed the boolean, but the status strip names each destination and its last
  // delivery, and `null` keeps "this session may not read them" distinct from "there
  // are none" all the way down to the segment that is or is not rendered.
  const [destinations, setDestinations] = useState<Destination[] | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  // The status strip's sources (#105), held as ONE value and replaced atomically.
  //
  // Three separate pieces of state would land in three separate renders, and the
  // connections arrive a request earlier than the summaries do — so the strip would
  // print "no full sweep yet · no scheduled sweep" for a beat on a perfectly healthy
  // pod before correcting itself. A momentarily wrong fact is worse than a late one on
  // a line whose entire job is to be trusted at a glance. `null` means "not loaded yet"
  // and renders nothing at all.
  const [stripSources, setStripSources] = useState<StripSources | null>(null);
  const [stripFailed, setStripFailed] = useState(false);
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
        const [mdmConnections, syncStatuses, recentRuns, destinationRows] = await Promise.all([
          listConnections(),
          listSyncStatus(),
          // Kept as it was: this page of runs answers #104's hero and baseline, which is
          // a different question from the stamp's. One fetch cannot serve both — the
          // baseline is the *first* full sweep and the stamp is the *last* one, and the
          // pinning query is the reason `/runs/summary` exists at all.
          listRuns(undefined, 50),
          canReadDestinations ? listDestinations() : Promise.resolve(null)
        ]);
        if (!mounted.current) return;
        setConnected(mdmConnections.length > 0);
        setStatuses(syncStatuses);
        setRuns(recentRuns);
        setDestinations(destinationRows);
        adoptRunning(recentRuns);
        setFailedToLoad(false);

        // The strip's own sources, fetched second so a pod still on the stepper issues
        // not one extra request — and inside its OWN try, so they cannot take the page
        // down with them. Before this the whole Overview shared one catch; adding two
        // endpoints to it would have meant a 500 from `/runs/summary` blanking the
        // changes feed and the baseline line as well, which is a much larger blast
        // radius than the line those endpoints draw.
        if (mdmConnections.length > 0) {
          try {
            const [summaries, collectionLists] = await Promise.all([
              listRunSummaries(),
              Promise.all(mdmConnections.map((connection) => listCollections(connection.id)))
            ]);
            if (!mounted.current) return;
            setStripSources({
              connections: mdmConnections,
              runSummaries: summaries,
              collectionsByConnection: new Map(
                mdmConnections.map((connection, index) => [connection.id, collectionLists[index]])
              )
            });
            setStripFailed(false);
          } catch {
            // Said, not swallowed. The strip's facts are stale the instant one of its
            // sources stops answering, and a line that quietly vanished would read as
            // "nothing to report" — #150's rule, applied to the one line an operator
            // looks at first.
            if (mounted.current) setStripFailed(true);
          }
        }
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

  // Built once and handed to every panel that needs it. #106's Needs Attention rows and
  // #101's alert counts read this same array rather than re-joining the sources — which
  // is what makes "the composition has exactly ONE implementation" mechanical instead of
  // aspirational: two joins would eventually disagree about which run the stamp names,
  // and the page would contradict itself a few pixels apart.
  const connectionStatuses = useMemo(
    () => (stripSources === null ? null : buildConnectionStatuses({ ...stripSources, syncStatuses: statuses })),
    [statuses, stripSources]
  );

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
    // The stepper only ever wanted the boolean; the rows are held for the strip, and
    // `null` — no permission to read them — stays `null` rather than collapsing to false.
    const destinationAdded = destinations === null ? null : destinations.length > 0;
    return <SetupStepper connected={connected} synced={synced} destinationAdded={destinationAdded} />;
  }

  return (
    <section className="space-y-6">
      <div className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">{t.overview.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.overview.title}</h1>
      </div>
      {/* The status strip (#105) — the first pixels, above the baseline line. Rendered
          only once its own sources have answered, or once they have refused: an empty
          strip on the way to a full one would flash facts that are about to change. */}
      {connectionStatuses !== null || stripFailed ? (
        <StatusStrip statuses={connectionStatuses ?? []} destinations={destinations} failed={stripFailed} />
      ) : null}
      <BaselineLine run={settledBaseline} />
      {/* The changes feed (#107) — the centerpiece. It is given the baseline so it can
          tell "nothing to compare against yet" from "measured, and quiet", which are
          different sentences and must never share an empty state. */}
      <ChangesFeed baselineAt={settledBaseline?.finishedAt ?? settledBaseline?.startedAt ?? null} />
      {/* #106 (needs attention) and #101 (alerts) compose in here, and both read the same
          `connectionStatuses` array the strip above was given — one join, one truth. */}
    </section>
  );
}
