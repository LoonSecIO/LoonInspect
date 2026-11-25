import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { ApiError } from "@/config/api";
import { listJamfPatchTitles } from "@/features/jamfPatch/api";
import { AppPicker } from "@/features/patchPolicy/AppPicker";
import { pickerApps, type CatalogTitle } from "@/features/patchPolicy/apps";
import { SLIDER_STOPS, isSliderStop, type ReadResult, type SliderStop } from "@/features/patchPolicy/replay";
import { REPLAY_INDEX, loadReplay } from "@/features/patchPolicy/replayIndex";
import { ReplayView } from "@/features/patchPolicy/ReplayView";
import {
  channelsSetAside,
  defaultTrack,
  esrFoldedIn,
  getPatchPolicyWalk,
  isWalkSource,
  isWalkYears,
  sourceTrack,
  walkQuery,
  type WalkAnswer,
  type WalkRefusal,
  type WalkSource,
  type WalkYears
} from "@/features/patchPolicy/walk";
import { reasonWords, type WalkCopy } from "@/features/patchPolicy/walkCopy";
import { WalkControls } from "@/features/patchPolicy/WalkControls";
import { WalkView } from "@/features/patchPolicy/WalkView";
import { describeFeed, getPatchPolicyApps, type PatchPolicyAppsResponse } from "@/features/support/patchPolicyFeed";
import { useLocale } from "@/i18n/LocaleContext";

/** `/apps`'s answer: the response, or the status of a read that failed (null for no answer). */
type AppsRead = { ok: PatchPolicyAppsResponse; failed?: undefined } | { failed: { status: number | null }; ok?: undefined };

/** The feed states that are a failed attempt rather than an answer: their sentence is drawn in the warning colour. */
const FEED_FAILED = new Set(["not_published", "algorithm_unknown", "download_failed", "invalid"]);

/** The facts beside a refusal a reader can act on: the versions that matched nothing. */
function unmatchedOf(facts: Record<string, unknown>): string[] {
  const reach = facts.in_reach;
  const listed = typeof reach === "object" && reach !== null ? (reach as { unmatched?: unknown }).unmatched : facts.unmatched;
  return Array.isArray(listed) ? listed.filter((each): each is string => typeof each === "string") : [];
}

/** A parity refusal's facts: the stop, the total, and the walked and published values that disagree. */
function parityOf(facts: Record<string, unknown>): { stop: string; key: string; walked: number; published: number } | null {
  const { stop, key, walked, published } = facts;
  return typeof stop === "string" && typeof key === "string" && typeof walked === "number" && typeof published === "number" ? { stop, key, walked, published } : null;
}

/** Each window of the app and the word for why it was not matched (`unchecked`, `no_public_dates`, `document_invalid`). */
function windowsOf(facts: Record<string, unknown>): string[] {
  const windows = facts.windows;
  if (typeof windows !== "object" || windows === null || Array.isArray(windows)) return [];
  return Object.entries(windows).flatMap(([window, why]) => (typeof why === "string" ? [`${window}: ${why}`] : []));
}

/** A walk the instance refused: the state word's sentence in the reader's language, the instance's
 *  own sentence beneath it for a report, and the facts beside it a reader can act on: the versions
 *  that matched nothing, the versions of channels set aside before the walk, the totals that
 *  disagreed, and each window's reason. */
function RefusedWalk({
  refusal,
  app,
  track,
  source,
  words,
  stops
}: {
  refusal: WalkRefusal;
  app: string;
  track: string;
  source: WalkSource;
  words: WalkCopy;
  stops: Record<string, string>;
}) {
  const about = isWalkSource(refusal.source) ? refusal.source : source;
  const lead = reasonWords(words, refusal.reason, { app, track, source: words.sourceWords[about], sourceId: about }, refusal.detail);
  const unmatched = unmatchedOf(refusal.facts);
  const setAside = channelsSetAside(refusal.facts.other_channels);
  const parity = parityOf(refusal.facts);
  const windows = windowsOf(refusal.facts);
  const mono = "break-all font-mono text-xs text-muted-foreground";
  return (
    <div className="space-y-1 text-sm">
      <p className="text-destructive">{lead}</p>
      {refusal.detail !== lead && <p className="text-xs text-muted-foreground">{words.serverSaid(refusal.detail)}</p>}
      {unmatched.length > 0 && <p className={mono}>{words.unmatchedListed(unmatched)}</p>}
      {setAside.map((each) => (
        <p key={each.channel} className="text-xs text-muted-foreground">
          {words.channelSetAside(each.count, each.label, about === "fleet" ? 5 : 4)}
        </p>
      ))}
      {parity && <p className="text-xs text-muted-foreground">{words.parityFacts(stops[parity.stop] ?? parity.stop, parity.key, parity.walked, parity.published)}</p>}
      {windows.length > 0 && <p className={mono}>{words.windowsFacts(windows)}</p>}
    </div>
  );
}

/**
 * Posture › Patch policy (#614): pick an app, a track, where its release dates come from and a
 * window, move the policy slider, and read what a Mac kept to that policy would have run, day by
 * day. This component is the page's data half and nothing else: it reads which apps LoonSec's
 * patch-policy data references and which sources can date each (`/api/patch-policy/apps`), reads
 * Jamf's patch catalog for the picker's other rows, asks the instance for one walk at a time, and
 * keeps every choice in the address so a link opens the same view. The views draw.
 *
 * **Two modes.** With LoonSec's data held for this organization, the page walks it: Public, Jamf or
 * Fleet dates, computed on this instance (`WalkControls`, `WalkView`). Without it (data sharing off,
 * nothing arrived yet, or the state could not be read), the page draws the reference replays that
 * ship with the build (`ReplayView`), under the sentence that says why. The replays stay as that
 * fallback until LoonSec's data is live in production (ruled 2026-11-24), so the page is never blank
 * between a merge and a deploy.
 *
 * It is a reference analysis of a hypothetical Mac. Nothing here reads this organization's
 * inventory: the catalog read takes title names and bundle IDs and ignores the device counts that
 * ride with them, and a walk reads no device.
 */
export function PatchPolicyPage() {
  const { t } = useLocale();
  const copy = t.patchPolicy;
  const words = t.patchPolicyWalk;
  const [params, setParams] = useSearchParams();
  // The address as this page last asked for it. useSearchParams hands an updater the address of the
  // last render, so two choices made before the page draws again (an app, then a source) would keep
  // only the second; each change builds on the one before it instead. An address the page did not
  // ask for (back, forward, a link) replaces it when it is drawn.
  const latest = useRef(params);
  useLayoutEffect(() => {
    latest.current = params;
  }, [params]);
  const asked = params.get("policy");
  const stop: SliderStop = isSliderStop(asked) ? asked : SLIDER_STOPS[0];

  // `null` until each read lands. A read that FAILED is not an empty answer (#150), so each has its sentence.
  const [titles, setTitles] = useState<CatalogTitle[] | null>(null);
  const [catalogFailed, setCatalogFailed] = useState(false);
  const [appsRead, setAppsRead] = useState<AppsRead | null>(null);

  useEffect(() => {
    let cancelled = false;
    listJamfPatchTitles()
      .then((response) => void (cancelled || setTitles(response.items)))
      .catch(() => void (cancelled || (setTitles([]), setCatalogFailed(true))));
    getPatchPolicyApps()
      .then((answer) => void (cancelled || setAppsRead({ ok: answer })))
      .catch((caught: unknown) => void (cancelled || setAppsRead({ failed: { status: caught instanceof ApiError ? caught.status : null } })));
    return () => void (cancelled = true);
  }, []);

  const apps = appsRead?.ok?.apps ?? null;
  const feed = appsRead?.ok?.feed ?? null;
  const walking = apps !== null;
  const listed = apps ?? [];

  // --- the walk mode's choices, from the address ---
  const appId: string | null = params.get("app") ?? (walking ? listed.at(0)?.app : REPLAY_INDEX.at(0)?.id) ?? null;
  const app = listed.find((each) => each.app === appId) ?? null;
  const track = app ? (params.get("track") ?? defaultTrack(app)) : null;
  const trackKnown = app !== null && app.tracks.some((each) => each.track === track);
  const askedSource = params.get("source");
  const source: WalkSource = isWalkSource(askedSource) ? askedSource : "public";
  const askedYears = Number(params.get("years"));
  const years: WalkYears = isWalkYears(askedYears) ? askedYears : 2;
  const align = params.get("align") === "common";
  const page = Math.max(1, Math.floor(Number(params.get("page"))) || 1);
  const usable = app !== null && track !== null && trackKnown && sourceTrack(app, source, track)?.available === true;
  // The request as its query string: the one value the walk's effect depends on, so the same
  // choices never ask twice.
  const key = usable && app && track ? walkQuery({ app: app.app, track, source, years, align, page }) : null;
  // Keyed by the request it answers, so a walk is never drawn under another choice while the next
  // one loads, and the effect has nothing to reset (#15, #479).
  const [walked, setWalked] = useState<{ key: string; answer: WalkAnswer } | null>(null);
  const answer = key !== null && walked?.key === key ? walked.answer : null;

  useEffect(() => {
    if (key === null) return;
    let cancelled = false;
    void getPatchPolicyWalk(key).then((reply) => void (cancelled || setWalked({ key, answer: reply })));
    return () => void (cancelled = true);
  }, [key]);

  // --- the fallback mode: the reference replays that ship with the build ---
  const fallback = appsRead !== null && !walking;
  const entry = fallback ? (REPLAY_INDEX.find((each) => each.id === appId) ?? null) : null;
  const [read, setRead] = useState<{ id: string; result: ReadResult } | null>(null);
  const result = entry && read?.id === entry.id ? read.result : null;

  useEffect(() => {
    if (!entry) return;
    let cancelled = false;
    void loadReplay(entry).then((loaded) => void (cancelled || setRead({ id: entry.id, result: loaded })));
    return () => void (cancelled = true);
  }, [entry]);

  const indexed = useMemo(() => (apps ? apps.map((each) => ({ id: each.app, name: each.name, bundleIds: each.bundleIds })) : REPLAY_INDEX), [apps]);
  const pickable = useMemo(() => pickerApps(titles ?? [], indexed), [titles, indexed]);
  // Replaced, not pushed: a drag across the slider is one visit, not six. A new app, track, source
  // or window starts the CVE list on its first page, and a new app on its own default track.
  const set = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(latest.current);
    for (const [name, value] of Object.entries(changes)) {
      if (value === null) next.delete(name);
      else next.set(name, value);
    }
    if (Object.keys(changes).some((name) => ["app", "track", "source", "years", "align"].includes(name))) next.delete("page");
    if ("app" in changes) next.delete("track");
    latest.current = next;
    setParams(next, { replace: true });
  };

  const sourceName = words.sources[source];
  const trackLabel = app?.tracks.find((each) => each.track === track)?.label ?? track ?? "";

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{copy.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{copy.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{copy.description}</p>
      </div>
      {appsRead === null && <p className="text-sm text-muted-foreground">{words.appsLoading}</p>}
      {appsRead?.failed && <p className="max-w-3xl text-sm text-destructive">{words.appsFailed(appsRead.failed.status)}</p>}
      {feed && !walking && <p className="max-w-3xl text-sm">{words.fallback(describeFeed(feed, t.support.patchPolicyFeed))}</p>}
      {feed && walking && feed.state !== "current" && (
        <p className={`max-w-3xl text-sm ${FEED_FAILED.has(feed.state) ? "text-amber-700 dark:text-amber-400" : "text-muted-foreground"}`}>
          {describeFeed(feed, t.support.patchPolicyFeed)}
        </p>
      )}
      {appsRead !== null && (
        <div className="grid gap-6 lg:grid-cols-[18rem_minmax(0,1fr)]">
          {/* Stays beside the walk on a wide screen, under the navbar, while the tables scroll. */}
          <div className="space-y-2 lg:sticky lg:top-24 lg:self-start">
            <AppPicker
              apps={pickable}
              selected={walking ? (app?.app ?? null) : (entry?.id ?? null)}
              onSelect={(id) => set({ app: id })}
              copy={copy}
              labels={walking ? { has: words.appInData, none: words.appNoReference } : undefined}
            />
            {titles === null && <p className="text-xs text-muted-foreground">{copy.catalogLoading}</p>}
            {/* Without the catalog the list is the walk's apps or the build's replays: each mode says which. */}
            {catalogFailed && <p className="text-xs text-destructive">{(walking ? words : copy).catalogFailed}</p>}
            {titles?.length === 0 && !catalogFailed && <p className="text-xs text-muted-foreground">{(walking ? words : copy).catalogEmpty}</p>}
          </div>

          {walking ? (
            <div className="min-w-0 space-y-4">
              {!app && <p className="text-sm">{appId === null ? words.noApps : words.unknownApp(appId)}</p>}
              {app && (
                <>
                  {esrFoldedIn(app, titles ?? []) && <p className="text-sm text-muted-foreground">{words.esrNotInData(app.name)}</p>}
                  <WalkControls
                    app={app}
                    track={track ?? ""}
                    source={source}
                    years={years}
                    align={align}
                    onTrack={(next) => set({ track: next })}
                    onSource={(next) => set({ source: next === "public" ? null : next })}
                    onYears={(next) => set({ years: next === 2 ? null : String(next) })}
                    onAlign={(next) => set({ align: next ? "common" : null })}
                    words={words}
                  />
                  {!trackKnown && (
                    <p className="text-sm">{words.unknownTrack(app.name, track ?? "", app.tracks.map((each) => each.label).join(", "))}</p>
                  )}
                  {trackKnown && !usable && <p className="text-sm text-muted-foreground">{words.notWalked(sourceName)}</p>}
                  {usable && !answer && <p className="text-sm text-muted-foreground">{words.walkLoading(trackLabel, sourceName)}</p>}
                  {answer?.failed && (
                    <p className="text-sm text-destructive">
                      {answer.failed.unreadable ? words.walkUnreadable(answer.failed.unreadable) : words.walkFailed(answer.failed.status)}
                    </p>
                  )}
                  {answer?.refusal && <RefusedWalk refusal={answer.refusal} app={app.name} track={trackLabel} source={source} words={words} stops={copy.stops} />}
                  {answer?.walk && (
                    <WalkView
                      walk={answer.walk}
                      stop={stop}
                      onStop={(next) => set({ policy: next })}
                      onPage={(next) => set({ page: next > 1 ? String(next) : null })}
                      copy={copy}
                      words={words}
                    />
                  )}
                </>
              )}
            </div>
          ) : (
            <>
              {!entry && <p className="text-sm">{appId === null ? copy.noReplays : copy.unknownApp(appId)}</p>}
              {entry && !result && <p className="text-sm text-muted-foreground">{copy.replayLoading}</p>}
              {entry && result?.refusal && (
                <div className="space-y-1 text-sm">
                  <p className="text-destructive">{copy.refusedLead(entry.name)} {copy.refused(result.refusal)}</p>
                  <p>{copy.refusedCheck}</p>
                </div>
              )}
              {entry && result?.replay && (
                <ReplayView replay={result.replay} appName={entry.name} stop={stop} onStop={(next) => set({ policy: next })} copy={copy} />
              )}
            </>
          )}
        </div>
      )}
    </section>
  );
}
