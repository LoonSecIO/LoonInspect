import { useEffect, useRef, useState } from "react";
import { Download, RefreshCw, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import {
  getDataSharing,
  getExclusionCandidates,
  getExclusionRankingStatus,
  rankExclusionCandidates,
  type ExclusionRanking,
  type ExclusionRankingStatus,
  type RankingProvider,
  previewExchange,
  resetSubmissionUuid,
  sendExchangeNow,
  updateDataSharing,
  type DataSharingSettings,
  type ExclusionCandidates,
  type ShareLogEntry,
  type SharingTier
} from "@/features/system/api";
import { endpointHost, sendNowAvailability } from "@/features/system/sendNow";
import { ApiError } from "@/config/api";
import { env } from "@/config/env";
import { useLocale } from "@/i18n/LocaleContext";

const TIERS: SharingTier[] = ["reveal", "keys", "off"];

export function DataSharingPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);

  const [settings, setSettings] = useState<DataSharingSettings | null>(null);
  const [globsDraft, setGlobsDraft] = useState("");
  const [preview, setPreview] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  // Send now (#408): the row the last send wrote, which replaces the preview in the box,
  // and the server's refusal when a click meets one the page could not foresee.
  const [sent, setSent] = useState<ShareLogEntry | null>(null);
  const [sending, setSending] = useState(false);
  const [sendRefusal, setSendRefusal] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // What the fleet carries that no public source here knows, and what each pattern
  // matches (#483). Three states, never one: counting, counted, and could-not-count.
  const [candidates, setCandidates] = useState<ExclusionCandidates | null>(null);
  const [candidatesError, setCandidatesError] = useState<string | null>(null);
  const [rankingStatus, setRankingStatus] = useState<ExclusionRankingStatus | null>(null);
  const [rankingProvider, setRankingProvider] = useState<RankingProvider | "">("");
  const [ranking, setRanking] = useState<ExclusionRanking | null>(null);
  const [rankingBusy, setRankingBusy] = useState(false);
  const [rankingError, setRankingError] = useState<string | null>(null);
  const candidateRevision = useRef(0);

  useEffect(() => {
    getExclusionRankingStatus().then(setRankingStatus).catch(() => setRankingError(t.system.sharing.rankingStatusFailed));
  }, [t.system.sharing.rankingStatusFailed]);

  function invalidateRanking() {
    candidateRevision.current += 1;
    setRanking(null);
    setRankingError(null);
  }

  async function handleRanking() {
    const provider = rankingProvider || rankingStatus?.providers[0]?.provider;
    if (!provider) return;
    const revision = ++candidateRevision.current;
    setRankingBusy(true);
    setRankingError(null);
    try {
      const result = await rankExclusionCandidates(provider, draftGlobs());
      if (candidateRevision.current !== revision) return;
      setCandidates(result.candidates);
      setCandidatesError(null);
      setRanking(result);
    } catch (caught) {
      if (candidateRevision.current !== revision) return;
      setRankingError(caught instanceof ApiError && caught.detail ? caught.detail : t.system.sharing.rankingFailed);
    } finally {
      setRankingBusy(false);
    }
  }

  /** #150's rule, on this panel: a read that failed must not render as a build without a
   *  panel, nor as a first load still in flight. It says so instead — and says it under
   *  the textarea, because the panel is an aid to the box, never a reason to block it. */
  function refreshCandidates(globs: string[]) {
    invalidateRanking();
    const revision = candidateRevision.current;
    setCandidatesError(null);
    getExclusionCandidates(globs)
      .then((result) => { if (candidateRevision.current === revision) setCandidates(result); })
      .catch(() => {
        if (candidateRevision.current !== revision) return;
        // The stale counts go with it. A count of the box as it was two edits ago is a
        // wrong answer where "could not be loaded" is a true one.
        setCandidates(null);
        setCandidatesError(t.system.sharing.candidatesFailed);
      });
  }

  useEffect(() => {
    getDataSharing()
      .then((loaded) => {
        setSettings(loaded);
        setGlobsDraft(loaded.excludeGlobs.join("\n"));
        refreshCandidates(loaded.excludeGlobs);
      })
      .catch(() => setError(t.system.sharing.loadFailed));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function draftGlobs(): string[] {
    return globsDraft.split("\n").map((g) => g.trim()).filter(Boolean);
  }

  /** Accepting a suggestion is the same audited PUT a hand-typed glob takes — no second
   *  write path, and the audit record cannot tell the two apart. */
  async function addGlob(glob: string) {
    invalidateRanking();
    const next = draftGlobs().includes(glob) ? draftGlobs() : [...draftGlobs(), glob];
    setGlobsDraft(next.join("\n"));
    await apply({ excludeGlobs: next });
    refreshCandidates(next);
  }

  async function apply(update: { tier?: SharingTier; excludeGlobs?: string[] }) {
    try {
      setError(null);
      setSettings(await updateDataSharing(update));
    } catch {
      setError(t.system.sharing.saveFailed);
    }
  }

  async function handleResetUuid() {
    try {
      setError(null);
      setSettings(await resetSubmissionUuid());
    } catch {
      setError(t.system.sharing.saveFailed);
    }
  }

  async function handleDownloadLog() {
    try {
      setError(null);
      // Raw fetch rather than apiRequest: the endpoint streams NDJSON, not JSON.
      const response = await fetch(`${env.apiBaseUrl}/system/share-log`, { credentials: "include" });
      if (!response.ok) throw new Error(String(response.status));
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "share-log.ndjson";
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(t.system.sharing.loadFailed);
    }
  }

  async function handlePreview() {
    setPreviewLoading(true);
    try {
      setError(null);
      setPreview(JSON.stringify(await previewExchange(), null, 2));
      setSent(null);
      setSendRefusal(null);
    } catch {
      setError(t.system.sharing.loadFailed);
    } finally {
      setPreviewLoading(false);
    }
  }

  async function handleSend() {
    setSending(true);
    setSendRefusal(null);
    try {
      setError(null);
      const result = await sendExchangeNow();
      setSent(result.exchange);
      setPreview(null);
      setSettings(result.settings);
    } catch (caught) {
      // A 409 is a refusal before anything was attempted, and its detail is the
      // sentence; anything else never reached the exchange at all.
      setSendRefusal(
        caught instanceof ApiError && caught.status === 409 && caught.detail
          ? caught.detail
          : t.system.sharing.sendRequestFailed
      );
    } finally {
      setSending(false);
    }
  }

  if (!settings) {
    return <p className="text-sm text-muted-foreground">{error ?? t.auth.loading}</p>;
  }

  // One reason locks these controls, and it is the permission: changing what this
  // instance shares is a consent decision reserved to administrators
  // (`permissions.py`, SYSTEM_WRITE). The environment override used to lock them too,
  // which contradicted the backend, whose PUT is written to persist a choice made
  // while overridden so it survives the override being lifted (#302). Now the
  // override is explained above and the choice is recorded beneath it.
  const locked = !canWrite;
  const sendAvailability = sendNowAvailability(settings, canWrite);

  function outcomeLabel(outcome: string | null): string {
    switch (outcome) {
      case "sent":
        return t.system.sharing.outcomeSent;
      case "failed":
        return t.system.sharing.outcomeFailed;
      default:
        return outcome ?? "?";
    }
  }
  const tierLabels: Record<SharingTier, { label: string; description: string }> = {
    reveal: { label: t.system.sharing.tierReveal, description: t.system.sharing.tierRevealHelp },
    keys: { label: t.system.sharing.tierKeys, description: t.system.sharing.tierKeysHelp },
    off: { label: t.system.sharing.tierOff, description: t.system.sharing.tierOffHelp }
  };

  return (
    <div className="max-w-3xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">{t.nav.dataSharing}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.system.sharing.pageDescription}</p>
      </div>

      {settings.envDisabled && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm">
          {t.system.sharing.envLocked}
        </p>
      )}

      {!canWrite && (
        <p className="rounded-md border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
          {t.system.sharing.readOnlyRole}
        </p>
      )}

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.tierHeading}</h2>
        {settings.envDisabled && (
          <p className="text-xs text-muted-foreground">{t.system.sharing.tierRecordedWhileOverridden}</p>
        )}
        {TIERS.map((tier) => (
          <label
            key={tier}
            className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 ${
              settings.tier === tier ? "border-primary bg-primary/5" : "border-input"
            } ${locked ? "cursor-not-allowed opacity-60" : ""}`}
          >
            <input
              type="radio"
              name="sharing-tier"
              className="mt-1"
              checked={settings.tier === tier}
              disabled={locked}
              onChange={() => void apply({ tier })}
            />
            <span>
              <span className="block text-sm font-medium">{tierLabels[tier].label}</span>
              <span className="block text-xs text-muted-foreground">
                {tierLabels[tier].description}
              </span>
            </span>
          </label>
        ))}
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.disclosureHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosureShared}</p>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosureNever}</p>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosureReveals}</p>
        <p className="text-sm text-muted-foreground">{t.system.sharing.disclosurePseudonym}</p>
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.previewHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.previewHelp}</p>
        {sendAvailability !== "hidden" && (
          <p className="text-sm text-muted-foreground">{t.system.sharing.sendHelp}</p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" onClick={handlePreview} disabled={previewLoading || sending}>
            {previewLoading ? t.auth.loading : t.system.sharing.previewButton}
          </Button>
          {sendAvailability !== "hidden" && (
            <Button
              type="button"
              variant="outline"
              onClick={handleSend}
              disabled={sendAvailability !== "ready" || sending}
            >
              <Send aria-hidden="true" className="mr-1.5 h-4 w-4" />
              {sending ? t.system.sharing.sending : t.system.sharing.sendButton}
            </Button>
          )}
        </div>
        {sendAvailability === "blockedEnv" && (
          <p className="text-xs text-muted-foreground">{t.system.sharing.sendBlockedEnv}</p>
        )}
        {sendAvailability === "blockedOff" && (
          <p className="text-xs text-muted-foreground">{t.system.sharing.sendBlockedOff}</p>
        )}
        {sending && <p className="text-xs text-muted-foreground">{t.system.sharing.sendingHelp}</p>}
        {sendRefusal && (
          <p role="alert" className="text-sm text-destructive">
            {sendRefusal}
          </p>
        )}
        {sent !== null ? (
          // The past, where the future was: the row the send wrote, never the corpus link
          // the answer may have carried — that is a capability and is never shown.
          <div className="space-y-2">
            <p className="text-sm">
              {(sent.outcome === "sent" ? t.system.sharing.resultSent : t.system.sharing.resultFailed)(
                new Date(sent.occurredAt).toLocaleString(),
                endpointHost(sent.endpoint)
              )}
            </p>
            {sent.error && <p className="text-sm text-destructive">{sent.error}</p>}
            {sent.revealsShed && <p className="text-xs text-muted-foreground">{t.system.sharing.revealsShed}</p>}
            <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
              {JSON.stringify(sent.payload, null, 2)}
            </pre>
          </div>
        ) : (
          preview !== null && (
            <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">
              {preview}
            </pre>
          )
        )}
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.identityHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.identityHelp}</p>
        <p className="flex items-center gap-3 text-sm">
          <code className="rounded bg-muted px-2 py-1 font-mono text-xs">
            {settings.submissionUuid}
          </code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleResetUuid}
            disabled={locked}
          >
            <RefreshCw aria-hidden="true" className="mr-1.5 h-3.5 w-3.5" />
            {t.system.sharing.resetUuid}
          </Button>
        </p>
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.excludeHeading}</h2>
        <p className="text-sm text-muted-foreground">{t.system.sharing.excludeHelp}</p>
        <textarea
          className="min-h-24 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
          value={globsDraft}
          disabled={locked}
          onChange={(event) => { invalidateRanking(); setGlobsDraft(event.target.value); }}
          onBlur={() => {
            void apply({ excludeGlobs: draftGlobs() });
            refreshCandidates(draftGlobs());
          }}
          placeholder="com.acme.*"
        />
        {candidatesError && (
          <p role="alert" className="border-t pt-3 text-xs text-amber-700 dark:text-amber-500">
            {candidatesError}
          </p>
        )}
        {!candidates && !candidatesError && (
          <p className="border-t pt-3 text-xs text-muted-foreground">{t.system.sharing.candidatesLoading}</p>
        )}
        {candidates && (
          <div className="space-y-3 border-t pt-3">
            {candidates.globs.map((count) => (
              <p key={count.glob} className="text-xs">
                <code className="font-mono">{count.glob}</code>{" "}
                {t.system.sharing.globMatches(count.appCount, count.deviceCount)}
                {/* The case trap, said out loud: fnmatch is case-sensitive in the
                    container, so com.acme.* leaves com.Acme.Deploy on the wire. */}
                {count.caseMisses.map((bundleId) => (
                  <span key={bundleId} className="block text-amber-700 dark:text-amber-500">
                    {t.system.sharing.caseMiss(bundleId)}
                  </span>
                ))}
                {count.moreCaseMisses > 0 && (
                  <span className="block text-amber-700 dark:text-amber-500">
                    {t.system.sharing.moreCaseMisses(count.moreCaseMisses)}
                  </span>
                )}
              </p>
            ))}
            {candidates.moreGlobs > 0 && (
              <p className="text-xs text-muted-foreground">{t.system.sharing.moreGlobs(candidates.moreGlobs)}</p>
            )}
            <h3 className="text-sm font-medium">{t.system.sharing.candidatesHeading}</h3>
            <p className="text-xs text-muted-foreground">{t.system.sharing.candidatesHelp}</p>
            {canWrite && rankingStatus?.reason === "local_endpoint_required" && (
              <p className="text-xs text-muted-foreground">{t.system.sharing.rankingLocalRequired}</p>
            )}
            {canWrite && rankingStatus?.available && candidates.groups.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">{t.system.sharing.rankingDisclosure}</p>
                <label className="flex flex-wrap items-center gap-2 text-xs">
                  {t.system.sharing.rankingEndpoint}
                  <select className="rounded border bg-background p-1" value={rankingProvider || rankingStatus.providers[0]?.provider}
                    onChange={(event) => { invalidateRanking(); setRankingProvider(event.target.value as RankingProvider); }} disabled={rankingBusy}>
                    {rankingStatus.providers.map((provider) => (
                      <option key={provider.provider} value={provider.provider}>{provider.model} · {provider.destination}</option>
                    ))}
                  </select>
                  <Button type="button" size="sm" variant="outline" onClick={() => void handleRanking()} disabled={rankingBusy}>
                    {rankingBusy ? t.system.sharing.rankingBusy : t.system.sharing.rankingButton}
                  </Button>
                </label>
              </div>
            )}
            {rankingError && <p role="alert" className="text-xs text-destructive">{rankingError}</p>}
            {ranking && <p className="text-xs text-muted-foreground">{t.system.sharing.rankingResult(ranking.model, ranking.destination)}</p>}
            {candidates.groups.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                {t.system.sharing.candidatesNone(candidates.catalogTitles, candidates.libraryTitles)}
              </p>
            ) : (
              candidates.groups.map((group) => (
                <div key={group.prefix} className="rounded-md border p-3 text-xs">
                  <p className="flex flex-wrap items-center gap-2">
                    <code className="font-mono text-sm">{group.prefix}</code>
                    <span className="text-muted-foreground">
                      {t.system.sharing.groupSummary(group.appCount, group.deviceCount)}
                    </span>
                    {ranking?.assessments.filter((assessment) => assessment.prefix === group.prefix).map((assessment) => (
                      <span key={assessment.prefix} className="text-muted-foreground">{t.system.sharing.rankingLabels[assessment.classification]}</span>
                    ))}
                    {group.excluded && (
                      <span className="text-muted-foreground">{t.system.sharing.groupCovered}</span>
                    )}
                    {group.suggestion !== null && !group.excluded && !locked && (
                      <Button type="button" size="sm" variant="outline" onClick={() => void addGlob(group.suggestion!)}>
                        {t.system.sharing.addGlob(group.suggestion)}
                      </Button>
                    )}
                  </p>
                  <ul className="mt-2 space-y-1 text-muted-foreground">
                    {/* Keyed on both: one bundle ID carries two titles wherever two display
                        names share it, and that is a row each. */}
                    {group.apps.map((app) => (
                      <li key={`${app.bundleId}|${app.name}`}>
                        {t.system.sharing.candidateRow(app.name, app.bundleId, app.deviceCount)}
                      </li>
                    ))}
                  </ul>
                </div>
              ))
            )}
            {candidates.moreGroups > 0 && (
              <p className="text-xs text-muted-foreground">{t.system.sharing.moreGroups(candidates.moreGroups)}</p>
            )}
          </div>
        )}
      </section>

      <section className="space-y-3 rounded-lg border bg-card p-6">
        <h2 className="font-semibold">{t.system.sharing.logHeading}</h2>
        <p className="text-sm text-muted-foreground">
          {t.system.sharing.lastExchange}:{" "}
          {settings.lastExchangeAt === null
            ? // "never" keeps meaning "no exchange has been recorded" — an off-tier instance
              // logs nothing, and that is a different fact from a skipped one.
              t.system.sharing.neverExchanged
            : settings.lastExchangeOutcome === "skipped_env"
              ? // The daily proof the override is biting gets its own sentence, not a code
                // in parentheses.
                t.system.sharing.skippedEnv(new Date(settings.lastExchangeAt).toLocaleString())
              : `${new Date(settings.lastExchangeAt).toLocaleString()} (${outcomeLabel(settings.lastExchangeOutcome)}${
                  settings.lastExchangeRevealsShed ? `, ${t.system.sharing.revealsShed}` : ""
                })`}
        </p>
        {settings.lastExchangeOutcome === "failed" && settings.lastExchangeError && (
          // The row's own sentence (#408): before, "(failed)" was all the page said, and
          // the reason lived only in the download below.
          <p className="text-sm text-destructive">{settings.lastExchangeError}</p>
        )}
        <p className="text-sm text-muted-foreground">{t.system.sharing.logHelp}</p>
        <Button type="button" variant="outline" onClick={handleDownloadLog}>
          <Download aria-hidden="true" className="mr-1.5 h-4 w-4" />
          {t.system.sharing.downloadLog}
        </Button>
      </section>
    </div>
  );
}
