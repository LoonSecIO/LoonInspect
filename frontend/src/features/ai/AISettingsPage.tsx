import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { useFeatureFlagStore } from "@/features/settings/flagStore";
import { getDataSharing, updateDataSharing } from "@/features/system/api";
import {
  deleteConfig,
  getHostDetection,
  getProviders,
  listConfigs,
  listModels,
  saveConfig,
  sendTest,
  type HostDetection,
  type ModelsResponse,
  type Provider,
  type ProvidersResponse,
  type TestResponse
} from "@/features/ai/api";
import {
  byProvider,
  cardEffort,
  effortToSend,
  openingCard,
  PROVIDER_ORDER,
  REMOVED,
  removeAnswer,
  removeLine,
  savedAfterAnswer,
  savedConfigsOf,
  statusAfterAnswer,
  statusLine,
  takesReasoningEffort,
  type RemoveAnswer,
  type SavedByProvider,
  type StatusReading
} from "@/features/ai/savedState";
import { getPromptStatus } from "@/features/changes/api";
import { failureReason, isPromptStatus } from "@/features/changes/prompt";
import { ApiError } from "@/config/api";
import { ExternalLink } from "@/components/ui/external-link";
import { APPLE_FM_GUIDE_URL } from "@/features/support/links";
import { useLocale } from "@/i18n/LocaleContext";

const AI_FLAG = "ai_features";

/**
 * Settings › AI: the test box (#319). One prompt to an endpoint the admin names,
 * the reply shown as it came back. Three cards, one per entry; the Apple card is
 * "via Docker Desktop" because the label names the pattern the operator is on, not
 * what powers the model. Every model call is made by the backend, never from here.
 *
 * Save keeps a card on this server for the Changes Prompt bar, judged the way Send
 * judges it; the key goes in encrypted and never comes back, so the field says one is
 * there instead of showing it. The status line says whether the bar shows, and if not,
 * which of the flag, the consent or a saved card is missing.
 */
export function AISettingsPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);

  // The one flag state the whole session shares (#402). The route guard in front of
  // this page reads the same value, so a page that renders at all has the flag on —
  // the card below says so, and stops saying "\u2026" for a read that no longer happens here.
  const flagOn = useFeatureFlagStore((state) => state.enabled.has(AI_FLAG));
  const [consent, setConsent] = useState<boolean | null>(null);
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);
  const [detection, setDetection] = useState<HostDetection | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [provider, setProvider] = useState<Provider>("apple_fm");
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [reasoningEffort, setReasoningEffort] = useState<string>("");
  const [prompt, setPrompt] = useState(t.ai.promptDefault);

  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<TestResponse | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  const [loaded, setLoaded] = useState<ModelsResponse | null>(null);
  const [sendError, setSendError] = useState<string | null>(null);
  const [consentError, setConsentError] = useState<string | null>(null);

  const [saved, setSaved] = useState<SavedByProvider>({});
  // The status, or the sentence for why it could not be read — one value, so a line that
  // was true before a Remove can never sit beside the failure to re-read it.
  const [statusReading, setStatusReading] = useState<StatusReading>(null);
  const [savingConfig, setSavingConfig] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [configNotice, setConfigNotice] = useState<string | null>(null);
  // The saved pills' read reports its own failure, in its own line.
  const [configsError, setConfigsError] = useState<string | null>(null);
  // Only the newest read of each lands: a slow first read that settles after a Remove's
  // re-read would otherwise put back what the server held before the Remove.
  const savedReads = useRef(0);
  const statusReads = useRef(0);
  // The newest saved map and the card the page is on, for code that runs after an await:
  // the opening selection reads these rather than what its own, possibly older, read said.
  // `keepSaved` and `fillCard` are the only writers, so each stays level with its state.
  const savedLatest = useRef<SavedByProvider>({});
  const providerLatest = useRef<Provider>("apple_fm");
  // Remove is the one control that works before the page's reads settle (it needs only the
  // saved cards); once pressed, the opening selection leaves the card and its lines alone.
  const removeAsked = useRef(false);

  function keepSaved(next: SavedByProvider) {
    savedLatest.current = next;
    setSaved(next);
  }

  // The two reads the Prompt bar added. Loaded apart from the page's own four, so that
  // either failing costs its own line and not the page: in one Promise.all with them, a
  // failed read of the saved cards blanked the test box, the switches and the detection.
  // Both settle rather than throw; a caller never has to catch them. A body that is not
  // the shape the read promises is an answer that could not be read, never an empty list.
  function readSaved(): Promise<SavedByProvider | null> {
    const read = ++savedReads.current;
    return listConfigs().then(
      (body: unknown) => {
        const configs = savedConfigsOf(body);
        const savedNow = configs ? byProvider(configs) : null;
        if (read === savedReads.current) {
          if (savedNow) keepSaved(savedNow);
          setConfigsError(savedNow ? null : t.ai.configsLoadFailed(failureReason(null, t.changes.prompt)));
        }
        return savedNow;
      },
      (error: unknown) => {
        if (read === savedReads.current) setConfigsError(t.ai.configsLoadFailed(failureReason(error, t.changes.prompt)));
        return null;
      }
    );
  }

  function readPromptStatus(): Promise<void> {
    const read = ++statusReads.current;
    const failed = (error: unknown): StatusReading => ({
      failure: t.ai.promptStatusLoadFailed(failureReason(error, t.changes.prompt))
    });
    return getPromptStatus().then(
      (status: unknown) => {
        if (read === statusReads.current) setStatusReading(isPromptStatus(status) ? { status } : failed(null));
      },
      (error: unknown) => {
        if (read === statusReads.current) setStatusReading(failed(error));
      }
    );
  }

  useEffect(() => {
    let cancelled = false;
    void readPromptStatus();
    const openingRead = readSaved();
    // `readSaved` numbers its read as it starts it; this is the opening read's number.
    const openingReadNumber = savedReads.current;
    Promise.all([getDataSharing(), getProviders(), getHostDetection(), openingRead])
      .then(([sharing, loadedProviders, loadedDetection]) => {
        if (cancelled) return;
        setConsent(sharing.aiInference);
        setProviders(loadedProviders);
        setDetection(loadedDetection);
        // A saved card opens first — the first one is what the Prompt bar uses. With
        // none saved (or none readable), the hint, never a gate: a full match pre-selects
        // the Apple card; anything else starts on the documented default (Ollama, #28)
        // and says what it saw. The newest read of the saved cards wins here as it does
        // for the pills: a Remove asked for or made while the slowest of these reads was
        // still out keeps its card and its confirm or its line (`openingCard`).
        const opening = openingCard({
          newerRead: openingReadNumber !== savedReads.current,
          removeAsked: removeAsked.current,
          latest: savedLatest.current,
          current: providerLatest.current,
          dockerDesktopOnMacos: loadedDetection.dockerDesktopOnMacos
        });
        if (opening.clearLines) selectCard(loadedProviders, opening.card);
        else fillCard(loadedProviders, opening.card);
      })
      .catch(() => {
        if (!cancelled) setLoadError(t.ai.loadFailed);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // A saved card comes back as it was saved; an unsaved one starts from its defaults.
  // Either way the key field starts empty — a saved key is never sent to the page — and
  // the Apple card starts with no reasoning effort, whatever an older save carried.
  function fillCard(loaded: ProvidersResponse, next: Provider) {
    const entry = loaded.entries.find((e) => e.provider === next);
    if (!entry) return false;
    const kept = savedLatest.current[next];
    providerLatest.current = next;
    setProvider(next);
    setBaseUrl(kept?.baseUrl ?? entry.baseUrl);
    setModel(kept?.model ?? entry.model);
    setApiKey("");
    setReasoningEffort(cardEffort(next, kept, entry.reasoningEffort));
    return true;
  }

  // Picking a card starts it clean: the last card's reply and its lines go with it.
  function selectCard(loaded: ProvidersResponse, next: Provider) {
    if (!fillCard(loaded, next)) return;
    setResult(null);
    setSendError(null);
    setLoaded(null);
    setConfigError(null);
    setConfigNotice(null);
    setConfirmRemove(false);
  }

  // After a save or a consent change: what is saved, and whether the Prompt bar now
  // shows. Each read reports its own failure. (A removal re-reads in `handleRemove`.)
  async function reloadSaved() {
    await Promise.all([readSaved(), readPromptStatus()]);
  }

  async function handleSave() {
    if (!providers) return;
    const entry = providers.entries.find((e) => e.provider === provider);
    setSavingConfig(true);
    setConfigError(null);
    setConfigNotice(null);
    try {
      const config = await saveConfig(provider, {
        hostReach: entry?.usesHostReach ? "docker_desktop" : "custom",
        baseUrl,
        model,
        // Left out on the Apple card, which takes none (`effortToSend`).
        reasoningEffort: effortToSend(provider, reasoningEffort),
        // Blank keeps the stored key; the server never sends it back to compare.
        apiKey: apiKey.trim() ? apiKey.trim() : null
      });
      keepSaved({ ...savedLatest.current, [provider]: config });
      // The key lives on the server now, encrypted; the page stops holding it.
      setApiKey("");
      setConfigNotice(t.ai.savedNotice);
      await reloadSaved();
    } catch (error) {
      // reloadSaved() reports its own failures, so this catch is the save's.
      setConfigError(error instanceof ApiError && error.detail ? error.detail : t.ai.configSaveFailed);
    } finally {
      setSavingConfig(false);
    }
  }

  // The transitions live in savedState.ts, where the test lane holds them to the rule:
  // the page follows the server's latest known truth.
  async function handleRemove() {
    const target = provider;
    setSavingConfig(true);
    setConfigError(null);
    setConfigNotice(null);
    try {
      const answer: RemoveAnswer = await deleteConfig(target).then(
        () => REMOVED,
        (error: unknown) => removeAnswer(error, t.ai.configRemoveFailed)
      );
      // A 204 or a 404 is the server saying the card is gone: its pill and its Remove go
      // now, and a status line naming it with them, whatever the re-reads do.
      keepSaved(savedAfterAnswer(savedLatest.current, target, answer));
      setStatusReading((current) => statusAfterAnswer(current, target, answer));
      // Whatever the removal did, the page shows what the server now holds rather than
      // what it held before. Each read reports its own failure in its own line.
      const [reread] = await Promise.all([readSaved(), readPromptStatus()]);
      const line = removeLine(target, answer, reread, t.ai);
      setConfigNotice(line.notice);
      setConfigError(line.error);
    } finally {
      // Asked once, for this attempt: the next Remove asks again, and a Save never does.
      setConfirmRemove(false);
      setSavingConfig(false);
    }
  }

  async function handleLoadModels() {
    if (!providers) return;
    const entry = providers.entries.find((e) => e.provider === provider);
    setLoadingModels(true);
    setSendError(null);
    try {
      setLoaded(
        await listModels({
          provider,
          hostReach: entry?.usesHostReach ? "docker_desktop" : "custom",
          baseUrl,
          apiKey: apiKey.trim() ? apiKey.trim() : undefined
        })
      );
    } catch (error) {
      setLoaded(null);
      setSendError(error instanceof ApiError && error.detail ? error.detail : t.ai.sendFailed);
    } finally {
      setLoadingModels(false);
    }
  }

  async function toggleConsent() {
    if (consent === null) return;
    setConsentError(null);
    try {
      const updated = await updateDataSharing({ aiInference: !consent });
      setConsent(updated.aiInference);
    } catch {
      setConsentError(t.ai.saveFailed);
      return;
    }
    // The consent is one of the three things the Prompt bar waits on.
    await reloadSaved();
  }

  async function handleSend() {
    if (!providers) return;
    const entry = providers.entries.find((e) => e.provider === provider);
    setSending(true);
    setSendError(null);
    setResult(null);
    try {
      const response = await sendTest({
        provider,
        hostReach: entry?.usesHostReach ? "docker_desktop" : "custom",
        baseUrl,
        model,
        apiKey: apiKey.trim() ? apiKey.trim() : undefined,
        prompt,
        reasoningEffort: effortToSend(provider, reasoningEffort)
      });
      setResult(response);
    } catch (error) {
      setSendError(error instanceof ApiError && error.detail ? error.detail : t.ai.sendFailed);
    } finally {
      setSending(false);
    }
  }

  const entry = providers?.entries.find((e) => e.provider === provider);
  const switchesOn = canWrite && flagOn && consent === true;
  const canSend = switchesOn && !sending && baseUrl.trim() !== "" && model.trim() !== "" && prompt.trim() !== "";
  const canLoadModels = switchesOn && !loadingModels && baseUrl.trim() !== "";
  // What the endpoint said it serves, once asked; the card's own suggestions until then.
  const suggestions = loaded && !loaded.error ? loaded.models.map((m) => m.id) : (entry?.models ?? []);
  const modelNotListed = loaded !== null && !loaded.error && model.trim() !== "" && !suggestions.includes(model.trim());
  // Saving needs the flag but not the consent: nothing leaves the pod on a save. The
  // server judges the URL and the key rule exactly as Send does.
  const stored = saved[provider];
  const canSave = canWrite && flagOn && !savingConfig && baseUrl.trim() !== "" && model.trim() !== "";
  const canRemove = canWrite && !savingConfig && stored !== undefined;
  // A Save's or a Remove's line is about the card it was pressed on, and lands under
  // whichever card is showing; so the cards hold still until it has landed.
  const cardsLocked = !providers || savingConfig;
  const promptBarLine = statusLine(statusReading, t.ai);

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.ai.title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t.ai.description}</p>
      </div>

      {loadError && <p className="text-sm text-destructive">{loadError}</p>}

      {/* The two switches, both default off. The flag lives on its own page; the
          consent is toggled here because it has no other surface yet. */}
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border bg-card p-4">
          <p className="text-sm font-medium">{t.ai.flagLabel}</p>
          <p className="mt-1 text-sm text-muted-foreground">
            {flagOn ? t.ai.on : t.ai.off}
            {" · "}
            <Link className="underline" to="/settings/feature-flags">
              {t.ai.flagHelp}
            </Link>
          </p>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-medium">{t.ai.consentLabel}</p>
              <p className="mt-1 text-sm text-muted-foreground">
                {consent === null ? "…" : consent ? t.ai.consentOn : t.ai.consentOff}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">{t.ai.consentHelp}</p>
              {consentError && <p className="mt-1 text-xs text-destructive">{consentError}</p>}
            </div>
            {canWrite && consent !== null && (
              <Button variant={consent ? "outline" : "default"} size="sm" onClick={() => void toggleConsent()}>
                {consent ? t.ai.consentToggleOff : t.ai.consentToggleOn}
              </Button>
            )}
          </div>
        </div>
      </div>

      {detection && (
        <div className="rounded-lg border bg-card p-4">
          <p className="text-sm font-medium">{t.ai.detectionHeading}</p>
          <p className="mt-1 text-sm text-muted-foreground">
            {detection.dockerDesktopOnMacos
              ? t.ai.detectionDockerDesktopMac
              : detection.runtime === "docker_desktop"
                ? t.ai.detectionDockerDesktop
                : t.ai.detectionUnknown}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {t.ai.detectionEvidence}: {Object.values(detection.evidence).join(" · ")}
          </p>
        </div>
      )}

      <div className="space-y-3">
        <h2 className="font-semibold">{t.ai.providersHeading}</h2>
        {/* Whether the Changes Prompt bar shows, and if not, which of the three it waits
            on — the page that can fix it is the page that says so. */}
        {promptBarLine &&
          (promptBarLine.failed ? (
            <p className="text-sm text-destructive">{promptBarLine.text}</p>
          ) : (
            <p role="status" className="text-sm text-muted-foreground">
              {promptBarLine.text}
            </p>
          ))}
        {configsError && <p className="text-sm text-destructive">{configsError}</p>}
        <div className="grid gap-3 md:grid-cols-3">
          {PROVIDER_ORDER.map((candidate) => (
            <label
              key={candidate}
              className={`flex flex-col gap-1 rounded-lg border p-4 ${cardsLocked ? "cursor-default" : "cursor-pointer"} ${
                provider === candidate ? "border-primary bg-primary/5" : "border-input"
              }`}
            >
              <input
                type="radio"
                name="ai-provider"
                className="sr-only"
                checked={provider === candidate}
                disabled={cardsLocked}
                onChange={() => providers && selectCard(providers, candidate)}
              />
              <span className="flex items-start justify-between gap-2">
                <span className="text-sm font-medium">{t.ai.providerLabels[candidate]}</span>
                {saved[candidate] && (
                  <span className="shrink-0 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
                    {t.ai.savedPill}
                  </span>
                )}
              </span>
              <span className="text-xs text-muted-foreground">{t.ai.providerHelp[candidate]}</span>
            </label>
          ))}
        </div>
        <p className="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
          <ExternalLink href={APPLE_FM_GUIDE_URL}>{t.ai.appleGuide}</ExternalLink>
          <span>{t.ai.otherRuntimes}</span>
        </p>
      </div>

      <div className="grid gap-4 rounded-lg border bg-card p-4 md:grid-cols-2">
        <label className="space-y-1 text-sm">
          <span className="font-medium">{t.ai.baseUrl}</span>
          <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} spellCheck={false} />
        </label>
        <div className="space-y-1 text-sm">
          <div className="flex items-center justify-between gap-2">
            <label className="font-medium" htmlFor="ai-model">
              {t.ai.model}
            </label>
            <Button type="button" variant="outline" size="sm" disabled={!canLoadModels} onClick={() => void handleLoadModels()}>
              {loadingModels ? t.ai.loadingModels : t.ai.loadModels}
            </Button>
          </div>
          <Input id="ai-model" value={model} onChange={(e) => setModel(e.target.value)} list="ai-models" spellCheck={false} />
          <datalist id="ai-models">
            {suggestions.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
          {loaded && loaded.error && (
            <p className="text-xs text-destructive">
              {loaded.error.kind}
              {loaded.error.status ? ` (${loaded.error.status})` : ""}: {loaded.error.message}
            </p>
          )}
          {loaded && !loaded.error && (
            <p className="text-xs text-muted-foreground">{t.ai.modelsLoaded(loaded.models.length, loaded.latencyMs)}</p>
          )}
          {modelNotListed && <p className="text-xs text-muted-foreground">{t.ai.modelNotListed}</p>}
        </div>
        {entry && entry.key !== "none" && (
          <label className="space-y-1 text-sm">
            <span className="font-medium">
              {t.ai.apiKey} ({entry.key === "required" ? t.ai.apiKeyRequired : t.ai.apiKeyOptional})
            </span>
            <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off" />
            {stored?.hasKey && <span className="block text-xs text-muted-foreground">{t.ai.keySaved}</span>}
          </label>
        )}
        {/* Not on the Apple card: fm serve refuses any reasoning effort on its system
            model, so a control there could only set up a call that fails. */}
        {takesReasoningEffort(provider) && (
          <label className="space-y-1 text-sm">
            <span className="font-medium">{t.ai.reasoningEffort}</span>
            <select
              className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
              value={reasoningEffort}
              onChange={(e) => setReasoningEffort(e.target.value)}
            >
              <option value="">{t.ai.reasoningDefault}</option>
              {providers?.reasoningEfforts.map((effort) => (
                <option key={effort} value={effort}>
                  {effort}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="space-y-1 text-sm md:col-span-2">
          <span className="font-medium">{t.ai.prompt}</span>
          <textarea
            className="flex min-h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            maxLength={4000}
          />
        </label>
        <div className="flex flex-wrap items-center gap-3 md:col-span-2">
          <Button disabled={!canSend} onClick={() => void handleSend()}>
            {sending ? t.ai.sending : t.ai.send}
          </Button>
          <Button variant="outline" disabled={!canSave} onClick={() => void handleSave()}>
            {savingConfig && !confirmRemove ? t.ai.saving : t.ai.save}
          </Button>
          {stored &&
            (confirmRemove ? (
              <span className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {t.ai.removeConfirm(t.ai.providerLabels[provider])}
                </span>
                <Button variant="destructive" size="sm" disabled={savingConfig} onClick={() => void handleRemove()}>
                  {savingConfig ? t.ai.removing : t.ai.remove}
                </Button>
                <Button variant="outline" size="sm" disabled={savingConfig} onClick={() => setConfirmRemove(false)}>
                  {t.ai.cancel}
                </Button>
              </span>
            ) : (
              <Button
                variant="outline"
                disabled={!canRemove}
                onClick={() => {
                  removeAsked.current = true;
                  setConfirmRemove(true);
                }}
              >
                {t.ai.remove}
              </Button>
            ))}
        </div>
        {!canSend && !sending && <p className="text-xs text-muted-foreground md:col-span-2">{t.ai.sendBlocked}</p>}
        {!canSave && !savingConfig && <p className="text-xs text-muted-foreground md:col-span-2">{t.ai.saveBlocked}</p>}
        {sendError && <p className="text-sm text-destructive md:col-span-2">{sendError}</p>}
        {configError && <p className="text-sm text-destructive md:col-span-2">{configError}</p>}
        {configNotice && <p className="text-sm text-muted-foreground md:col-span-2">{configNotice}</p>}
      </div>

      {result && (
        <div className="space-y-3 rounded-lg border bg-card p-4">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="font-semibold">{t.ai.resultHeading}</h2>
            <span
              className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                result.outcome === "answered" ? "bg-primary/10 text-primary" : "bg-destructive/10 text-destructive"
              }`}
            >
              {t.ai.outcome[result.outcome]}
            </span>
          </div>
          {result.outcome === "budget_exhausted_thinking" && (
            <p className="text-sm text-muted-foreground">{t.ai.budgetExhaustedHelp}</p>
          )}
          {result.error && (
            <p className="text-sm text-destructive">
              {result.error.kind}
              {result.error.status ? ` (${result.error.status})` : ""}: {result.error.message}
            </p>
          )}
          {result.content && <pre className="whitespace-pre-wrap font-sans text-sm">{result.content}</pre>}
          {result.reasoning && (
            <details className="text-sm">
              <summary className="cursor-pointer text-muted-foreground">{t.ai.reasoning}</summary>
              <pre className="mt-2 whitespace-pre-wrap font-sans text-xs text-muted-foreground">{result.reasoning}</pre>
            </details>
          )}
          <p className="text-xs text-muted-foreground">
            {t.ai.destination}: {result.destination}
            {result.model ? ` · ${t.ai.model}: ${result.model}` : ""}
            {` · ${t.ai.latency}: ${result.latencyMs} ms`}
            {result.completionTokens !== null ? ` · ${t.ai.tokens}: ${result.completionTokens}` : ""}
            {result.finishReason ? ` · ${t.ai.finish}: ${result.finishReason}` : ""}
          </p>
        </div>
      )}
    </section>
  );
}
