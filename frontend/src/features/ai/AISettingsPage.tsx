import { useEffect, useState } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PERMISSIONS } from "@/features/auth/types";
import { useHasPermission } from "@/features/auth/store";
import { listFeatureFlags } from "@/features/settings/api";
import { getDataSharing, updateDataSharing } from "@/features/system/api";
import {
  getHostDetection,
  getProviders,
  sendTest,
  type HostDetection,
  type Provider,
  type ProvidersResponse,
  type TestResponse
} from "@/features/ai/api";
import { ApiError } from "@/config/api";
import { useLocale } from "@/i18n/LocaleContext";

const AI_FLAG = "ai_features";
const PROVIDER_ORDER: Provider[] = ["apple_fm", "openai_compatible", "anthropic"];

/**
 * Settings › AI: the test box (#319). One prompt to an endpoint the admin names,
 * the reply shown as it came back. Three cards, one per entry; the Apple card is
 * "via Docker Desktop" because the label names the pattern the operator is on, not
 * what powers the model. Every model call is made by the backend, never from here.
 */
export function AISettingsPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.SYSTEM_WRITE);

  const [flagOn, setFlagOn] = useState<boolean | null>(null);
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
  const [sendError, setSendError] = useState<string | null>(null);
  const [consentError, setConsentError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([listFeatureFlags(), getDataSharing(), getProviders(), getHostDetection()])
      .then(([flags, sharing, loadedProviders, loadedDetection]) => {
        if (cancelled) return;
        setFlagOn(flags.some((f) => f.key === AI_FLAG && f.enabled));
        setConsent(sharing.aiInference);
        setProviders(loadedProviders);
        setDetection(loadedDetection);
        // The hint, never a gate: a full match pre-selects the Apple card; anything
        // else starts on the documented default (Ollama, #28) and says what it saw.
        const initial: Provider = loadedDetection.dockerDesktopOnMacos ? "apple_fm" : "openai_compatible";
        applyDefaults(loadedProviders, initial);
      })
      .catch(() => {
        if (!cancelled) setLoadError(t.ai.loadFailed);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function applyDefaults(loaded: ProvidersResponse, next: Provider) {
    const entry = loaded.entries.find((e) => e.provider === next);
    if (!entry) return;
    setProvider(next);
    setBaseUrl(entry.baseUrl);
    setModel(entry.model);
    setApiKey("");
    setReasoningEffort(entry.reasoningEffort ?? "");
    setResult(null);
    setSendError(null);
  }

  async function toggleConsent() {
    if (consent === null) return;
    setConsentError(null);
    try {
      const updated = await updateDataSharing({ aiInference: !consent });
      setConsent(updated.aiInference);
    } catch {
      setConsentError(t.ai.saveFailed);
    }
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
        reasoningEffort: reasoningEffort ? reasoningEffort : null
      });
      setResult(response);
    } catch (error) {
      setSendError(error instanceof ApiError && error.detail ? error.detail : t.ai.sendFailed);
    } finally {
      setSending(false);
    }
  }

  const entry = providers?.entries.find((e) => e.provider === provider);
  const canSend = canWrite && flagOn === true && consent === true && !sending && baseUrl.trim() !== "" && model.trim() !== "" && prompt.trim() !== "";

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
            {flagOn === null ? "…" : flagOn ? t.ai.on : t.ai.off}
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
        <div className="grid gap-3 md:grid-cols-3">
          {PROVIDER_ORDER.map((candidate) => (
            <label
              key={candidate}
              className={`flex cursor-pointer flex-col gap-1 rounded-lg border p-4 ${
                provider === candidate ? "border-primary bg-primary/5" : "border-input"
              }`}
            >
              <input
                type="radio"
                name="ai-provider"
                className="sr-only"
                checked={provider === candidate}
                disabled={!providers}
                onChange={() => providers && applyDefaults(providers, candidate)}
              />
              <span className="text-sm font-medium">{t.ai.providerLabels[candidate]}</span>
              <span className="text-xs text-muted-foreground">{t.ai.providerHelp[candidate]}</span>
            </label>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">{t.ai.otherRuntimes}</p>
      </div>

      <div className="grid gap-4 rounded-lg border bg-card p-4 md:grid-cols-2">
        <label className="space-y-1 text-sm">
          <span className="font-medium">{t.ai.baseUrl}</span>
          <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} spellCheck={false} />
        </label>
        <label className="space-y-1 text-sm">
          <span className="font-medium">{t.ai.model}</span>
          <Input value={model} onChange={(e) => setModel(e.target.value)} list="ai-models" spellCheck={false} />
          <datalist id="ai-models">
            {entry?.models.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        </label>
        {entry && entry.key !== "none" && (
          <label className="space-y-1 text-sm">
            <span className="font-medium">
              {t.ai.apiKey} ({entry.key === "required" ? t.ai.apiKeyRequired : t.ai.apiKeyOptional})
            </span>
            <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off" />
          </label>
        )}
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
        <label className="space-y-1 text-sm md:col-span-2">
          <span className="font-medium">{t.ai.prompt}</span>
          <textarea
            className="flex min-h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            maxLength={4000}
          />
        </label>
        <div className="flex items-center gap-3 md:col-span-2">
          <Button disabled={!canSend} onClick={() => void handleSend()}>
            {sending ? t.ai.sending : t.ai.send}
          </Button>
          {!canSend && !sending && <p className="text-xs text-muted-foreground">{t.ai.sendBlocked}</p>}
        </div>
        {sendError && <p className="text-sm text-destructive md:col-span-2">{sendError}</p>}
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
