import { useEffect, useState, type FormEvent } from "react";
import { CheckCircle2, Info, Loader2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { createConnection, getProviders, testConnection, updateConnection } from "@/features/mdm/api";
import type {
  MdmConnection,
  MdmConnectionInput,
  MdmProviderType,
  PatchManagementProvider,
  ProviderCredentialField,
  ProviderInfo
} from "@/features/mdm/types";
import { useLocale } from "@/i18n/LocaleContext";

interface ConnectionFormProps {
  connection?: MdmConnection;
  onSaved: () => void;
  onCancel: () => void;
}

const providerOptions: MdmProviderType[] = ["jamf"];

const inputClasses =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

type TestStatus = "idle" | "testing" | "success" | "failure";

function toCamel(key: string): string {
  return key.replace(/_([a-zA-Z0-9])/g, (_, c: string) => c.toUpperCase());
}

/** Mirrors `_same_base_url` in api/connections.py: only the trailing slash is erased,
 *  because that is the one difference the Jamf client itself erases. Kept as narrow as
 *  the server's rule on purpose — a looser comparison here would let the form promise a
 *  save the server then refuses. */
function sameBaseUrl(supplied: string, stored: string): boolean {
  return supplied.trim().replace(/\/+$/, "") === stored.trim().replace(/\/+$/, "");
}

export function ConnectionForm({ connection, onSaved, onCancel }: ConnectionFormProps) {
  const { t } = useLocale();
  const patchProviderLabels = t.connectionForm.patchProviderLabels;

  const [name, setName] = useState(connection?.name ?? "");
  const [provider, setProvider] = useState<MdmProviderType>(connection?.provider ?? "jamf");
  const [baseUrl, setBaseUrl] = useState(connection?.baseUrl ?? "");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [patchManagementProvider, setPatchManagementProvider] = useState<PatchManagementProvider>(
    connection?.patchManagementProvider ?? "none"
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [userAgentOverride, setUserAgentOverride] = useState(connection?.userAgentOverride ?? "");
  const [sweepPageSize, setSweepPageSize] = useState<number>(connection?.sweepPageSize ?? 400);
  const [capabilityDevices, setCapabilityDevices] = useState(connection?.capabilityDevices ?? true);
  const [capabilityUsers, setCapabilityUsers] = useState(connection?.capabilityUsers ?? false);
  const [capabilityWebhooks, setCapabilityWebhooks] = useState(connection?.capabilityWebhooks ?? false);
  const [capabilityJamfPro, setCapabilityJamfPro] = useState(connection?.capabilityJamfPro ?? false);
  // Never seeded from `connection`: the server sends `hasWebhookSecret`, never the
  // value. Blank on an edit means "keep what is stored", the same contract the
  // credential fields above and the destination form's secret both use.
  const [webhookSecret, setWebhookSecret] = useState("");

  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [credentialsJsonMode, setCredentialsJsonMode] = useState(false);
  const [credentialsJson, setCredentialsJson] = useState("");
  const [jsonParseError, setJsonParseError] = useState<string | null>(null);

  const [testStatus, setTestStatus] = useState<TestStatus>("idle");
  const [testMessage, setTestMessage] = useState<string | null>(null);
  const [testDetail, setTestDetail] = useState<string | null>(null);
  const [showTestDetail, setShowTestDetail] = useState(false);

  useEffect(() => {
    getProviders().then(setProviders);
  }, []);

  const credentialFields: ProviderCredentialField[] =
    providers.find((p) => p.provider === provider)?.credentialFields ?? [];

  function setCredentialField(key: string, value: string) {
    setCredentials((current) => ({ ...current, [key]: value }));
  }

  function handleCredentialsJsonChange(value: string) {
    setCredentialsJson(value);
    setJsonParseError(null);

    if (!value.trim()) return;

    try {
      const parsed = JSON.parse(value);
      let matchedAny = false;

      for (const [rawKey, rawValue] of Object.entries(parsed)) {
        if (typeof rawValue !== "string") continue;
        const camelKey = toCamel(rawKey);
        const field = credentialFields.find((f) => f.key === camelKey || f.key === rawKey);
        if (field) {
          setCredentialField(field.key, rawValue);
          matchedAny = true;
        }
      }

      if (typeof parsed.client_name === "string" && !name) setName(parsed.client_name);
      if (!matchedAny) {
        setJsonParseError(t.connectionForm.jsonNoMatch(credentialFields.map((f) => f.key).join(", ")));
      }
    } catch {
      setJsonParseError(t.connectionForm.jsonParseError);
    }
  }

  async function handleTest() {
    setTestStatus("testing");
    setTestMessage(null);
    setTestDetail(null);
    setShowTestDetail(false);

    try {
      const result = await testConnection({
        connectionId: connection?.id,
        provider,
        baseUrl,
        clientId: credentials.clientId ?? "",
        clientSecret: credentials.clientSecret || undefined,
        userAgentOverride: userAgentOverride || undefined
      });
      setTestStatus(result.success ? "success" : "failure");
      setTestMessage(result.message);
      setTestDetail(result.detail ?? null);
    } catch {
      setTestStatus("failure");
      setTestMessage(t.connectionForm.testRequestFailed);
    }
  }

  const canTest =
    Boolean(baseUrl) &&
    Boolean(credentials.clientId) &&
    (Boolean(credentials.clientSecret) || connection?.credentialFieldsSet.includes("clientSecret"));

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    // Webhook auth fails closed (api/webhooks.py): a connection with the capability on
    // and no secret answers every Jamf callback with 401, which reads as Jamf being
    // broken rather than as a half-filled form. The input's `required` attribute cannot
    // carry this alone — the capability checkboxes live inside the collapsible advanced
    // panel, so ticking the box, collapsing the panel and submitting leaves no such
    // input in the DOM for the browser to validate.
    if (capabilityWebhooks && !webhookSecret && !connection?.hasWebhookSecret) {
      setShowAdvanced(true);
      setError(t.connectionForm.webhookSecretRequired);
      return;
    }

    // The server refuses a URL change that would reuse the stored secret
    // (api/connections.py): moving a connection retargets a credential nothing can read
    // back, so whoever moves it has to prove they hold it. Repeated here because the
    // save path renders one generic message — a 422 the operator can't read leaves them
    // guessing at which field went wrong, and the honest answer is a specific one.
    const unproven =
      connection && !sameBaseUrl(baseUrl, connection.baseUrl)
        ? credentialFields.filter(
            (field) =>
              field.secret && connection.credentialFieldsSet.includes(field.key) && !credentials[field.key]
          )
        : [];
    if (unproven.length > 0) {
      setError(t.connectionForm.baseUrlChangeNeedsSecret(unproven.map((field) => field.label).join(", ")));
      return;
    }

    setSubmitting(true);

    const filledCredentials = Object.fromEntries(
      Object.entries(credentials).filter(([, value]) => value)
    );

    const input: Partial<MdmConnectionInput> = {
      name,
      provider,
      baseUrl,
      patchManagementProvider,
      capabilityDevices,
      capabilityUsers,
      capabilityWebhooks,
      capabilityJamfPro
    };
    if (Object.keys(filledCredentials).length > 0) input.credentials = filledCredentials;
    // Omitted rather than sent blank: the backend applies `webhook_secret` whenever the
    // key is present, so sending "" on an edit would clear the stored secret and shut
    // the endpoint down without saying so.
    if (webhookSecret) input.webhookSecret = webhookSecret;
    if (userAgentOverride) input.userAgentOverride = userAgentOverride;
    // 400 is the default: stored as null so a connection that never deviated (or slid
    // back) keeps following the instance default if it ever moves.
    input.sweepPageSize = sweepPageSize === 400 ? null : sweepPageSize;

    try {
      if (connection) {
        await updateConnection(connection.id, input);
      } else {
        await createConnection(input as MdmConnectionInput);
      }
      onSaved();
    } catch {
      setError(t.connectionForm.saveError);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-6">
      <div className="grid grid-cols-2 gap-4">
        <label className="space-y-1 text-sm">
          <span className="font-medium">{t.connectionForm.name}</span>
          <input className={inputClasses} value={name} onChange={(e) => setName(e.target.value)} required />
        </label>

        <label className="space-y-1 text-sm">
          <span className="font-medium">{t.connectionForm.provider}</span>
          <select
            className={inputClasses}
            value={provider}
            onChange={(e) => {
              setProvider(e.target.value as MdmProviderType);
              setCredentials({});
            }}
          >
            {providerOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <label className="col-span-2 space-y-1 text-sm">
          <span className="font-medium">{t.connectionForm.baseUrl}</span>
          <input
            className={inputClasses}
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={t.connectionForm.baseUrlPlaceholder}
            required
          />
        </label>
      </div>

      <div className="space-y-2 rounded-md border p-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">{t.connectionForm.credentials}</span>
          <button
            type="button"
            className="text-xs font-medium text-primary underline-offset-2 hover:underline"
            onClick={() => setCredentialsJsonMode((current) => !current)}
          >
            {credentialsJsonMode ? t.connectionForm.enterManually : t.connectionForm.pasteJson}
          </button>
        </div>

        {credentialsJsonMode ? (
          <div className="space-y-1">
            <textarea
              className={`${inputClasses} h-24 font-mono text-xs`}
              placeholder={t.connectionForm.jsonPlaceholder}
              value={credentialsJson}
              onChange={(e) => handleCredentialsJsonChange(e.target.value)}
            />
            {jsonParseError && <p className="text-xs text-destructive">{jsonParseError}</p>}
            {!jsonParseError && Object.keys(credentials).length > 0 && (
              <p className="text-xs text-muted-foreground">{t.connectionForm.jsonParsedHint}</p>
            )}
          </div>
        ) : credentialFields.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t.connectionForm.loadingFields}</p>
        ) : (
          <div className="grid grid-cols-2 gap-4">
            {credentialFields.map((field) => (
              <label key={field.key} className="space-y-1 text-sm">
                <span className="font-medium">
                  {field.label}
                  {connection?.credentialFieldsSet.includes(field.key) && (
                    <span className="ml-1 text-xs text-muted-foreground">{t.connectionForm.setLeaveBlank}</span>
                  )}
                </span>
                <input
                  type={field.secret ? "password" : "text"}
                  className={inputClasses}
                  value={credentials[field.key] ?? ""}
                  onChange={(e) => setCredentialField(field.key, e.target.value)}
                />
              </label>
            ))}
          </div>
        )}

        <div className="flex items-center gap-3 pt-1">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={!canTest || testStatus === "testing"}
            onClick={handleTest}
          >
            {testStatus === "testing" ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> {t.connectionForm.testing}
              </>
            ) : (
              t.connectionForm.testConnection
            )}
          </Button>

          {testStatus === "success" && (
            <span className="flex items-center gap-1 text-sm text-green-600">
              <CheckCircle2 className="h-4 w-4" /> {testMessage}
            </span>
          )}
          {testStatus === "failure" && (
            <span className="flex items-center gap-1 text-sm text-destructive">
              <XCircle className="h-4 w-4" /> {testMessage}
            </span>
          )}

          {testDetail && (
            <button
              type="button"
              title={t.connectionForm.viewRawResponse}
              className="text-muted-foreground hover:text-foreground"
              onClick={() => setShowTestDetail((current) => !current)}
            >
              <Info className="h-4 w-4" />
            </button>
          )}
        </div>

        {showTestDetail && testDetail && (
          <pre className="max-h-48 overflow-auto rounded-md bg-muted p-2 text-xs">{testDetail}</pre>
        )}
      </div>

      <div className="space-y-2">
        <span className="text-sm font-medium">{t.connectionForm.patchManagement}</span>
        <div className="flex gap-4">
          {(["none", "jamf"] as PatchManagementProvider[]).map((option) => (
            <label key={option} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="patchManagementProvider"
                value={option}
                checked={patchManagementProvider === option}
                onChange={() => setPatchManagementProvider(option)}
              />
              {patchProviderLabels[option]}
            </label>
          ))}
          {/* Named but not selectable: the seam is visible, the service behind it is not
              live yet (#79). A stored value still shows as checked so an old row stays
              legible. */}
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <input
              type="radio"
              name="patchManagementProvider"
              value="loonsecio"
              checked={patchManagementProvider === "loonsecio"}
              disabled
            />
            {patchProviderLabels.loonsecio}
            <span className="text-xs">{t.connectionForm.loonsecioComingSoon}</span>
          </label>
        </div>
      </div>

      <div className="space-y-2">
        <button
          type="button"
          className="text-xs font-medium text-primary underline-offset-2 hover:underline"
          onClick={() => setShowAdvanced((current) => !current)}
        >
          {showAdvanced ? t.connectionForm.hideAdvancedSettings : t.connectionForm.advancedSettings}
        </button>

        {showAdvanced && (
          <div className="space-y-4 rounded-md border p-3">
            <label className="space-y-1 text-sm">
              <span className="font-medium">{t.connectionForm.userAgentOverride}</span>
              <input
                className={inputClasses}
                value={userAgentOverride}
                onChange={(e) => setUserAgentOverride(e.target.value)}
                placeholder={t.connectionForm.userAgentPlaceholder}
              />
              <p className="text-xs text-muted-foreground">{t.connectionForm.userAgentHint}</p>
            </label>

            <label className="space-y-1 text-sm">
              <span className="font-medium">
                {t.connectionForm.sweepPageSize}: {sweepPageSize}
                {sweepPageSize === 400 ? ` ${t.connectionForm.sweepPageSizeDefault}` : ""}
              </span>
              <input
                type="range"
                min={100}
                max={1000}
                step={50}
                className="w-full"
                value={sweepPageSize}
                onChange={(e) => setSweepPageSize(Number(e.target.value))}
              />
              <p className="text-xs text-muted-foreground">{t.connectionForm.sweepPageSizeHint}</p>
            </label>

            <div className="space-y-2">
              <span className="text-sm font-medium">{t.connectionForm.whatUsedFor}</span>
              <div className="grid grid-cols-2 gap-2">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={capabilityDevices}
                    onChange={(e) => setCapabilityDevices(e.target.checked)}
                  />
                  {t.connectionForm.capabilityDevices}{" "}
                  <span className="text-xs text-muted-foreground">{t.connectionForm.crud}</span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={capabilityUsers}
                    onChange={(e) => setCapabilityUsers(e.target.checked)}
                  />
                  {t.connectionForm.capabilityUsers}{" "}
                  <span className="text-xs text-muted-foreground">{t.connectionForm.crud}</span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={capabilityWebhooks}
                    onChange={(e) => setCapabilityWebhooks(e.target.checked)}
                  />
                  {t.connectionForm.capabilityWebhooks}{" "}
                  <span className="text-xs text-muted-foreground">{t.connectionForm.readOnly}</span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={capabilityJamfPro}
                    onChange={(e) => setCapabilityJamfPro(e.target.checked)}
                  />
                  {t.connectionForm.capabilityJamfPro}{" "}
                  <span className="text-xs text-muted-foreground">{t.connectionForm.readOnly}</span>
                </label>
              </div>

              {capabilityWebhooks && (
                <label className="space-y-1 text-sm">
                  <span className="font-medium">
                    {t.connectionForm.webhookSecret}
                    {connection?.hasWebhookSecret && (
                      <span className="ml-1 text-xs text-muted-foreground">{t.connectionForm.setLeaveBlank}</span>
                    )}
                  </span>
                  <input
                    type="password"
                    autoComplete="off"
                    className={inputClasses}
                    required={!connection?.hasWebhookSecret}
                    value={webhookSecret}
                    onChange={(e) => setWebhookSecret(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">{t.connectionForm.webhookSecretHint}</p>
                </label>
              )}
            </div>

            {connection && (
              <div className="space-y-1 text-xs text-muted-foreground">
                <p>
                  {t.connectionForm.lastSuccessfulAuth}{" "}
                  {connection.lastSuccessfulAuthAt
                    ? new Date(connection.lastSuccessfulAuthAt).toLocaleString()
                    : t.connectionForm.never}
                </p>
                <p>
                  {t.connectionForm.credentialsRotated}{" "}
                  {connection.credentialsRotatedAt
                    ? new Date(connection.credentialsRotatedAt).toLocaleString()
                    : t.connectionForm.never}
                  {connection.credentialsFingerprint &&
                    ` ${t.connectionForm.startsWithFingerprint(connection.credentialsFingerprint)}`}
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="flex gap-2">
        <Button type="submit" disabled={submitting}>
          {connection ? t.connectionForm.saveChanges : t.connectionForm.addConnectionButton}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t.connectionForm.cancel}
        </Button>
      </div>
    </form>
  );
}
