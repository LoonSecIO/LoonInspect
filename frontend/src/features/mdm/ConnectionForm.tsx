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

interface ConnectionFormProps {
  connection?: MdmConnection;
  onSaved: () => void;
  onCancel: () => void;
}

const providerOptions: MdmProviderType[] = ["jamf", "simplemdm", "addigy", "fleet", "nano"];

const patchProviderLabels: Record<PatchManagementProvider, string> = {
  none: "None",
  jamf: "Jamf",
  loonsecio: "LoonSecIO"
};

const inputClasses =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

type TestStatus = "idle" | "testing" | "success" | "failure";

function toCamel(key: string): string {
  return key.replace(/_([a-zA-Z0-9])/g, (_, c: string) => c.toUpperCase());
}

export function ConnectionForm({ connection, onSaved, onCancel }: ConnectionFormProps) {
  const [name, setName] = useState(connection?.name ?? "");
  const [provider, setProvider] = useState<MdmProviderType>(connection?.provider ?? "jamf");
  const [baseUrl, setBaseUrl] = useState(connection?.baseUrl ?? "");
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [patchManagementProvider, setPatchManagementProvider] = useState<PatchManagementProvider>(
    connection?.patchManagementProvider ?? "none"
  );
  const [loonsecioLicenseKey, setLoonsecioLicenseKey] = useState("");
  const [loonsecioDataSharingEnabled, setLoonsecioDataSharingEnabled] = useState(
    connection?.loonsecioDataSharingEnabled ?? false
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [userAgentOverride, setUserAgentOverride] = useState(connection?.userAgentOverride ?? "");
  const [capabilityDevices, setCapabilityDevices] = useState(connection?.capabilityDevices ?? true);
  const [capabilityUsers, setCapabilityUsers] = useState(connection?.capabilityUsers ?? false);
  const [capabilityWebhooks, setCapabilityWebhooks] = useState(connection?.capabilityWebhooks ?? false);
  const [capabilityJamfPro, setCapabilityJamfPro] = useState(connection?.capabilityJamfPro ?? false);

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
        setJsonParseError(`Didn't find any of this provider's fields (${credentialFields.map((f) => f.key).join(", ")}) in that JSON.`);
      }
    } catch {
      setJsonParseError("Couldn't parse JSON — check the format.");
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
      setTestMessage("Test request failed.");
    }
  }

  const canTest =
    provider === "jamf" &&
    Boolean(baseUrl) &&
    Boolean(credentials.clientId) &&
    (Boolean(credentials.clientSecret) || connection?.credentialFieldsSet.includes("clientSecret"));

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    const filledCredentials = Object.fromEntries(
      Object.entries(credentials).filter(([, value]) => value)
    );

    const input: Partial<MdmConnectionInput> = {
      name,
      provider,
      baseUrl,
      patchManagementProvider,
      loonsecioDataSharingEnabled,
      capabilityDevices,
      capabilityUsers,
      capabilityWebhooks,
      capabilityJamfPro
    };
    if (Object.keys(filledCredentials).length > 0) input.credentials = filledCredentials;
    if (loonsecioLicenseKey) input.loonsecioLicenseKey = loonsecioLicenseKey;
    if (userAgentOverride) input.userAgentOverride = userAgentOverride;

    try {
      if (connection) {
        await updateConnection(connection.id, input);
      } else {
        await createConnection(input as MdmConnectionInput);
      }
      onSaved();
    } catch {
      setError("Failed to save connection. Check the values and try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-6">
      <div className="grid grid-cols-2 gap-4">
        <label className="space-y-1 text-sm">
          <span className="font-medium">Name</span>
          <input className={inputClasses} value={name} onChange={(e) => setName(e.target.value)} required />
        </label>

        <label className="space-y-1 text-sm">
          <span className="font-medium">Provider</span>
          <select
            className={inputClasses}
            value={provider}
            onChange={(e) => {
              const next = e.target.value as MdmProviderType;
              setProvider(next);
              setCredentials({});
              if (next !== "jamf") {
                setPatchManagementProvider((current) => (current === "jamf" ? "none" : current));
                setCapabilityJamfPro(false);
                setUserAgentOverride("");
              }
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
          <span className="font-medium">Base URL</span>
          <input
            className={inputClasses}
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://your-org.jamfcloud.com"
            required
          />
        </label>
      </div>

      <div className="space-y-2 rounded-md border p-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">Credentials</span>
          <button
            type="button"
            className="text-xs font-medium text-primary underline-offset-2 hover:underline"
            onClick={() => setCredentialsJsonMode((current) => !current)}
          >
            {credentialsJsonMode ? "Enter fields manually" : "Paste JSON instead"}
          </button>
        </div>

        {credentialsJsonMode ? (
          <div className="space-y-1">
            <textarea
              className={`${inputClasses} h-24 font-mono text-xs`}
              placeholder='{"client_id": "...", "client_secret": "...", ...}'
              value={credentialsJson}
              onChange={(e) => handleCredentialsJsonChange(e.target.value)}
            />
            {jsonParseError && <p className="text-xs text-destructive">{jsonParseError}</p>}
            {!jsonParseError && Object.keys(credentials).length > 0 && (
              <p className="text-xs text-muted-foreground">Parsed fields from JSON.</p>
            )}
          </div>
        ) : credentialFields.length === 0 ? (
          <p className="text-xs text-muted-foreground">Loading fields for this provider...</p>
        ) : (
          <div className="grid grid-cols-2 gap-4">
            {credentialFields.map((field) => (
              <label key={field.key} className="space-y-1 text-sm">
                <span className="font-medium">
                  {field.label}
                  {connection?.credentialFieldsSet.includes(field.key) && (
                    <span className="ml-1 text-xs text-muted-foreground">(set — leave blank to keep)</span>
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
                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Testing...
              </>
            ) : (
              "Test connection"
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
              title="View the raw response from Jamf"
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

        {provider !== "jamf" && (
          <p className="text-xs text-muted-foreground">Testing is currently only supported for Jamf connections.</p>
        )}
      </div>

      <div className="space-y-2">
        <span className="text-sm font-medium">Patch management</span>
        <div className="flex gap-4">
          {(Object.keys(patchProviderLabels) as PatchManagementProvider[])
            .filter((option) => option !== "jamf" || provider === "jamf")
            .map((option) => (
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
        </div>
        {provider !== "jamf" && (
          <p className="text-xs text-muted-foreground">
            Jamf patch management is only available for Jamf connections.
          </p>
        )}

        {patchManagementProvider === "loonsecio" && (
          <div className="space-y-2 rounded-md border border-dashed p-3">
            <label className="space-y-1 text-sm">
              <span className="font-medium">
                LoonSecIO license key
                {connection?.hasLoonsecioLicenseKey && (
                  <span className="ml-1 text-xs text-muted-foreground">(set — leave blank to keep)</span>
                )}
              </span>
              <input
                type="password"
                className={inputClasses}
                value={loonsecioLicenseKey}
                onChange={(e) => setLoonsecioLicenseKey(e.target.value)}
              />
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={loonsecioDataSharingEnabled}
                onChange={(e) => setLoonsecioDataSharingEnabled(e.target.checked)}
              />
              Enable data sharing
            </label>
            <p className="text-xs text-muted-foreground">
              LoonSecIO requires a license key and/or data sharing enabled.
            </p>
          </div>
        )}
      </div>

      <div className="space-y-2">
        <button
          type="button"
          className="text-xs font-medium text-primary underline-offset-2 hover:underline"
          onClick={() => setShowAdvanced((current) => !current)}
        >
          {showAdvanced ? "Hide advanced settings" : "Advanced settings"}
        </button>

        {showAdvanced && (
          <div className="space-y-4 rounded-md border p-3">
            {provider === "jamf" && (
              <label className="space-y-1 text-sm">
                <span className="font-medium">User-Agent override</span>
                <input
                  className={inputClasses}
                  value={userAgentOverride}
                  onChange={(e) => setUserAgentOverride(e.target.value)}
                  placeholder="LoonSecIO (default)"
                />
                <p className="text-xs text-muted-foreground">
                  Sent as the product name in the User-Agent header on every request to Jamf Pro
                  (e.g. "LoonSecIO/0.1.0 auth"). Leave blank to use the instance default.
                </p>
              </label>
            )}

            <div className="space-y-2">
              <span className="text-sm font-medium">What this connection is used for</span>
              <div className="grid grid-cols-2 gap-2">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={capabilityDevices}
                    onChange={(e) => setCapabilityDevices(e.target.checked)}
                  />
                  Devices <span className="text-xs text-muted-foreground">(CRUD)</span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={capabilityUsers}
                    onChange={(e) => setCapabilityUsers(e.target.checked)}
                  />
                  Users <span className="text-xs text-muted-foreground">(CRUD)</span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={capabilityWebhooks}
                    onChange={(e) => setCapabilityWebhooks(e.target.checked)}
                  />
                  Callback webhooks <span className="text-xs text-muted-foreground">(read)</span>
                </label>
                {provider === "jamf" && (
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={capabilityJamfPro}
                      onChange={(e) => setCapabilityJamfPro(e.target.checked)}
                    />
                    Jamf Pro <span className="text-xs text-muted-foreground">(read)</span>
                  </label>
                )}
              </div>
            </div>

            {connection && (
              <div className="space-y-1 text-xs text-muted-foreground">
                <p>
                  Last successful authentication:{" "}
                  {connection.lastSuccessfulAuthAt
                    ? new Date(connection.lastSuccessfulAuthAt).toLocaleString()
                    : "Never"}
                </p>
                <p>
                  Credentials last rotated:{" "}
                  {connection.credentialsRotatedAt
                    ? new Date(connection.credentialsRotatedAt).toLocaleString()
                    : "Never"}
                  {connection.credentialsFingerprint && ` (starts with "${connection.credentialsFingerprint}")`}
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <div className="flex gap-2">
        <Button type="submit" disabled={submitting}>
          {connection ? "Save changes" : "Add connection"}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
