import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { createConnection, updateConnection } from "@/features/mdm/api";
import type { MdmConnection, MdmConnectionInput, MdmProviderType, PatchManagementProvider } from "@/features/mdm/types";

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

export function ConnectionForm({ connection, onSaved, onCancel }: ConnectionFormProps) {
  const [name, setName] = useState(connection?.name ?? "");
  const [provider, setProvider] = useState<MdmProviderType>(connection?.provider ?? "jamf");
  const [baseUrl, setBaseUrl] = useState(connection?.baseUrl ?? "");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [patchManagementProvider, setPatchManagementProvider] = useState<PatchManagementProvider>(
    connection?.patchManagementProvider ?? "none"
  );
  const [loonsecioLicenseKey, setLoonsecioLicenseKey] = useState("");
  const [loonsecioDataSharingEnabled, setLoonsecioDataSharingEnabled] = useState(
    connection?.loonsecioDataSharingEnabled ?? false
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    const input: Partial<MdmConnectionInput> = {
      name,
      provider,
      baseUrl,
      patchManagementProvider,
      loonsecioDataSharingEnabled
    };
    if (clientId) input.clientId = clientId;
    if (clientSecret) input.clientSecret = clientSecret;
    if (loonsecioLicenseKey) input.loonsecioLicenseKey = loonsecioLicenseKey;

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
            onChange={(e) => setProvider(e.target.value as MdmProviderType)}
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

        <label className="space-y-1 text-sm">
          <span className="font-medium">Client ID</span>
          <input className={inputClasses} value={clientId} onChange={(e) => setClientId(e.target.value)} />
        </label>

        <label className="space-y-1 text-sm">
          <span className="font-medium">
            Client secret
            {connection?.hasClientSecret && (
              <span className="ml-1 text-xs text-muted-foreground">(set — leave blank to keep)</span>
            )}
          </span>
          <input
            type="password"
            className={inputClasses}
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
          />
        </label>
      </div>

      <div className="space-y-2">
        <span className="text-sm font-medium">Patch management</span>
        <div className="flex gap-4">
          {(Object.keys(patchProviderLabels) as PatchManagementProvider[]).map((option) => (
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
