import { useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/config/api";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { createDestination, deleteDestination, listDestinations, updateDestination } from "@/features/destinations/api";
import type { AuthType, Destination, DestinationType } from "@/features/destinations/types";
import { useLocale } from "@/i18n/LocaleContext";

type FormMode = "closed" | "create" | number;

interface FormState {
  name: string;
  type: DestinationType;
  url: string;
  authType: AuthType;
  authHeaderName: string;
  authSecret: string;
  enabled: boolean;
}

const EMPTY_FORM: FormState = {
  name: "",
  type: "generic_webhook",
  url: "",
  authType: "none",
  authHeaderName: "",
  authSecret: "",
  enabled: true
};

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export function DestinationsPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.DESTINATION_WRITE);

  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [formMode, setFormMode] = useState<FormMode>("closed");
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [pendingDeleteId, setPendingDeleteId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  async function refresh() {
    setLoading(true);
    try {
      setDestinations(await listDestinations());
    } catch {
      setError(t.destinations.errorLoading);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  function openCreate() {
    setForm(EMPTY_FORM);
    setFormMode("create");
  }

  function openEdit(destination: Destination) {
    setForm({
      name: destination.name,
      type: destination.type,
      url: destination.url,
      // Splunk HEC's auth convention is fixed; editing a generic webhook's auth type
      // is the only case this selector matters for. See the type-change handler below.
      authType: destination.type === "splunk_hec" ? "splunk_hec" : destination.authType,
      authHeaderName: destination.authHeaderName ?? "",
      authSecret: "",
      enabled: destination.enabled
    });
    setFormMode(destination.id);
  }

  function handleTypeChange(type: DestinationType) {
    setForm((current) => ({
      ...current,
      type,
      // Splunk HEC always authenticates the same way — exposing a separate selector
      // for it would just be a way to misconfigure it.
      authType: type === "splunk_hec" ? "splunk_hec" : current.authType === "splunk_hec" ? "none" : current.authType
    }));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const payload = {
        name: form.name,
        type: form.type,
        url: form.url,
        authType: form.authType,
        authHeaderName: form.authType === "header" ? form.authHeaderName : null,
        authSecret: form.authSecret || undefined,
        enabled: form.enabled
      };

      if (formMode === "create") {
        await createDestination(payload);
      } else if (typeof formMode === "number") {
        await updateDestination(formMode, payload);
      }

      setFormMode("closed");
      await refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.detail
          ? caught.detail
          : formMode === "create"
            ? t.destinations.errorCreating
            : t.destinations.errorUpdating
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function handleToggleEnabled(destination: Destination) {
    setBusyId(destination.id);
    setError(null);
    try {
      await updateDestination(destination.id, { enabled: !destination.enabled });
      await refresh();
    } catch {
      setError(t.destinations.errorUpdating);
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(id: number) {
    setBusyId(id);
    setError(null);
    try {
      await deleteDestination(id);
      setPendingDeleteId(null);
      await refresh();
    } catch {
      setError(t.destinations.errorDeleting);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
          <h1 className="text-3xl font-bold tracking-tight">{t.destinations.title}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t.destinations.description}</p>
        </div>
        {canWrite && formMode === "closed" && <Button onClick={openCreate}>{t.destinations.add}</Button>}
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      {canWrite && formMode !== "closed" && (
        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <label htmlFor="destName" className="text-sm font-medium">
                {t.destinations.name}
              </label>
              <Input
                id="destName"
                required
                value={form.name}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="destType" className="text-sm font-medium">
                {t.destinations.type}
              </label>
              <select
                id="destType"
                value={form.type}
                onChange={(event) => handleTypeChange(event.target.value as DestinationType)}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="generic_webhook">{t.destinations.typeGenericWebhook}</option>
                <option value="splunk_hec">{t.destinations.typeSplunkHec}</option>
              </select>
            </div>
          </div>

          <div className="space-y-2">
            <label htmlFor="destUrl" className="text-sm font-medium">
              {t.destinations.url}
            </label>
            <Input
              id="destUrl"
              type="url"
              required
              placeholder="https://…"
              value={form.url}
              onChange={(event) => setForm((current) => ({ ...current, url: event.target.value }))}
            />
          </div>

          {form.type === "generic_webhook" && (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <label htmlFor="destAuthType" className="text-sm font-medium">
                  {t.destinations.authType}
                </label>
                <select
                  id="destAuthType"
                  value={form.authType}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, authType: event.target.value as AuthType }))
                  }
                  className="flex h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="none">{t.destinations.authNone}</option>
                  <option value="bearer">{t.destinations.authBearer}</option>
                  <option value="header">{t.destinations.authHeader}</option>
                </select>
              </div>
              {form.authType === "header" && (
                <div className="space-y-2">
                  <label htmlFor="destAuthHeaderName" className="text-sm font-medium">
                    {t.destinations.authHeaderName}
                  </label>
                  <Input
                    id="destAuthHeaderName"
                    required
                    placeholder="X-Api-Key"
                    value={form.authHeaderName}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, authHeaderName: event.target.value }))
                    }
                  />
                </div>
              )}
            </div>
          )}

          {form.authType !== "none" && (
            <div className="space-y-2">
              <label htmlFor="destAuthSecret" className="text-sm font-medium">
                {formMode === "create" ? t.destinations.authSecret : t.destinations.authSecretRotate}
              </label>
              <Input
                id="destAuthSecret"
                type="password"
                autoComplete="off"
                required={formMode === "create"}
                placeholder={formMode === "create" ? undefined : t.destinations.authSecretPlaceholder}
                value={form.authSecret}
                onChange={(event) => setForm((current) => ({ ...current, authSecret: event.target.value }))}
              />
            </div>
          )}

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))}
            />
            {t.destinations.enabled}
          </label>

          <div className="flex gap-2">
            <Button type="submit" disabled={submitting}>
              {submitting ? t.destinations.saving : t.destinations.save}
            </Button>
            <Button type="button" variant="outline" onClick={() => setFormMode("closed")}>
              {t.destinations.cancel}
            </Button>
          </div>
        </form>
      )}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.destinations.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.destinations.tableType}</th>
              <th className="px-4 py-2 font-medium">{t.destinations.tableUrl}</th>
              <th className="px-4 py-2 font-medium">{t.destinations.tableStatus}</th>
              <th className="px-4 py-2 font-medium">{t.destinations.tableLastActivity}</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.destinations.loading}
                </td>
              </tr>
            )}
            {!loading && destinations.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.destinations.empty}
                </td>
              </tr>
            )}
            {destinations.map((destination) => (
              <tr key={destination.id} className="border-b align-top last:border-0">
                <td className="px-4 py-3 font-medium">{destination.name}</td>
                <td className="px-4 py-3">
                  {destination.type === "splunk_hec" ? t.destinations.typeSplunkHec : t.destinations.typeGenericWebhook}
                </td>
                <td className="max-w-xs truncate px-4 py-3 font-mono text-xs text-muted-foreground" title={destination.url}>
                  {destination.url}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={
                      destination.enabled
                        ? "rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-600 dark:text-emerald-400"
                        : "rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground"
                    }
                  >
                    {destination.enabled ? t.destinations.enabledLabel : t.destinations.disabledLabel}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs">
                  {destination.lastFailureAt &&
                  (!destination.lastSuccessAt || destination.lastFailureAt > destination.lastSuccessAt) ? (
                    <span className="text-destructive">{t.destinations.lastFailed(formatDate(destination.lastFailureAt))}</span>
                  ) : destination.lastSuccessAt ? (
                    <span className="text-muted-foreground">{formatDate(destination.lastSuccessAt)}</span>
                  ) : (
                    <span className="text-muted-foreground">{t.destinations.neverDelivered}</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {canWrite && (
                    <div className="flex flex-col items-end gap-2">
                      {pendingDeleteId === destination.id ? (
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">{t.destinations.deleteConfirm}</span>
                          <Button
                            variant="destructive"
                            size="sm"
                            disabled={busyId === destination.id}
                            onClick={() => handleDelete(destination.id)}
                          >
                            {t.destinations.confirm}
                          </Button>
                          <Button variant="outline" size="sm" onClick={() => setPendingDeleteId(null)}>
                            {t.destinations.cancel}
                          </Button>
                        </div>
                      ) : (
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={busyId === destination.id}
                            onClick={() => handleToggleEnabled(destination)}
                          >
                            {destination.enabled ? t.destinations.disable : t.destinations.enable}
                          </Button>
                          <Button variant="outline" size="sm" onClick={() => openEdit(destination)}>
                            {t.destinations.edit}
                          </Button>
                          <Button variant="destructive" size="sm" onClick={() => setPendingDeleteId(destination.id)}>
                            {t.destinations.delete}
                          </Button>
                        </div>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
