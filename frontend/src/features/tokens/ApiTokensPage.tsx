import { useEffect, useState, type FormEvent } from "react";
import { Check, Copy, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuthStore } from "@/features/auth/store";
import { createToken, listTokens, revokeToken } from "@/features/tokens/api";
import type { ApiToken, ApiTokenCreated } from "@/features/tokens/types";
import { useLocale } from "@/i18n/LocaleContext";

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export function ApiTokensPage() {
  const { t } = useLocale();
  const ownPermissions = useAuthStore((state) => state.user?.permissions ?? []);

  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [expiresInDays, setExpiresInDays] = useState("");
  const [scopes, setScopes] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  async function refresh() {
    setLoading(true);
    try {
      setTokens(await listTokens());
    } catch {
      setError(t.apiTokens.errorLoading);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function toggleScope(permission: string) {
    setScopes((current) =>
      current.includes(permission)
        ? current.filter((value) => value !== permission)
        : [...current, permission]
    );
  }

  async function handleCreate(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const token = await createToken({
        name,
        scopes,
        expiresInDays: expiresInDays ? Number(expiresInDays) : null
      });
      setCreated(token);
      setName("");
      setExpiresInDays("");
      setScopes([]);
      await refresh();
    } catch {
      setError(t.apiTokens.errorCreating);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRevoke(id: string) {
    setRevokingId(id);
    setError(null);
    try {
      await revokeToken(id);
      await refresh();
    } catch {
      setError(t.apiTokens.errorRevoking);
    } finally {
      setRevokingId(null);
    }
  }

  async function handleCopy() {
    if (!created) return;
    await navigator.clipboard.writeText(created.token);
    setCopied(true);
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.apiTokens.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.apiTokens.description}</p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {created && (
        <div className="space-y-3 rounded-lg border border-primary/40 bg-primary/5 p-4">
          <div className="flex items-center gap-2 text-sm font-medium">
            <KeyRound className="h-4 w-4 text-primary" />
            {t.apiTokens.createdTitle}
          </div>
          <p className="text-sm text-muted-foreground">{t.apiTokens.createdWarning}</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs">
              {created.token}
            </code>
            <Button variant="outline" size="sm" onClick={handleCopy}>
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              <span className="ml-2">{copied ? t.apiTokens.copied : t.apiTokens.copy}</span>
            </Button>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setCreated(null);
              setCopied(false);
            }}
          >
            {t.apiTokens.dismiss}
          </Button>
        </div>
      )}

      <form onSubmit={handleCreate} className="space-y-4 rounded-lg border bg-card p-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <label htmlFor="tokenName" className="text-sm font-medium">
              {t.apiTokens.name}
            </label>
            <Input
              id="tokenName"
              required
              maxLength={255}
              placeholder={t.apiTokens.namePlaceholder}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="tokenExpiry" className="text-sm font-medium">
              {t.apiTokens.expiry}
            </label>
            <Input
              id="tokenExpiry"
              type="number"
              min={1}
              max={365}
              placeholder={t.apiTokens.expiryPlaceholder}
              value={expiresInDays}
              onChange={(event) => setExpiresInDays(event.target.value)}
            />
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-sm font-medium">{t.apiTokens.scopes}</p>
          <p className="text-xs text-muted-foreground">{t.apiTokens.scopesHint}</p>
          <div className="flex flex-wrap gap-2">
            {ownPermissions.map((permission) => {
              const selected = scopes.includes(permission);
              return (
                <button
                  key={permission}
                  type="button"
                  onClick={() => toggleScope(permission)}
                  className={
                    selected
                      ? "rounded-md border border-primary bg-primary/10 px-2 py-1 font-mono text-xs"
                      : "rounded-md border border-input px-2 py-1 font-mono text-xs text-muted-foreground hover:bg-accent"
                  }
                >
                  {permission}
                </button>
              );
            })}
          </div>
        </div>

        <Button type="submit" disabled={submitting}>
          {submitting ? t.apiTokens.creating : t.apiTokens.create}
        </Button>
      </form>

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.apiTokens.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.apiTokens.tableScopes}</th>
              <th className="px-4 py-2 font-medium">{t.apiTokens.tableCreated}</th>
              <th className="px-4 py-2 font-medium">{t.apiTokens.tableExpires}</th>
              <th className="px-4 py-2 font-medium">{t.apiTokens.tableLastUsed}</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.apiTokens.loading}
                </td>
              </tr>
            )}
            {!loading && tokens.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={6}>
                  {t.apiTokens.empty}
                </td>
              </tr>
            )}
            {tokens.map((token) => (
              <tr key={token.id} className="border-b last:border-0">
                <td className="px-4 py-2 font-medium">{token.name}</td>
                <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                  {token.scopes.length > 0 ? token.scopes.join(", ") : t.apiTokens.inheritAll}
                </td>
                <td className="px-4 py-2">{formatDate(token.createdAt)}</td>
                <td className="px-4 py-2">
                  {token.expiresAt ? formatDate(token.expiresAt) : t.apiTokens.never}
                </td>
                <td className="px-4 py-2">{formatDate(token.lastUsedAt)}</td>
                <td className="px-4 py-2 text-right">
                  <Button
                    variant="destructive"
                    size="sm"
                    disabled={revokingId === token.id}
                    onClick={() => handleRevoke(token.id)}
                  >
                    {revokingId === token.id ? t.apiTokens.revoking : t.apiTokens.revoke}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
