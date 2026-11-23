import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/config/api";
import { env } from "@/config/env";
import { useAuthStore } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { createToken, listTokens, revokeToken } from "@/features/tokens/api";
import type { ApiToken, ApiTokenCreated } from "@/features/tokens/types";
import { useLocale } from "@/i18n/LocaleContext";
import { getMcpSettings, testMcpConnection, updateMcpSettings, type McpSettings } from "./api";
import { clientConfiguration, grantedMcpScopes, pairingCommand, scopeGroups, type McpClient, type McpConnectionMode } from "./configuration";

/** Switching accounts or organizations clears tokens and pending UI state immediately. */
export function McpSettingsPage() {
  const user = useAuthStore(state => state.user);
  if (!user?.tenant) return null;
  return <OrganizationMcpSettings key={`${user.id}:${user.tenant.id}:${user.permissions.join(",")}`}
    userId={user.id} organizationId={user.tenant.id} permissions={user.permissions} />;
}

function OrganizationMcpSettings({ userId, organizationId, permissions }: {
  userId: string; organizationId: string; permissions: string[];
}) {
  const { t, locale } = useLocale();
  const copy = t.mcp;
  const [settings, setSettings] = useState<McpSettings | null>(null);
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const [reload, setReload] = useState(0);
  const [saving, setSaving] = useState(false);
  const [client, setClient] = useState<McpClient>("codex");
  const [mode, setMode] = useState<McpConnectionMode>("mac");
  const [name, setName] = useState("Codex");
  const [expiry, setExpiry] = useState("30");
  const [selected, setSelected] = useState<string[]>(["device:read", "app:read", "vuln:read"]);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [showToken, setShowToken] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [testToken, setTestToken] = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<number | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const [asked, setAsked] = useState({ organizationId, copy, reload });
  if (asked.organizationId !== organizationId || asked.copy !== copy || asked.reload !== reload) {
    setAsked({ organizationId, copy, reload });
    setLoading(true);
    setError(null);
    setSettings(null);
  }

  useEffect(() => {
    let live = true;
    Promise.all([getMcpSettings(organizationId), listTokens(organizationId)]).then(([answer, rows]) => {
      if (!live) return;
      if (answer.organizationId !== organizationId) {
        setStale(true);
        setError(copy.organizationChanged);
        return;
      }
      setSettings(answer);
      setTokens(rows.filter(token => token.scopes.includes("mcp:connect")));
    }).catch(reason => {
      if (!live) return;
      const changed = reason instanceof ApiError && reason.status === 409;
      setStale(changed);
      setError(changed ? copy.organizationChanged : copy.loadFailed);
    }).finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [organizationId, copy, reload]);

  function isCurrent() {
    const current = useAuthStore.getState().user;
    return current?.id === userId && current.tenant?.id === organizationId;
  }

  function fail(reason: unknown, fallback: string) {
    if (!isCurrent()) return;
    if (reason instanceof ApiError && reason.status === 409) {
      setStale(true);
      setCreated(null);
      setTestToken("");
      setError(copy.organizationChanged);
    } else setError(fallback);
  }

  async function toggleEnabled() {
    if (!settings) return;
    setSaving(true);
    setError(null);
    try {
      const answer = await updateMcpSettings(organizationId, !settings.enabled);
      if (!isCurrent()) return;
      if (answer.organizationId !== organizationId) throw new ApiError(409, null);
      setSettings(answer);
      setTestResult(null);
    } catch (reason) { fail(reason, copy.saveFailed); }
    finally { if (isCurrent()) setSaving(false); }
  }

  async function create(event: FormEvent) {
    event.preventDefault();
    if (!settings?.enabled || !settings.aiFeaturesEnabled) return;
    const expiresInDays = Number(expiry);
    if (!Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 365) {
      setError(copy.invalidExpiry);
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const answer = await createToken({ name: name.trim(), expiresInDays,
        scopes: grantedMcpScopes(settings.scopes.map(scope => scope.value).filter(scope => permissions.includes(scope)), selected) }, organizationId);
      if (!isCurrent()) return;
      setCreated(answer);
      setShowToken(false);
      setCopied(null);
      setTestToken(answer.token);
      setTestResult(null);
      setTokens(rows => [{ id: answer.id, name: answer.name, scopes: answer.scopes,
        createdAt: answer.createdAt, expiresAt: answer.expiresAt, lastUsedAt: answer.lastUsedAt }, ...rows]);
    } catch (reason) { fail(reason, copy.createFailed); }
    finally { if (isCurrent()) setCreating(false); }
  }

  async function revoke(id: string) {
    setRevoking(id);
    setError(null);
    try {
      await revokeToken(id, organizationId);
      if (!isCurrent()) return;
      setTokens(rows => rows.filter(token => token.id !== id));
      setTestToken("");
      setTestResult(null);
      if (created?.id === id) setCreated(null);
    } catch (reason) { fail(reason, copy.revokeFailed); }
    finally { if (isCurrent()) setRevoking(null); }
  }

  async function test(event: FormEvent) {
    event.preventDefault();
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      const answer = await testMcpConnection(organizationId, testToken.trim());
      if (!isCurrent()) return;
      if (answer.organizationId !== organizationId) throw new ApiError(409, null);
      if (!answer.ok) throw new Error("connection refused");
      setTestResult(answer.toolCount);
    } catch (reason) { fail(reason, copy.testFailed); }
    finally { if (isCurrent()) setTesting(false); }
  }

  async function copyValue(value: string, kind: string) {
    try {
      await navigator.clipboard.writeText(value);
      if (isCurrent()) setCopied(kind);
    } catch (reason) { fail(reason, copy.copyFailed); }
  }

  const available = settings?.scopes.map(scope => scope.value).filter(scope => permissions.includes(scope)) ?? [];
  const enabled = Boolean(settings?.enabled && settings.aiFeaturesEnabled);
  const endpoint = settings ? new URL(settings.endpoint, new URL(env.apiBaseUrl, window.location.origin)).href : "";
  const configuration = clientConfiguration(client, mode, endpoint);
  const configHelp = client === "codex" ? copy.codexConfig : client === "claude-code" ? copy.claudeCodeConfig : copy.claudeDesktopConfig;
  const date = (value: string | null, fallback: string) => value ? new Date(value).toLocaleString(locale) : fallback;

  return <section className="space-y-6">
    <header>
      <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
      <h1 className="text-3xl font-bold tracking-tight">{copy.title}</h1>
      <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{copy.description}</p>
    </header>
    {error && <div role="alert" className="space-y-2 rounded-lg border border-destructive/30 p-4 text-sm text-destructive">
      <p>{error}</p>
      {!settings && !loading && !stale && <Button variant="outline" onClick={() => setReload(value => value + 1)}>{copy.retry}</Button>}
    </div>}
    {loading && <p role="status" className="text-sm text-muted-foreground">{copy.loading}</p>}
    {!loading && settings && !stale && <>
      <section className="space-y-3 rounded-lg border bg-card p-4" aria-labelledby="mcpDisclosure">
        <h2 id="mcpDisclosure" className="font-semibold">{copy.disclosureTitle}</h2>
        <p className="max-w-4xl text-sm text-muted-foreground">{copy.disclosure}</p>
        <p className="text-sm">{settings.enabled ? copy.enabled : copy.disabled}</p>
        {!settings.aiFeaturesEnabled && <div className="space-y-2 rounded-md bg-muted p-3 text-sm">
          <p>{copy.masterOff}</p>
          {permissions.includes(PERMISSIONS.FEATURE_FLAG_WRITE) && <Link className="underline" to="/settings/feature-flags">{copy.featureFlags}</Link>}
        </div>}
        {settings.canManage ? <Button variant={settings.enabled ? "outline" : "default"} disabled={saving} onClick={toggleEnabled}>
          {saving ? copy.saving : settings.enabled ? copy.disable : copy.enable}
        </Button> : <p className="text-sm text-muted-foreground">{copy.administratorOnly}</p>}
      </section>

      {created && <section className="space-y-3 rounded-lg border border-primary/40 bg-primary/5 p-4" aria-labelledby="mcpCreated">
        <h2 id="mcpCreated" className="font-semibold">{copy.createdTitle}</h2>
        <p className="text-sm text-muted-foreground">{copy.createdHelp}</p>
        <div className="flex flex-wrap gap-2">
          <Input className="min-w-48 flex-1 font-mono" aria-label={copy.secret} type={showToken ? "text" : "password"} readOnly value={created.token} autoComplete="off" />
          <Button variant="outline" onClick={() => setShowToken(value => !value)}>{showToken ? copy.hideToken : copy.showToken}</Button>
          <Button variant="outline" onClick={() => copyValue(created.token, "token")}>{copied === "token" ? copy.copied : copy.copyToken}</Button>
        </div>
        <Button variant="ghost" onClick={() => { setCreated(null); setTestToken(""); setTestResult(null); setCopied(null); }}>{copy.dismiss}</Button>
      </section>}

      <form onSubmit={create} className="space-y-4 rounded-lg border bg-card p-4" aria-labelledby="mcpCreate">
        <h2 id="mcpCreate" className="font-semibold">{copy.createTitle}</h2>
        <div className="grid gap-4 sm:grid-cols-3">
          <div className="space-y-2 text-sm font-medium">
            <label htmlFor="mcpClient">{copy.client}</label>
            <select id="mcpClient" className="block h-10 w-full rounded-md border bg-background px-3" value={client} onChange={event => {
              const value = event.target.value as McpClient;
              setClient(value); setName(copy.clientLabels[value]); setCopied(null);
            }}>
              {Object.entries(copy.clientLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </div>
          <label className="space-y-2 text-sm font-medium">{copy.name}
            <Input required maxLength={255} value={name} onChange={event => setName(event.target.value)} />
          </label>
          <label className="space-y-2 text-sm font-medium">{copy.expiry}
            <Input required type="number" min={1} max={365} step={1} value={expiry} onChange={event => setExpiry(event.target.value)} />
          </label>
        </div>
        <p className="text-xs text-muted-foreground">{copy.expiryHelp}</p>
        <fieldset className="space-y-3" disabled={!enabled || creating}>
          <legend className="mb-2 text-sm font-medium">{copy.capabilities}</legend>
          <p className="text-xs text-muted-foreground">{copy.requiredScope}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            {scopeGroups.map(group => {
              const scopes = group.scopes.filter(scope => available.includes(scope));
              if (!scopes.length) return null;
              return <fieldset key={group.key} className="space-y-2 rounded-md border p-3">
                <legend className="px-1 text-sm font-medium">{copy.groups[group.key]}</legend>
                {scopes.map(scope => <label key={scope} className="flex items-start gap-2 text-sm">
                  <input type="checkbox" className="mt-1" checked={selected.includes(scope)} onChange={() => setSelected(current => current.includes(scope) ? current.filter(value => value !== scope) : [...current, scope])} />
                  <span>{copy.scopeLabels[scope]}</span>
                </label>)}
                {group.key === "refresh" && <p className="text-xs text-muted-foreground">{copy.refreshHelp}</p>}
              </fieldset>;
            })}
          </div>
        </fieldset>
        <Button type="submit" disabled={!enabled || creating || !name.trim() || created !== null}>{creating ? copy.creating : copy.create}</Button>
      </form>

      <section className="space-y-4 rounded-lg border bg-card p-4" aria-labelledby="mcpSetup">
        <h2 id="mcpSetup" className="font-semibold">{copy.setupTitle}</h2>
        <div className="max-w-sm space-y-2 text-sm font-medium">
          <label htmlFor="mcpDeployment">{copy.mode}</label>
          <select id="mcpDeployment" className="block h-10 w-full rounded-md border bg-background px-3" value={mode} onChange={event => { setMode(event.target.value as McpConnectionMode); setCopied(null); }}>
            <option value="mac">{copy.mac}</option><option value="http">{copy.http}</option>
          </select>
        </div>
        {mode === "mac" && <div className="space-y-2">
          <h3 className="text-sm font-medium">{copy.pair}</h3>
          <p className="text-sm text-muted-foreground">{copy.pairHelp}</p>
          <pre aria-label={copy.pairingLabel} className="overflow-x-auto rounded-md border bg-muted/30 p-3 text-xs"><code>{pairingCommand(client)}</code></pre>
          <Button size="sm" variant="outline" onClick={() => copyValue(pairingCommand(client), "pair")}>{copied === "pair" ? copy.copied : copy.copyCommand}</Button>
        </div>}
        <div className="space-y-2">
          <h3 className="text-sm font-medium">{mode === "mac" ? copy.config : client === "claude-desktop" ? copy.endpoint : copy.httpConfig}</h3>
          <p className="text-sm text-muted-foreground">{mode === "http" && client === "claude-desktop" ? copy.remoteDesktopHelp : configHelp}</p>
          {mode === "http" && client !== "claude-desktop" && <p className="text-sm text-muted-foreground">{copy.environmentHelp}</p>}
          <pre aria-label={copy.configurationLabel} className="overflow-x-auto rounded-md border bg-muted/30 p-3 text-xs"><code>{configuration}</code></pre>
          <Button size="sm" variant="outline" onClick={() => copyValue(configuration, "config")}>{copied === "config" ? copy.copied : copy.copyConfig}</Button>
        </div>
      </section>

      <form onSubmit={test} className="space-y-3 rounded-lg border bg-card p-4" aria-labelledby="mcpTest">
        <h2 id="mcpTest" className="font-semibold">{copy.testTitle}</h2>
        <p className="text-sm text-muted-foreground">{copy.testHelp}</p>
        <label className="block space-y-2 text-sm font-medium">{copy.testToken}
          <Input type="password" autoComplete="off" value={testToken} onChange={event => { setTestToken(event.target.value); setTestResult(null); }} />
        </label>
        <Button type="submit" variant="outline" disabled={!enabled || testing || !testToken.trim()}>{testing ? copy.testing : copy.test}</Button>
        {testResult !== null && <p role="status" className="text-sm">{copy.testSuccess(testResult)}</p>}
      </form>

      <section className="space-y-3" aria-labelledby="mcpTokens">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 id="mcpTokens" className="font-semibold">{copy.connectionsTitle}</h2>
          <Button size="sm" variant="outline" disabled={creating || saving || testing || revoking !== null} onClick={() => setReload(value => value + 1)}>{copy.refreshList}</Button>
        </div>
        {!tokens.length ? <p className="text-sm text-muted-foreground">{copy.empty}</p> : <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm"><thead className="border-b bg-muted/30 text-left text-muted-foreground"><tr>
            {[copy.tokenName, copy.permissions, copy.expires, copy.lastUsed].map(label => <th key={label} className="px-4 py-2 font-medium">{label}</th>)}<th className="px-4 py-2" />
          </tr></thead><tbody>{tokens.map(token => <tr key={token.id} className="border-b last:border-0">
            <td className="px-4 py-2 font-medium">{token.name}</td>
            <td className="max-w-sm px-4 py-2 text-xs text-muted-foreground">{token.scopes.map(scope => copy.scopeLabels[scope] ?? scope).join(", ")}</td>
            <td className="whitespace-nowrap px-4 py-2">{date(token.expiresAt, copy.never)}</td>
            <td className="whitespace-nowrap px-4 py-2">{date(token.lastUsedAt, copy.unused)}</td>
            <td className="px-4 py-2 text-right"><Button variant="destructive" size="sm" disabled={revoking === token.id} onClick={() => revoke(token.id)}>{revoking === token.id ? copy.revoking : copy.revoke}</Button></td>
          </tr>)}</tbody></table>
        </div>}
      </section>
    </>}
  </section>;
}
