import { useEffect, useState, type FormEvent } from "react";
import { KeyRound, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/config/api";
import { createAccount, listAccounts, resetPassword, updateAccount } from "@/features/accounts/api";
import { ROLES, type Account } from "@/features/accounts/types";
import { useAuthStore } from "@/features/auth/store";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { useLocale } from "@/i18n/LocaleContext";

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export function AccountsPage() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.ACCOUNT_WRITE);
  const currentUserId = useAuthStore((state) => state.user?.id);

  const [accounts, setAccounts] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [newRoles, setNewRoles] = useState<string[]>(["viewer"]);
  const [submitting, setSubmitting] = useState(false);

  const [resetFor, setResetFor] = useState<string | null>(null);
  const [resetPw, setResetPw] = useState("");

  async function refresh() {
    setLoading(true);
    try {
      setAccounts(await listAccounts());
    } catch {
      setError(t.accounts.errorLoading);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** The server is the authority on every guard here — it refuses self-disable, self
   *  demotion, and removing the last admin regardless of what the UI allows. Surfacing
   *  its message rather than a generic one is what makes those refusals learnable. */
  function reportError(caught: unknown, fallback: string) {
    if (caught instanceof ApiError && caught.status === 409 && caught.detail) {
      setError(caught.detail);
    } else {
      setError(fallback);
    }
  }

  async function handleCreate(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await createAccount({ email, displayName, password, roles: newRoles });
      setEmail("");
      setDisplayName("");
      setPassword("");
      setNewRoles(["viewer"]);
      setShowCreate(false);
      await refresh();
    } catch (caught) {
      reportError(caught, t.accounts.errorCreating);
    } finally {
      setSubmitting(false);
    }
  }

  async function toggleRole(account: Account, role: string) {
    const roles = account.roles.includes(role)
      ? account.roles.filter((value) => value !== role)
      : [...account.roles, role];

    setBusyId(account.id);
    setError(null);
    try {
      await updateAccount(account.id, { roles });
      await refresh();
    } catch (caught) {
      reportError(caught, t.accounts.errorUpdating);
    } finally {
      setBusyId(null);
    }
  }

  async function toggleStatus(account: Account) {
    setBusyId(account.id);
    setError(null);
    try {
      await updateAccount(account.id, {
        status: account.status === "active" ? "disabled" : "active"
      });
      await refresh();
    } catch (caught) {
      reportError(caught, t.accounts.errorUpdating);
    } finally {
      setBusyId(null);
    }
  }

  async function handleReset(event: FormEvent, account: Account) {
    event.preventDefault();
    setBusyId(account.id);
    setError(null);
    try {
      await resetPassword(account.id, resetPw);
      setResetFor(null);
      setResetPw("");
      await refresh();
    } catch (caught) {
      reportError(caught, t.accounts.errorResetting);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
          <h1 className="text-3xl font-bold tracking-tight">{t.accounts.title}</h1>
          <p className="mt-1 text-sm text-muted-foreground">{t.accounts.description}</p>
        </div>
        {canWrite && !showCreate && (
          <Button onClick={() => setShowCreate(true)}>{t.accounts.addAccount}</Button>
        )}
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      {canWrite && showCreate && (
        <form onSubmit={handleCreate} className="space-y-4 rounded-lg border bg-card p-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-2">
              <label htmlFor="newDisplayName" className="text-sm font-medium">
                {t.accounts.displayName}
              </label>
              <Input
                id="newDisplayName"
                required
                value={displayName}
                onChange={(event) => setDisplayName(event.target.value)}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="newEmail" className="text-sm font-medium">
                {t.accounts.email}
              </label>
              <Input
                id="newEmail"
                type="email"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="newPassword" className="text-sm font-medium">
                {t.accounts.initialPassword}
              </label>
              <Input
                id="newPassword"
                type="password"
                required
                minLength={12}
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
          </div>

          <div className="space-y-2">
            <p className="text-sm font-medium">{t.accounts.roles}</p>
            <div className="flex flex-wrap gap-2">
              {ROLES.map((role) => (
                <button
                  key={role}
                  type="button"
                  onClick={() =>
                    setNewRoles((current) =>
                      current.includes(role)
                        ? current.filter((value) => value !== role)
                        : [...current, role]
                    )
                  }
                  className={
                    newRoles.includes(role)
                      ? "rounded-md border border-primary bg-primary/10 px-2 py-1 text-xs font-medium"
                      : "rounded-md border border-input px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
                  }
                >
                  {role}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">{t.accounts.passwordHint}</p>
          </div>

          <div className="flex gap-2">
            <Button type="submit" disabled={submitting}>
              {submitting ? t.accounts.creating : t.accounts.create}
            </Button>
            <Button type="button" variant="outline" onClick={() => setShowCreate(false)}>
              {t.accounts.cancel}
            </Button>
          </div>
        </form>
      )}

      <div className="overflow-x-auto rounded-lg border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/30 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-2 font-medium">{t.accounts.tableName}</th>
              <th className="px-4 py-2 font-medium">{t.accounts.tableRoles}</th>
              <th className="px-4 py-2 font-medium">{t.accounts.tableStatus}</th>
              <th className="px-4 py-2 font-medium">{t.accounts.tableLastLogin}</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td className="px-4 py-4 text-muted-foreground" colSpan={5}>
                  {t.accounts.loading}
                </td>
              </tr>
            )}
            {accounts.map((account) => {
              const isSelf = account.id === currentUserId;
              return (
                <tr key={account.id} className="border-b align-top last:border-0">
                  <td className="px-4 py-3">
                    <div className="font-medium">
                      {account.displayName}
                      {isSelf && (
                        <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                          {t.accounts.you}
                        </span>
                      )}
                      {account.isBreakGlass && (
                        <span
                          title={t.accounts.breakGlassHint}
                          className="ml-2 inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-xs text-amber-600 dark:text-amber-400"
                        >
                          <ShieldAlert className="h-3 w-3" />
                          {t.accounts.breakGlass}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground">{account.email}</div>
                  </td>

                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {ROLES.map((role) => {
                        const held = account.roles.includes(role);
                        if (!canWrite) {
                          return held ? (
                            <span key={role} className="rounded-md border px-2 py-0.5 text-xs">
                              {role}
                            </span>
                          ) : null;
                        }
                        return (
                          <button
                            key={role}
                            type="button"
                            disabled={busyId === account.id}
                            onClick={() => toggleRole(account, role)}
                            className={
                              held
                                ? "rounded-md border border-primary bg-primary/10 px-2 py-0.5 text-xs font-medium disabled:opacity-50"
                                : "rounded-md border border-input px-2 py-0.5 text-xs text-muted-foreground hover:bg-accent disabled:opacity-50"
                            }
                          >
                            {role}
                          </button>
                        );
                      })}
                    </div>
                  </td>

                  <td className="px-4 py-3">
                    <span
                      className={
                        account.status === "active"
                          ? "rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-600 dark:text-emerald-400"
                          : "rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground"
                      }
                    >
                      {account.status === "active" ? t.accounts.active : t.accounts.disabled}
                    </span>
                  </td>

                  <td className="px-4 py-3 text-xs">{formatDate(account.lastLoginAt)}</td>

                  <td className="px-4 py-3">
                    {canWrite && (
                      <div className="flex flex-col items-end gap-2">
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={busyId === account.id}
                            onClick={() => setResetFor(resetFor === account.id ? null : account.id)}
                          >
                            <KeyRound className="mr-1 h-3 w-3" />
                            {t.accounts.resetPassword}
                          </Button>
                          <Button
                            variant={account.status === "active" ? "destructive" : "outline"}
                            size="sm"
                            disabled={busyId === account.id || isSelf}
                            title={isSelf ? t.accounts.cannotDisableSelf : undefined}
                            onClick={() => toggleStatus(account)}
                          >
                            {account.status === "active" ? t.accounts.disable : t.accounts.enable}
                          </Button>
                        </div>

                        {resetFor === account.id && (
                          <form
                            onSubmit={(event) => handleReset(event, account)}
                            className="flex items-center gap-2"
                          >
                            <Input
                              type="password"
                              required
                              minLength={12}
                              autoComplete="new-password"
                              placeholder={t.accounts.newPassword}
                              value={resetPw}
                              onChange={(event) => setResetPw(event.target.value)}
                              className="h-9 w-56"
                            />
                            <Button type="submit" size="sm" disabled={busyId === account.id}>
                              {t.accounts.confirm}
                            </Button>
                          </form>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-muted-foreground">{t.accounts.disableHint}</p>
    </section>
  );
}
