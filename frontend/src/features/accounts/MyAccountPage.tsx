import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/config/api";
import { changeOwnPassword } from "@/features/accounts/api";
import { useAuthStore } from "@/features/auth/store";
import { useBuildVersion } from "@/features/system/useBuildVersion";
import { useLocale } from "@/i18n/LocaleContext";

export function MyAccountPage() {
  const { t } = useLocale();
  const user = useAuthStore((state) => state.user);
  const version = useBuildVersion();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setDone(false);

    if (newPassword !== confirmPassword) {
      setError(t.myAccount.mismatch);
      return;
    }

    setSubmitting(true);
    try {
      await changeOwnPassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setDone(true);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) {
        setError(t.myAccount.wrongCurrent);
      } else {
        setError(t.myAccount.errorChanging);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.settings.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.myAccount.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.myAccount.description}</p>
      </div>

      <div className="grid gap-4 rounded-lg border bg-card p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <p className="text-xs text-muted-foreground">{t.myAccount.name}</p>
          <p className="text-sm font-medium">{user?.displayName ?? "—"}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">{t.myAccount.email}</p>
          <p className="text-sm font-medium">{user?.email ?? "—"}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">{t.myAccount.roles}</p>
          <p className="text-sm font-medium">{user?.roles.join(", ") || "—"}</p>
        </div>
        {/* The build lives here as well as in the sidebar footer because the sidebar
            is hidden below 768px and can be switched off — and since #130 took this
            answer off the sign-in page, at least one in-app surface has to be one the
            operator cannot lose. */}
        <div>
          <p className="text-xs text-muted-foreground">{t.myAccount.build}</p>
          <p className="truncate font-mono text-sm font-medium" title={version ?? undefined}>
            {version ?? "—"}
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="max-w-md space-y-4 rounded-lg border bg-card p-4">
        <h2 className="text-lg font-semibold">{t.myAccount.changePassword}</h2>

        <div className="space-y-2">
          <label htmlFor="currentPassword" className="text-sm font-medium">
            {t.myAccount.currentPassword}
          </label>
          <Input
            id="currentPassword"
            type="password"
            required
            autoComplete="current-password"
            value={currentPassword}
            onChange={(event) => setCurrentPassword(event.target.value)}
          />
        </div>

        <div className="space-y-2">
          <label htmlFor="newPassword" className="text-sm font-medium">
            {t.myAccount.newPassword}
          </label>
          <Input
            id="newPassword"
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
        </div>

        <div className="space-y-2">
          <label htmlFor="confirmPassword" className="text-sm font-medium">
            {t.myAccount.confirmPassword}
          </label>
          <Input
            id="confirmPassword"
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
          />
        </div>

        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        {done && <p className="text-sm text-emerald-600 dark:text-emerald-400">{t.myAccount.changed}</p>}

        <Button type="submit" disabled={submitting}>
          {submitting ? t.myAccount.changing : t.myAccount.changePassword}
        </Button>

        {/* Stated rather than left as a surprise: a routine rotation shouldn't
            silently break someone's macOS client or CI job, so tokens survive it. */}
        <p className="text-xs text-muted-foreground">{t.myAccount.sessionsHint}</p>
      </form>
    </section>
  );
}
