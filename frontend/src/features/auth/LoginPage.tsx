import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { FlaskLogo } from "@/components/icons/FlaskLogo";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "@/components/ui/external-link";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import { SLACK_CHANNEL, SUPPORT_LINKS } from "@/features/support/links";
import { useLocale } from "@/i18n/LocaleContext";

export function LoginPage() {
  const { t } = useLocale();
  const navigate = useNavigate();
  const location = useLocation();

  const status = useAuthStore((state) => state.status);
  const bootstrap = useAuthStore((state) => state.bootstrap);
  const login = useAuthStore((state) => state.login);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (status === "unknown") void bootstrap();
  }, [status, bootstrap]);

  const from = (location.state as { from?: string } | null)?.from ?? "/";

  if (status === "authenticated") return <Navigate to={from} replace />;
  if (status === "setup-required") return <Navigate to="/setup" replace />;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      await login(email, password);
      navigate(from, { replace: true });
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 429) {
        setError(t.auth.lockedOut);
      } else if (caught instanceof ApiError && caught.status === 401) {
        // Same message for every credential failure — the server deliberately doesn't
        // distinguish unknown account from wrong password, and neither should we.
        setError(t.auth.invalidCredentials);
      } else {
        setError(t.auth.genericError);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4 text-foreground">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <FlaskLogo className="h-8 w-8 text-primary" />
          <h1 className="text-2xl font-bold tracking-tight">{t.auth.loginTitle}</h1>
          <p className="text-sm text-muted-foreground">{t.auth.loginDescription}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-6">
          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium">
              {t.auth.email}
            </label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              required
              autoFocus
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="password" className="text-sm font-medium">
              {t.auth.password}
            </label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>

          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? t.auth.signingIn : t.auth.signIn}
          </Button>
        </form>

        {/* The locked-out half of #301. Settings › Support sits behind DEVICE_READ
            like every other settings route, so a person with no session cannot reach
            it — and buying them an unauthenticated route to reach it would be the
            audit finding the gate was added to avoid. This page already answers
            without a session, so naming the same two channels here costs no new
            surface. It states no instance fact: no build string, no version, nothing
            that distinguishes this deployment from any other. */}
        <div className="space-y-2 px-1 text-xs text-muted-foreground">
          <p className="font-medium text-foreground">{t.auth.loginSupportTitle}</p>
          <p>{t.auth.loginSupportBody}</p>
          <p>{t.auth.loginSupportWarning}</p>
          <div className="flex flex-wrap gap-x-5 gap-y-1 pt-0.5">
            <ExternalLink href={SUPPORT_LINKS.newIssue}>
              {t.auth.loginSupportGithub}
            </ExternalLink>
            <ExternalLink href={SUPPORT_LINKS.slackJoin}>
              {t.auth.loginSupportSlack(SLACK_CHANNEL)}
            </ExternalLink>
          </div>
        </div>
      </div>
    </div>
  );
}
