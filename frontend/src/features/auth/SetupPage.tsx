import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router";
import { FlaskLogo } from "@/components/icons/FlaskLogo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/config/api";
import { useAuthStore } from "@/features/auth/store";
import { useLocale } from "@/i18n/LocaleContext";

const MIN_PASSWORD_LENGTH = 12;

export function SetupPage() {
  const { t } = useLocale();
  const navigate = useNavigate();

  const status = useAuthStore((state) => state.status);
  const bootstrap = useAuthStore((state) => state.bootstrap);
  const completeSetup = useAuthStore((state) => state.completeSetup);

  const [claimToken, setClaimToken] = useState("");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (status === "unknown") void bootstrap();
  }, [status, bootstrap]);

  if (status === "authenticated") return <Navigate to="/" replace />;
  // Someone already claimed this instance while this tab was open.
  if (status === "unauthenticated") return <Navigate to="/login" replace />;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      await completeSetup({ claimToken, email, displayName, password });
      navigate("/", { replace: true });
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 403) {
        setError(t.auth.invalidClaimToken);
      } else if (caught instanceof ApiError && caught.status === 409) {
        setError(t.auth.setupAlreadyDone);
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError(t.auth.passwordTooShort);
      } else {
        setError(t.auth.genericError);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4 py-10 text-foreground">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <FlaskLogo className="h-8 w-8 text-primary" />
          <h1 className="text-2xl font-bold tracking-tight">{t.auth.setupTitle}</h1>
          <p className="text-sm text-muted-foreground">{t.auth.setupDescription}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-6">
          <div className="space-y-2">
            <label htmlFor="claimToken" className="text-sm font-medium">
              {t.auth.claimToken}
            </label>
            <Input
              id="claimToken"
              required
              autoFocus
              autoComplete="off"
              spellCheck={false}
              value={claimToken}
              onChange={(event) => setClaimToken(event.target.value)}
            />
            <p className="text-xs text-muted-foreground">{t.auth.claimTokenHelp}</p>
            <pre className="overflow-x-auto rounded-md border bg-muted/40 px-3 py-2 text-xs">
              docker compose logs app | grep &quot;claim token&quot;
            </pre>
          </div>

          <div className="space-y-2">
            <label htmlFor="displayName" className="text-sm font-medium">
              {t.auth.displayName}
            </label>
            <Input
              id="displayName"
              required
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium">
              {t.auth.email}
            </label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              required
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
              autoComplete="new-password"
              required
              minLength={MIN_PASSWORD_LENGTH}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            <p className="text-xs text-muted-foreground">{t.auth.passwordHelp}</p>
          </div>

          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? t.auth.creating : t.auth.createAdmin}
          </Button>
        </form>
      </div>
    </div>
  );
}
