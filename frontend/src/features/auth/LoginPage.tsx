import { useEffect, useReducer, useRef, useState, type FormEvent } from "react";
import { KeyRound } from "lucide-react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { BrandIdentity } from "@/components/layout/BrandIdentity";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "@/components/ui/external-link";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/config/api";
import { passkeySupport, type PasskeySupport } from "@/features/auth/passkeys";
import { SecondStepForm } from "@/features/auth/SecondStepForm";
import { secondStep, secondStepError } from "@/features/auth/secondStep";
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
  const loginMfa = useAuthStore((state) => state.loginMfa);
  const signInWithPasskey = useAuthStore((state) => state.signInWithPasskey);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // null on the password step; after it, the challenge the password earned (#653).
  const [second, dispatch] = useReducer(secondStep, null);

  // Passkeys (#955): what this page can offer, null until the browser answers; the open conditional request, so the
  // password manager offers a passkey where it offers the password; and the button's own request.
  const [passkeys, setPasskeys] = useState<PasskeySupport | null>(null);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [armed, setArmed] = useState(0);
  const conditional = useRef<AbortController | null>(null);
  const modal = useRef<AbortController | null>(null);

  useEffect(() => {
    if (status === "unknown") void bootstrap();
  }, [status, bootstrap]);

  useEffect(() => {
    let live = true;
    passkeySupport().then((found) => live && setPasskeys(found));
    return () => {
      live = false;
      modal.current?.abort();
    };
  }, []);

  // Open while the password step shows and the browser has the conditional form; aborted when the person signs in
  // another way or leaves the page (the cleanup), and opened again after anything that ended it short of a session.
  const offersConditional = second === null && passkeys?.state === "available" && passkeys.conditional;
  const copy = t.auth.passkeys;
  useEffect(() => {
    if (!offersConditional) return;
    const controller = new AbortController();
    conditional.current = controller;
    signInWithPasskey("conditional", controller.signal, copy).then((outcome) => {
      if (outcome.kind !== "refused") return;
      setPasskeyError(outcome.error);
      setArmed((count) => count + 1);
    });
    return () => controller.abort();
  }, [offersConditional, armed, signInWithPasskey, copy]);

  const from = (location.state as { from?: string } | null)?.from ?? "/";

  if (status === "authenticated") return <Navigate to={from} replace />;
  if (status === "setup-required") return <Navigate to="/setup" replace />;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    // Signing in with the password is signing in another way: the passkey request the field offered ends.
    conditional.current?.abort();
    setSubmitting(true);
    setError(null);
    setPasskeyError(null);

    try {
      const challenge = await login(email, password);
      if (challenge === null) {
        navigate(from, { replace: true });
      } else {
        // A second factor is owed: a challenge, not a session, and the password is not kept.
        setPassword("");
        dispatch({ type: "challenged", challenge });
      }
    } catch (caught) {
      setArmed((count) => count + 1);
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

  /** Sign in with a passkey: the modal request, for a security key and a browser without the conditional form. */
  function handlePasskey() {
    conditional.current?.abort();
    const controller = new AbortController();
    modal.current = controller;
    setPasskeyBusy(true);
    setPasskeyError(null);
    setError(null);
    void signInWithPasskey("modal", controller.signal, copy).then((outcome) => {
      // Signed in: the page follows the session to where it was headed.
      if (outcome.kind === "signed-in" || controller.signal.aborted) return;
      setPasskeyBusy(false);
      if (outcome.kind !== "aborted") setPasskeyError(outcome.error);
      setArmed((count) => count + 1);
    });
  }

  async function handleCode(event: FormEvent) {
    event.preventDefault();
    if (second === null) return;
    setSubmitting(true);
    dispatch({ type: "sent" });

    try {
      await loginMfa(second.challenge.challenge, second.code);
      navigate(from, { replace: true });
    } catch (caught) {
      dispatch({ type: "refused", error: secondStepError(caught, t.auth) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center bg-background text-foreground">
      <div className="login-layout">
        <aside className="login-welcome">
          <h2>{t.auth.brandWelcome}</h2>
          <p>{t.auth.brandDescription}</p>
          <img src="/brand/lake-scene.svg" alt="" />
        </aside>
        <div className="login-form-panel space-y-6">
          <div className="flex flex-col items-center gap-2 text-center">
            <BrandIdentity />
            <h1 className="text-2xl font-bold tracking-tight">{t.auth.loginTitle}</h1>
            <p className="text-sm text-muted-foreground">{t.auth.loginDescription}</p>
          </div>

          {second && (
            <SecondStepForm step={second} copy={t.auth} submitting={submitting} dispatch={dispatch} onSubmit={handleCode} />
          )}
          {!second && <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border bg-card p-6">
            <div className="space-y-2">
              <label htmlFor="email" className="text-sm font-medium">
                {t.auth.email}
              </label>
              <Input
                id="email"
                type="email"
                // `webauthn` puts a saved passkey in the autofill menu beside a saved password, while the page holds
                // a conditional request open (#955).
                autoComplete="username webauthn"
                required
                autoFocus={email === ""}
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
                // Start over keeps the email, so the password is what is missing then.
                autoFocus={email !== ""}
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
          </form>}

          {/* Only where a passkey can work (#955): never at an IP address, over plain HTTP off localhost, or in a
              browser that answers false to both availability calls. My Account says which, and why. */}
          {!second && passkeys?.state === "available" && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="h-px flex-1 bg-border" />
                {copy.or}
                <span className="h-px flex-1 bg-border" />
              </div>
              <Button type="button" variant="outline" className="w-full" disabled={passkeyBusy || submitting} onClick={handlePasskey}>
                <KeyRound className="mr-2 h-4 w-4" />
                {passkeyBusy ? copy.waiting : copy.signIn}
              </Button>
              {passkeyError && (
                <p role="alert" className="text-sm text-destructive">
                  {passkeyError}
                </p>
              )}
            </div>
          )}

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
    </div>
  );
}
