import type { FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { SecondStep, SecondStepAction } from "@/features/auth/secondStep";
import type { Translations } from "@/i18n/en";

type Props = {
  step: SecondStep;
  copy: Translations["auth"];
  submitting: boolean;
  dispatch: (action: SecondStepAction) => void;
  onSubmit: (event: FormEvent) => void;
};

// type="button" on both: a plain <button> in a form submits it, and these move the step.
const MOVE = "text-primary underline-offset-4 hover:underline disabled:opacity-50";

/** The sign-in page's second step (#653): one input, in the authenticator's shape or a
 *  recovery code's, the server's refusal as it came, and the way back to the password. */
export function SecondStepForm({ step, copy, submitting, dispatch, onSubmit }: Props) {
  const { recovery } = step;
  return (
    <form onSubmit={onSubmit} className="space-y-4 rounded-lg border bg-card p-6">
      <div className="space-y-2">
        <label htmlFor="mfa-code" className="text-sm font-medium">
          {recovery ? copy.recoveryCodeLabel : copy.codeLabel}
        </label>
        <Input
          // Remounted per shape, so switching hands the focus to the other input.
          key={recovery ? "recovery" : "code"}
          id="mfa-code"
          aria-describedby="mfa-code-help"
          required
          autoFocus
          minLength={recovery ? 10 : 6}
          maxLength={32}
          inputMode={recovery ? "text" : "numeric"}
          autoComplete={recovery ? "off" : "one-time-code"}
          placeholder={recovery ? "xxxxx-xxxxx" : undefined}
          autoCorrect="off"
          spellCheck={false}
          value={step.code}
          onChange={(event) => dispatch({ type: "typed", code: event.target.value })}
        />
        <p id="mfa-code-help" className="text-xs text-muted-foreground">
          {recovery ? copy.recoveryCodeHelp : copy.codeHelp}
        </p>
      </div>

      {step.error && <p role="alert" className="text-sm text-destructive">{step.error}</p>}

      <Button type="submit" className="w-full" disabled={submitting}>
        {submitting ? copy.signingIn : copy.signIn}
      </Button>

      <div className="flex flex-wrap justify-between gap-2 text-sm">
        {step.challenge.methods.includes("recovery") && (
          <button type="button" className={MOVE} disabled={submitting} onClick={() => dispatch({ type: "switched" })}>
            {recovery ? copy.useAuthenticatorCode : copy.useRecoveryCode}
          </button>
        )}
        <button type="button" className={MOVE} disabled={submitting} onClick={() => dispatch({ type: "start-over" })}>
          {copy.startOver}
        </button>
      </div>
    </form>
  );
}
