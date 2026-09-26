import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { savePolicy } from "@/features/accounts/mfaPolicy";
import { useHasPermission } from "@/features/auth/store";
import { PERMISSIONS } from "@/features/auth/types";
import { getMfaPolicy } from "@/features/settings/api";
import { MFA_POLICIES, type MfaPolicy } from "@/features/settings/types";
import type { Translations } from "@/i18n/en";
import { useLocale } from "@/i18n/LocaleContext";

/** What the read answered. A read that failed is unknown, never "off" (#150). */
export type PolicyRead = { state: "loading" } | { state: "failed" } | { state: "ready"; policy: MfaPolicy };
type Handlers = { choose: (policy: MfaPolicy) => void; apply: () => void; cancel: () => void };
type ViewProps = { read: PolicyRead; canWrite: boolean; copy: Translations["accounts"]; pending?: MfaPolicy | null; busy?: boolean; error?: string | null; on?: Partial<Handlers> };

/** Who must sign in with a second factor (#653): the word in force for a reader; the three for an administrator. */
export function MfaPolicyView({ read, canWrite, copy, pending = null, busy = false, error = null, on = {} }: ViewProps) {
  const words = copy.mfaPolicy;
  const policy = read.state === "ready" ? read.policy : null;
  return (
    <div className="space-y-3 rounded-lg border bg-card p-4">
      <h2 className="text-lg font-semibold">{words.title}</h2>
      <p className="text-sm text-muted-foreground">{words.description}</p>
      {read.state === "loading" && <p className="text-sm text-muted-foreground">{words.loading}</p>}
      {read.state === "failed" && <p className="text-sm text-destructive">{words.unreadable}</p>}
      {policy && !canWrite && <p className="text-sm font-medium">{words.names[policy]}</p>}
      {policy && canWrite && (
        <div className="flex flex-wrap gap-2">
          {MFA_POLICIES.map((word) => (
            <Button key={word} size="sm" variant={word === policy ? "default" : "outline"} aria-pressed={word === policy}
              disabled={busy} onClick={() => on.choose?.(word)}>{words.names[word]}</Button>
          ))}
        </div>
      )}
      {pending && (
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm">{words.confirm[pending]}</p>
          <Button size="sm" disabled={busy} onClick={on.apply}>{copy.confirm}</Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={on.cancel}>{copy.cancel}</Button>
        </div>
      )}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    </div>
  );
}

export function MfaPolicyControl() {
  const { t } = useLocale();
  const canWrite = useHasPermission(PERMISSIONS.ACCOUNT_WRITE);
  const [read, setRead] = useState<PolicyRead>({ state: "loading" });
  const [pending, setPending] = useState<MfaPolicy | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getMfaPolicy()
      .then(({ mfaRequired }) => live && setRead({ state: "ready", policy: mfaRequired }))
      .catch(() => live && setRead({ state: "failed" }));
    return () => void (live = false);
  }, []);

  const on: Handlers = {
    choose: (word) => setPending(read.state === "ready" && word === read.policy ? null : word),
    cancel: () => setPending(null),
    apply: () => {
      if (!pending) return;
      setBusy(true);
      setError(null);
      void savePolicy(pending, t.accounts.mfaPolicy.failed).then((saved) => {
        if ("policy" in saved) setRead({ state: "ready", policy: saved.policy });
        else setError(saved.error);
        setPending(null);
        setBusy(false);
      });
    }
  };

  return <MfaPolicyView {...{ read, canWrite, pending, busy, error, on }} copy={t.accounts} />;
}
