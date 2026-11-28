import { useEffect, useState, type FormEvent } from "react";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { addPasskey, dropPasskey, PANEL_CLOSED, readPasskeys, type PasskeyMove, type PasskeyPanel, type PasskeyRead } from "@/features/accounts/passkeyPanel";
import type { Passkey } from "@/features/accounts/types";
import { passkeySupport, type PasskeySupport } from "@/features/auth/passkeys";
import { useAuthStore } from "@/features/auth/store";
import type { Translations } from "@/i18n/en";
import { useLocale, type Locale } from "@/i18n/LocaleContext";

type Handlers = Record<"open" | "cancel" | "confirmRemove", () => void> & {
  name: (value: string) => void;
  password: (value: string) => void;
  submit: (event: FormEvent) => void;
  remove: (passkey: Passkey) => void;
};

interface ViewProps {
  read: PasskeyRead;
  /** Null while the browser's availability calls are still answering. */
  support: PasskeySupport | null;
  panel: PasskeyPanel;
  copy: Translations["myAccount"]["passkeys"];
  locale: Locale;
  /** This page's host, to say of a passkey made elsewhere that it is not offered here. */
  hostname: string;
  /** The policy holds this session on My Account (#653): a passkey answers it too, and removal waits. */
  held?: boolean;
  busy?: boolean;
  name?: string;
  password?: string;
  on?: Partial<Handlers>;
}

/** Why this page offers no passkey, in the operator's words with the address (#955, trap 1), or null. */
function whyNot(support: PasskeySupport | null, copy: ViewProps["copy"]): string | null {
  if (support?.state === "address") {
    return support.reason === "ip" ? copy.ipAddress(support.origin, support.localhost) : copy.plainHttp(support.origin, support.localhost);
  }
  return support?.state === "browser" ? copy.browser : null;
}

/** My Account › Passkeys for one list read, one availability answer and one panel step; stateless, so the node lane renders it. */
export function PasskeysView({ read, support, panel, copy, locale, hostname, held = false, busy = false, name = "", password = "", on = {} }: ViewProps) {
  const day = (value: string) => new Date(value).toLocaleDateString(locale, { dateStyle: "medium" });
  const offered = support?.state === "available";
  const reason = whyNot(support, copy);

  return (
    <div className="max-w-md space-y-4 rounded-lg border bg-card p-4">
      <h2 className="text-lg font-semibold">{copy.title}</h2>
      <p className="text-sm text-muted-foreground">{copy.description}</p>
      {held && offered && <p className="text-sm">{copy.held}</p>}
      {reason && <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">{reason}</p>}

      {read.state === "loading" && <p className="text-sm text-muted-foreground">{copy.loading}</p>}
      {read.state === "failed" && <p className="text-sm text-destructive">{copy.unreadable}</p>}
      {read.state === "ready" && read.passkeys.length === 0 && <p className="text-sm text-muted-foreground">{copy.none}</p>}
      {read.state === "ready" && read.passkeys.length > 0 && (
        <ul className="divide-y rounded-md border">
          {read.passkeys.map((passkey) => (
            <li key={passkey.id} className="flex items-start justify-between gap-3 px-3 py-2">
              <div className="min-w-0 space-y-0.5">
                <p className="truncate text-sm font-medium">{passkey.name}</p>
                <p className="text-xs text-muted-foreground">{copy.worksAt(passkey.host)}</p>
                {passkey.host !== hostname && <p className="text-xs text-amber-600 dark:text-amber-400">{copy.notHere(passkey.host)}</p>}
                <p className="text-xs text-muted-foreground">
                  {copy.added(day(passkey.createdAt))} · {passkey.lastUsedAt ? copy.lastUsed(day(passkey.lastUsedAt)) : copy.neverUsed}
                </p>
              </div>
              {!held && (
                <Button variant="outline" size="sm" disabled={busy} onClick={() => on.remove?.(passkey)}>
                  {copy.remove}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}

      {panel.step === "remove" && (
        <div className="flex flex-wrap items-center justify-end gap-2">
          <span className="text-xs text-muted-foreground">{copy.removeConfirm(panel.passkey.name)}</span>
          <Button variant="destructive" size="sm" disabled={busy} onClick={on.confirmRemove}>{copy.remove}</Button>
          <Button variant="ghost" size="sm" disabled={busy} onClick={on.cancel}>{copy.cancel}</Button>
        </div>
      )}

      {offered && panel.step === "closed" && (
        <Button onClick={on.open}>
          <KeyRound className="mr-2 h-4 w-4" />
          {copy.add}
        </Button>
      )}
      {offered && panel.step === "form" && (
        <form onSubmit={on.submit} className="space-y-3">
          <div className="space-y-1">
            <label htmlFor="passkeyName" className="block text-sm font-medium">{copy.nameLabel}</label>
            <Input id="passkeyName" required maxLength={64} autoComplete="off" value={name} onChange={(event) => on.name?.(event.target.value)} />
            <p className="text-xs text-muted-foreground">{copy.nameHelp}</p>
          </div>
          <div className="space-y-1">
            <label htmlFor="passkeyPassword" className="block text-sm font-medium">{copy.passwordLabel}</label>
            <Input id="passkeyPassword" type="password" required autoComplete="current-password" value={password}
              onChange={(event) => on.password?.(event.target.value)} />
          </div>
          <div className="flex gap-2">
            <Button type="submit" disabled={busy}>{busy ? copy.adding : copy.add}</Button>
            <Button type="button" variant="ghost" disabled={busy} onClick={on.cancel}>{copy.cancel}</Button>
          </div>
        </form>
      )}

      {panel.step === "closed" && panel.notice && <p className="text-sm text-emerald-600 dark:text-emerald-400">{panel.notice}</p>}
      {panel.error && <p role="alert" className="text-sm text-destructive">{panel.error}</p>}
    </div>
  );
}

/** My Account › Passkeys (#955): each passkey with its host and dates, Add a passkey, and removal. */
export function Passkeys() {
  const { t, locale } = useLocale();
  const held = useAuthStore((state) => state.user?.mfaEnrolmentRequired ?? false);
  const [support, setSupport] = useState<PasskeySupport | null>(null);
  const [reads, setReads] = useState(0);
  const [read, setRead] = useState<PasskeyRead>({ state: "loading" });
  const [panel, setPanel] = useState<PasskeyPanel>(PANEL_CLOSED);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");

  // A re-read turns the list back to reading in the render that asked for it, never from the effect; the guard
  // compares the effect's whole dependency array (CONTRIBUTING, #479).
  const [asked, setAsked] = useState(reads);
  if (asked !== reads) {
    setAsked(reads);
    setRead({ state: "loading" });
  }

  useEffect(() => {
    let live = true;
    passkeySupport().then((found) => live && setSupport(found));
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    let live = true;
    readPasskeys().then((answer) => live && setRead(answer));
    return () => {
      live = false;
    };
  }, [reads]);

  function apply(move: PasskeyMove) {
    setPanel(move.panel);
    setBusy(false);
    if (move.panel.step !== "form") {
      setName("");
      setPassword("");
    }
    if (move.refresh) setReads((count) => count + 1);
  }

  function run(next: Promise<PasskeyMove>) {
    setBusy(true);
    void next.then(apply);
  }

  const on: Handlers = {
    open: () => setPanel({ step: "form", error: null }),
    cancel: () => apply({ panel: PANEL_CLOSED, refresh: false }),
    name: setName,
    password: setPassword,
    submit: (event) => {
      event.preventDefault();
      run(addPasskey(name.trim(), password, t, window.location.origin));
    },
    remove: (passkey) => setPanel({ step: "remove", passkey, error: null }),
    confirmRemove: () => {
      if (panel.step === "remove") run(dropPasskey(panel.passkey, t));
    }
  };

  return (
    <PasskeysView
      {...{ read, support, panel, locale, held, busy, name, password, on }}
      copy={t.myAccount.passkeys}
      hostname={window.location.hostname}
    />
  );
}
