import { useEffect, useState } from "react";
import { ApiError } from "@/config/api";
import { getDataSharing, type DataSharingSettings } from "@/features/system/api";
import { nextFetch, receiptShown, receiptState } from "@/features/system/receiptState";
import type { Translations } from "@/i18n/en";
import { useLocale, type Locale } from "@/i18n/LocaleContext";

/** What the Data sharing status read answered, and when. A failed read keeps the server's sentence, if one came. */
export type ReceiptRead =
  | { state: "loading" }
  | { state: "failed"; said: string | null }
  | { state: "ready"; sharing: Pick<DataSharingSettings, "tier" | "envDisabled" | "participation">; now: number };

type ViewProps = { read: ReceiptRead; copy: Translations["intelligence"]; locale: Locale };

/** The contribution route for one read; stateless, so the node lane renders it. It names only the status's fields,
 *  which carry presence, dates and progress: the receipt itself never reaches the browser. */
export function ContributionReceiptView({ read, copy, locale }: ViewProps) {
  const words = copy.contribution;
  if (read.state === "loading") return null;
  if (read.state === "failed") return <p role="alert" className="text-sm text-destructive">{read.said ?? words.loadFailed}</p>;
  const { sharing, now } = read;
  const receipt = sharing.participation;
  if (!receiptShown(receipt)) return null;
  const state = receiptState(receipt, sharing, now);
  const when = (at: string | null, absent: string = copy.none) =>
    at ? new Date(at).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" }) : absent;
  return (
    <section className="space-y-3 rounded-md border p-4" aria-label={words.title}>
      <h2 className="font-semibold">{words.title}</h2>
      <p className="text-sm text-muted-foreground">{words.description}</p>
      {!receipt.enabled && <p className="text-sm">{words.receiptsOff}</p>}
      {receipt.enabled && sharing.envDisabled && state === "idle" && <p className="text-sm">{words.envOverride}</p>}
      <dl className="grid grid-cols-2 gap-2 text-sm">
        <dt>{words.receipt}</dt><dd>{receipt.receiptPresent ? words.held : words.notHeld}</dd>
        <dt>{words.state}</dt>
        <dd><span className="font-medium">{words.states[state]}</span><span className="block text-muted-foreground">{words.explained[state]}</span></dd>
        <dt>{words.accepted}</dt><dd>{when(receipt.acceptedAt)}</dd>
        {/* A receipt withdrawn or ended keeps its old date in the status; only one still stored as in force shows it. */}
        <dt>{copy.until}</dt><dd>{when(["contributing", "idle", "lapsed"].includes(state) ? receipt.updatesUntil : null)}</dd>
        <dt>{words.lastFetched}</dt><dd>{when(receipt.lastRedeemedAt, words.notYet)}</dd>
        <dt>{words.nextFetch}</dt><dd>{when(nextFetch(sharing, receipt, state), words.noneScheduled)}</dd>
        {state === "withdrawal_pending" && <>
          <dt>{words.withdrawalRequested}</dt><dd>{when(receipt.withdrawalRequestedAt)}</dd>
          <dt>{words.withdrawalAttempt}</dt><dd>{when(receipt.lastWithdrawalAttemptAt, words.notYet)}</dd>
        </>}
        {state === "withdrawn" && receipt.withdrawnAt && <><dt>{words.withdrawnAt}</dt><dd>{when(receipt.withdrawnAt)}</dd></>}
      </dl>
      {receipt.error && <p role="alert" className="text-sm text-destructive">{receipt.error}</p>}
      <p className="text-sm text-muted-foreground">{words.disclosure}</p>
      <p className="text-sm text-muted-foreground">{words.both}</p>
      <p className="text-sm text-muted-foreground">{words.whichRefreshes}</p>
    </section>
  );
}

/**
 * Settings › Intelligence Access: the contribution route beside paid access (#622). It reads the Data sharing
 * status (`participation`), never paid access, so it shows whether or not the paid preview is on.
 */
export function ContributionReceipt() {
  const { t, locale } = useLocale();
  const [read, setRead] = useState<ReceiptRead>({ state: "loading" });
  useEffect(() => {
    let live = true;
    getDataSharing()
      .then((sharing) => {
        if (live) setRead({ state: "ready", sharing, now: Date.now() });
      })
      .catch((caught: unknown) => {
        if (live) setRead({ state: "failed", said: caught instanceof ApiError ? caught.detail : null });
      });
    return () => {
      live = false;
    };
  }, []);
  return <ContributionReceiptView read={read} copy={t.intelligence} locale={locale} />;
}
