import { useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/config/api";
import {
  listPromotions,
  promoteApplication,
  withdrawPromotion,
  type Promotion,
  type PromotionCandidate,
  type Promotions
} from "@/features/system/api";
import { promotionState } from "@/features/system/promotionState";
import type { Translations } from "@/i18n/en";
import { useLocale, type Locale } from "@/i18n/LocaleContext";

/** What the promotions read answered. A failed read keeps the server's sentence, if one came. */
export type PromotionsRead =
  | { state: "loading" }
  | { state: "failed"; said: string | null }
  | { state: "ready"; promotions: Promotions };

type Copy = Translations["system"]["sharing"]["promotions"];

type ViewProps = {
  read: PromotionsRead;
  copy: Copy;
  locale: Locale;
  canWrite: boolean;
  /** The key or id of the row a request is in flight for, so only that button waits. */
  busy: string | null;
  /** The server's refusal of the last promote or withdraw, as its own sentence. */
  refusal: string | null;
  query: string;
  onQuery: (value: string) => void;
  onSearch: () => void;
  onPromote: (candidate: PromotionCandidate) => void;
  onWithdraw: (promotion: Promotion) => void;
};

/**
 * Promoted applications (#793) for one read; stateless, so the node lane renders it. Absent where the
 * area is off and nothing is promoted. With the area off and something promoted it still lists the
 * choices, says they are not being sent, and offers withdrawal: the flag stops the sending, never the undoing.
 */
export function PromotedAppsView(props: ViewProps) {
  const { read, copy, locale, canWrite, busy, refusal } = props;
  if (read.state === "loading") return null;
  if (read.state === "failed") {
    return (
      <p role="alert" className="text-sm text-destructive">
        {read.said ?? copy.loadFailed}
      </p>
    );
  }
  const { enabled, paused, items, candidates, moreCandidates, limit } = read.promotions;
  if (!enabled && items.length === 0) return null;
  const when = (at: string) => new Date(at).toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });

  return (
    <section className="space-y-3 rounded-lg border bg-card p-6" aria-label={copy.heading}>
      <h2 className="font-semibold">{copy.heading}</h2>
      <p className="text-sm text-muted-foreground">{copy.description}</p>
      <p className="text-sm text-muted-foreground">{copy.whatLeaves}</p>
      {paused !== null && <p className="text-sm font-medium">{copy.paused[paused]}</p>}
      {refusal && (
        <p role="alert" className="text-sm text-destructive">
          {refusal}
        </p>
      )}

      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{copy.none}</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">{copy.columnApp}</th>
                <th className="px-3 py-2 font-medium">{copy.columnBundle}</th>
                <th className="px-3 py-2 font-medium">{copy.columnInstalled}</th>
                <th className="px-3 py-2 font-medium">{copy.columnVersions}</th>
                <th className="px-3 py-2 font-medium">{copy.columnState}</th>
                <th className="px-3 py-2 font-medium">{copy.columnPromoted}</th>
                {canWrite && <th className="px-3 py-2" />}
              </tr>
            </thead>
            <tbody>
              {items.map((promotion) => (
                <tr key={promotion.id} className="border-b last:border-b-0">
                  <td className="px-3 py-2 font-medium">{promotion.appName}</td>
                  <td className="px-3 py-2 font-mono text-xs">{promotion.bundleId}</td>
                  <td className="px-3 py-2">{copy.devices(promotion.deviceCount)}</td>
                  <td className="px-3 py-2">{promotion.versionCount}</td>
                  <td className="px-3 py-2">{promotionState(promotion, paused, copy)}</td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {copy.promotedBy(when(promotion.promotedAt), promotion.promotedBy)}
                  </td>
                  {canWrite && (
                    <td className="px-3 py-2 text-right">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={busy !== null}
                        onClick={() => props.onWithdraw(promotion)}
                      >
                        {copy.withdraw}
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-xs text-muted-foreground">{copy.limit(items.length, limit)}</p>

      {enabled && (
        <div className="space-y-3 border-t pt-3">
          <h3 className="text-sm font-semibold">{copy.pickerHeading}</h3>
          <p className="text-sm text-muted-foreground">{copy.pickerHelp}</p>
          <form
            className="flex gap-2"
            onSubmit={(event: FormEvent) => {
              event.preventDefault();
              props.onSearch();
            }}
          >
            <input
              type="search"
              aria-label={copy.searchLabel}
              placeholder={copy.searchPlaceholder}
              className="w-full max-w-sm rounded-md border border-input bg-background px-3 py-1.5 text-sm"
              value={props.query}
              maxLength={100}
              onChange={(event) => props.onQuery(event.target.value)}
            />
            <Button type="submit" variant="outline" size="sm">
              {copy.search}
            </Button>
          </form>
          {candidates.length === 0 ? (
            <p className="text-sm text-muted-foreground">{copy.noCandidates}</p>
          ) : (
            <ul className="divide-y rounded-md border">
              {candidates.map((candidate) => (
                <li key={candidate.keyTitle} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
                  <span>
                    <span className="font-medium">{candidate.appName}</span>{" "}
                    <span className="font-mono text-xs text-muted-foreground">{candidate.bundleId}</span>
                    <span className="block text-xs text-muted-foreground">
                      {copy.devices(candidate.deviceCount)} · {candidate.known ? copy.knownTag : copy.unknownTag}
                      {candidate.excludedBy !== null && ` · ${copy.excludedTag(candidate.excludedBy)}`}
                    </span>
                  </span>
                  {canWrite && (
                    <Button
                      type="button"
                      size="sm"
                      // An excluded title is refused by the server; the page says why before the click.
                      disabled={busy !== null || candidate.excludedBy !== null || items.length >= limit}
                      onClick={() => props.onPromote(candidate)}
                    >
                      {copy.promote}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {moreCandidates > 0 && <p className="text-xs text-muted-foreground">{copy.moreCandidates(moreCandidates)}</p>}
        </div>
      )}
      {!canWrite && <p className="text-xs text-muted-foreground">{copy.readOnly}</p>}
    </section>
  );
}

/**
 * Settings › Data Sharing: the applications this organization sends by name (#793). `onChanged` tells the
 * page that what the next exchange carries has moved, so it can drop a preview that no longer shows it.
 */
export function PromotedApps({ canWrite, onChanged }: { canWrite: boolean; onChanged: () => void }) {
  const { t, locale } = useLocale();
  const copy = t.system.sharing.promotions;
  const [read, setRead] = useState<PromotionsRead>({ state: "loading" });
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);

  function load(search: string): Promise<void> {
    return listPromotions(search)
      .then((promotions) => setRead({ state: "ready", promotions }))
      .catch((caught: unknown) => setRead({ state: "failed", said: caught instanceof ApiError ? caught.detail : null }));
  }

  useEffect(() => {
    let live = true;
    listPromotions()
      .then((promotions) => {
        if (live) setRead({ state: "ready", promotions });
      })
      .catch((caught: unknown) => {
        if (live) setRead({ state: "failed", said: caught instanceof ApiError ? caught.detail : null });
      });
    return () => {
      live = false;
    };
  }, []);

  async function act(key: string, request: () => Promise<unknown>, failed: string) {
    setBusy(key);
    setRefusal(null);
    try {
      await request();
      onChanged();
    } catch (caught) {
      // A 409's detail is the refusal in the operator's words; anything else gets the page's own.
      setRefusal(caught instanceof ApiError && caught.detail ? caught.detail : failed);
    } finally {
      await load(query);
      setBusy(null);
    }
  }

  return (
    <PromotedAppsView
      read={read}
      copy={copy}
      locale={locale}
      canWrite={canWrite}
      busy={busy}
      refusal={refusal}
      query={query}
      onQuery={setQuery}
      onSearch={() => void load(query)}
      onPromote={(candidate) => void act(candidate.keyTitle, () => promoteApplication(candidate.keyTitle), copy.promoteFailed)}
      onWithdraw={(promotion) => void act(promotion.id, () => withdrawPromotion(promotion.id), copy.withdrawFailed)}
    />
  );
}
