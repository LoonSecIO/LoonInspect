import { ApiError } from "@/config/api";
import type { Provider, SavedConfig } from "@/features/ai/api";
import { providerLabel } from "@/features/changes/prompt";
import type { PromptStatus } from "@/features/changes/types";
import type { Translations } from "@/i18n/en";

/**
 * Settings › AI's saved cards and its line about the Changes Prompt bar, as the page holds
 * them, and how a Remove moves them — kept out of the page so the node-only test lane can
 * hold the transitions to one rule: what the page shows follows the server's latest known
 * truth, and nothing the page no longer knows is left on screen as if it did.
 */

type AIStrings = Translations["ai"];

/** The three cards, in the order the page shows them and the server lists saved ones. */
export const PROVIDER_ORDER: readonly Provider[] = ["apple_fm", "openai_compatible", "anthropic"];

export type SavedByProvider = Partial<Record<Provider, SavedConfig>>;

export function byProvider(configs: SavedConfig[]): SavedByProvider {
  const saved: SavedByProvider = {};
  for (const config of configs) saved[config.provider] = config;
  return saved;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Whether `GET /api/system/ai/configs` answered with a list of saved cards — the fields
 *  the page reads, checked before it reads them. Anything else is an answer that could not
 *  be read, never an empty list: that would take every Saved pill away on a bad body. */
export function isSavedConfigList(value: unknown): value is SavedConfig[] {
  return (
    Array.isArray(value) &&
    value.every(
      (config) =>
        isRecord(config) &&
        typeof config.provider === "string" &&
        typeof config.baseUrl === "string" &&
        typeof config.model === "string" &&
        (config.reasoningEffort === null || typeof config.reasoningEffort === "string") &&
        typeof config.hasKey === "boolean"
    )
  );
}

/** The saved cards out of a `GET /api/system/ai/configs` body, or null when the body is not
 *  `{ configs: [...] }` — JSON null, a proxy's own JSON, another shape. `listConfigs` hands
 *  the body over unread, so a bad one lands here and reads as an answer that could not be
 *  read, never as a server that did not answer. */
export function savedConfigsOf(body: unknown): SavedConfig[] | null {
  return isRecord(body) && isSavedConfigList(body.configs) ? body.configs : null;
}

/**
 * The card the page moves to when the row of cards changes under it, or null to stay on the
 * one it is on. Since #474 the row follows the saved cards, so the page's own card can leave
 * it: a Remove of a card that was on the row only because this server held settings for it
 * takes that card off the row as the server answers. Left there, the page sits on a card no
 * radio can light, over an editor nothing on screen names, under the panel's sentence saying
 * that card is not offered here — with a Save that would write the settings straight back
 * and a Send that would dial them. So it moves: to the first card still on the row that this
 * server holds settings for — the one the Changes Prompt bar uses — else to the first card
 * on the row.
 *
 * A card still on the row is kept, and says so with `null`: nothing moves under an operator
 * who did not ask it to.
 */
export function cardAfterOffer(current: Provider, offered: readonly Provider[], saved: SavedByProvider): Provider | null {
  if (offered.length === 0 || offered.includes(current)) return null;
  return offered.find((candidate) => saved[candidate]) ?? offered[0];
}

/**
 * Where Settings › AI opens once its first reads settle, and whether it starts with clean
 * lines. `latest` is the newest saved map the page knows — never the list the opening read
 * of the saved cards returned, which may be older. While that read is still the newest, the
 * page opens on the first saved card (the one the Prompt bar uses) or, with none saved, on
 * the detection hint: the Apple card where it is offered, otherwise the documented default
 * (Ollama, #28).
 *
 * It opens only on a card that is on screen (`offered`, #404): one not on screen would be
 * selected with no card lit and no Remove to reach it. Since #474 `offered` holds every card
 * this server has settings for, wherever it runs, so the case that used to need this rule —
 * an Apple card saved on a Mac and restored onto a pod — now opens on a lit card with a
 * Remove on it. The rule stays for the cards a reading withholds and nothing has saved.
 *
 * The operator can get to the card first: Remove works before the page's other reads
 * settle, since it needs only the saved cards. `newerRead` — a Remove made while the host
 * detection was still out re-read the saved cards, so the opening read is superseded;
 * `removeAsked` — Remove was pressed, its confirm open or its DELETE out, before any re-read.
 * Either way the page stays on the card it is on, and the Remove's confirm or the line
 * saying what it did stays. Re-selecting from the opening read put the removed card back
 * and wiped that line. Unless that Remove took the card off the row (#474) — then staying is
 * not on offer, and the page moves as `cardAfterOffer` says, while the line still stays: it
 * is about what just happened, not about the card now showing.
 */
export function openingCard(opening: {
  newerRead: boolean;
  removeAsked: boolean;
  latest: SavedByProvider;
  current: Provider;
  offered: readonly Provider[];
}): { card: Provider; clearLines: boolean } {
  if (opening.newerRead || opening.removeAsked) {
    return { card: cardAfterOffer(opening.current, opening.offered, opening.latest) ?? opening.current, clearLines: false };
  }
  const firstSaved = opening.offered.find((candidate) => opening.latest[candidate]);
  return { card: firstSaved ?? (opening.offered.includes("apple_fm") ? "apple_fm" : "openai_compatible"), clearLines: true };
}

/** Whether a card takes a reasoning effort. Apple's does not: `fm serve` answers 400 to any
 *  `reasoning_effort` on its "system" model, "none" included, and this server refuses one
 *  on the Apple card with a 422 before it dials anything. So the page never offers it there. */
export function takesReasoningEffort(provider: Provider): boolean {
  return provider !== "apple_fm";
}

/** The Reasoning effort a card opens with: what was saved for it, else the card's default;
 *  and on the Apple card nothing, whatever an older save carried. */
export function cardEffort(provider: Provider, saved: SavedConfig | undefined, cardDefault: string | null): string {
  if (!takesReasoningEffort(provider)) return "";
  return (saved ? saved.reasoningEffort : cardDefault) ?? "";
}

/** `reasoningEffort` for a Send or a Save. Blank is the endpoint's default (null). On the
 *  Apple card it is undefined, so the key is left out of the body altogether — never sent. */
export function effortToSend(provider: Provider, chosen: string): string | null | undefined {
  if (!takesReasoningEffort(provider)) return undefined;
  return chosen ? chosen : null;
}

/** What the server said to a Remove: 204, 404 (someone removed it first), or anything else. */
export type RemoveAnswer = { kind: "removed" } | { kind: "absent" } | { kind: "failed"; sentence: string };

export const REMOVED: RemoveAnswer = { kind: "removed" };

/** A rejected `DELETE /api/system/ai/configs/{provider}`, read. A 404 means the goal is
 *  met — another tab or admin got there first — so it is not a failure. */
export function removeAnswer(error: unknown, fallback: string): RemoveAnswer {
  if (error instanceof ApiError && error.status === 404) return { kind: "absent" };
  return { kind: "failed", sentence: error instanceof ApiError && error.detail ? error.detail : fallback };
}

/** The saved map as soon as the Remove is answered. A 204 or a 404 is the server saying
 *  the card is gone, so its pill and its Remove go now, whatever the re-read does; any
 *  other answer leaves the map for the re-read to settle. */
export function savedAfterAnswer(saved: SavedByProvider, provider: Provider, answer: RemoveAnswer): SavedByProvider {
  if (answer.kind === "failed" || saved[provider] === undefined) return saved;
  const next = { ...saved };
  delete next[provider];
  return next;
}

/**
 * The line under the buttons once the re-read of the saved cards settles. `reread` is the
 * map the server returned, or null when that read failed (it reports itself, in its own
 * line). A Remove that failed as far as its answer goes — a 500 after the commit, a
 * connection dropped on the way back — but whose card the re-read no longer finds did
 * remove it, and says so rather than report a failure beside a card already gone.
 */
export function removeLine(
  provider: Provider,
  answer: RemoveAnswer,
  reread: SavedByProvider | null,
  words: Pick<AIStrings, "removedNotice" | "alreadyRemoved">
): { notice: string | null; error: string | null } {
  if (answer.kind === "removed") return { notice: words.removedNotice, error: null };
  if (answer.kind === "absent") return { notice: words.alreadyRemoved, error: null };
  if (reread !== null && reread[provider] === undefined) return { notice: words.removedNotice, error: null };
  return { notice: null, error: answer.sentence };
}

/** Settings › AI's last read of whether the Prompt bar shows: the status, or the sentence
 *  for why the read failed. Null before a read has settled — then the page says nothing. */
export type StatusReading = { status: PromptStatus } | { failure: string } | null;

/** The status once a Remove is answered. A line naming a provider the server has just said
 *  is gone ("shown (uses …)") is no longer known, so it goes until the re-read replaces it —
 *  with the new status, or with the sentence saying the status could not be re-read. */
export function statusAfterAnswer(reading: StatusReading, provider: Provider, answer: RemoveAnswer): StatusReading {
  if (answer.kind === "failed" || reading === null || !("status" in reading)) return reading;
  return reading.status.providers.some((saved) => saved.provider === provider) ? null : reading;
}

/** The line above the cards: whether the Changes Prompt bar shows, and if not, which of
 *  the flag, the consent or a saved card it waits on — or why that could not be read. */
export function statusLine(
  reading: StatusReading,
  words: Pick<AIStrings, "promptBarShown" | "promptBarHidden" | "promptBarHiddenBare" | "promptBarReasons" | "providerLabels">
): { text: string; failed: boolean } | null {
  if (reading === null) return null;
  if ("failure" in reading) return { text: reading.failure, failed: true };
  const { status } = reading;
  if (status.available && status.providers.length > 0) {
    return {
      text: words.promptBarShown(providerLabel(status.providers[0].provider, words.providerLabels), status.providers.length),
      failed: false
    };
  }
  const text = status.reason ? words.promptBarHidden(words.promptBarReasons[status.reason]) : words.promptBarHiddenBare;
  return { text, failed: false };
}
