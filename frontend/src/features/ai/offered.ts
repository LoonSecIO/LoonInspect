import type { HostDetection, Provider, ProviderEntry } from "@/features/ai/api";
import { PROVIDER_ORDER, type SavedByProvider } from "@/features/ai/savedState";

/**
 * Which cards Settings › AI offers, and what an unsaved one fills in (#404, #474).
 *
 * Host detection used to be a hint and never a gate. For the card list it is now a gate
 * (Kyle, 2026-09-12: the Apple card *"should not show in AWS"* — the pod offered it with no
 * Mac anywhere near it, and filled the OpenAI-compatible card with the Mac host's Ollama
 * pair under the page's own evidence line saying that name does not resolve; the record of
 * what that cost is `docs/ai-layer.md`). The Apple card is offered where its default can
 * work — Docker Desktop on an Apple Silicon Mac, with the alias resolving from inside this
 * container — or where this server holds settings for it (#474). Where neither holds it is
 * withheld and the detection panel says why in one sentence — and the Apple setup link and
 * the unsupported-runtime line go with the card, so nothing left on the page points at it —
 * which is how a Mac operator whose detection missed tells a withheld card from a missing
 * feature (`docs/diagnosability.md` rule 1, `docs/troubleshooting.md` §14). Detection stays
 * a hint for which offered card opens selected, and it gates nothing in the backend: a call
 * naming `apple_fm` is judged, gated and logged like any other, wherever this runs.
 *
 * The two cut opposite ways: a card is offered where the reading proves its default can work
 * or this server holds settings for it, a default withheld only where the reading proves it
 * cannot. Before the read there is neither.
 */

/** The name every local default on this page is written against. Docker Desktop supplies
 *  it, and `docker-compose.yml` declares it for other engines; `ops/aws` supplies nothing
 *  of the kind. A live reading names it too, in `alias`. */
export const HOST_ALIAS = "host.docker.internal";

/** What the two decisions read, and `null` until `GET /api/system/ai/host` has settled. */
export type DetectionReading = Pick<HostDetection, "alias" | "aliasResolves" | "dockerDesktopOnMacos"> | null;

/** The cards the page offers, in the order it shows them, from the reading and the cards
 *  this server holds settings for. The Apple card's default needs both halves of its reach:
 *  Docker Desktop on an Apple Silicon Mac (`fm serve` runs on the Mac, never in the
 *  container) and the alias resolving, which is how the container gets to the Mac.
 *
 *  A saved `apple_fm` offers the card wherever this runs (Kyle's R9 default, 2026-09-16,
 *  #474). That is not a claim it can work here: the backend judges a saved card wherever it
 *  is, so a row restored from a Mac onto a pod keeps the Changes Prompt bar dialling it and
 *  naming it — and taking the card off the page took **Remove** off with it, leaving a
 *  `curl` in the troubleshooting guide as the only way out of a state the UI reaches by a
 *  button in every other case. A card on screen for that reason alone says so on itself
 *  (`AISettingsPage.tsx`); the reading, not this, still decides what a card fills in.
 *
 *  The other two are offered everywhere — one takes any URL, the other a public endpoint. */
export function offeredProviders(detection: DetectionReading, saved: SavedByProvider): readonly Provider[] {
  const appleWorks = detection !== null && detection.dockerDesktopOnMacos && detection.aliasResolves;
  const appleOffered = appleWorks || saved.apple_fm !== undefined;
  return appleOffered ? PROVIDER_ORDER : PROVIDER_ORDER.filter((candidate) => candidate !== "apple_fm");
}

/** Whether a card's own default base URL is written against the alias while the alias does
 *  not resolve here. Then the card starts empty rather than filled with a name this
 *  container cannot reach, and the Base URL field says so. */
export function localDefaultWithheld(entry: Pick<ProviderEntry, "baseUrl">, detection: DetectionReading): boolean {
  if (detection === null || detection.aliasResolves) return false;
  return entry.baseUrl.includes(detection.alias || HOST_ALIAS);
}

/** What an unsaved card fills in: the card's own defaults, except where they only work
 *  where the alias does. Then neither field is filled — the model that goes with a local
 *  URL is as local as the URL (Ollama's `qwen3.5:2b-mlx`, `fm serve`'s `system`), and a
 *  model on its own names nothing to send it to. The Anthropic card is never touched: its
 *  default is a public endpoint. A saved card is not defaults — it comes back as saved. */
export function providerDefaults(
  entry: Pick<ProviderEntry, "baseUrl" | "model">,
  detection: DetectionReading
): { baseUrl: string; model: string } {
  if (localDefaultWithheld(entry, detection)) return { baseUrl: "", model: "" };
  return { baseUrl: entry.baseUrl, model: entry.model };
}
