import type { HostDetection, Provider, ProviderEntry } from "@/features/ai/api";
import { PROVIDER_ORDER } from "@/features/ai/savedState";

/**
 * Which cards Settings › AI offers, and what an unsaved one fills in (#404).
 *
 * Host detection used to be a hint and never a gate: every card was offered everywhere,
 * and a full match only decided which one opened selected. On the AWS pod that offered
 * "Apple Foundation Models via Docker Desktop" with no Mac anywhere near it, and filled
 * the OpenAI-compatible card with the Mac host's Ollama pair — a `host.docker.internal`
 * base URL directly under the page's own evidence line saying that name does not resolve.
 * Sending it wrote a share-log row naming a destination nothing could answer, then failed
 * with `Name or service not known`.
 *
 * So for the card list detection is now a gate (Kyle, 2026-09-12: the Apple card *"should
 * not show in AWS"*). The Apple card is offered only where its default can work: Docker
 * Desktop on an Apple Silicon Mac, with the alias resolving from inside this container.
 * Everywhere else it is withheld and the detection panel says why in one sentence, so a
 * Mac operator whose detection missed can tell a withheld card from a missing feature
 * (`docs/diagnosability.md` rule 1, `docs/troubleshooting.md` §14). Detection stays a hint
 * for which offered card opens selected, and it gates nothing in the backend: a call
 * naming `apple_fm` is judged, gated and logged like any other, wherever this runs.
 *
 * Both decisions act on the reading, which cuts opposite ways: a card is offered only where
 * the reading proves its default can work, and a default is withheld only where it proves it
 * cannot. Before the host read settles there is neither a reading nor anything filled in.
 */

/** The name every local default on this page is written against. Docker Desktop supplies
 *  it, and `docker-compose.yml` declares it for other engines; `ops/aws` supplies nothing
 *  of the kind. A live reading names it too, in `alias`. */
export const HOST_ALIAS = "host.docker.internal";

/** What the two decisions read, and `null` until `GET /api/system/ai/host` has settled. */
export type DetectionReading = Pick<HostDetection, "alias" | "aliasResolves" | "dockerDesktopOnMacos"> | null;

/** The cards the page offers, in the order it shows them. The Apple card needs both halves
 *  of its reach: Docker Desktop on an Apple Silicon Mac (`fm serve` runs on the Mac, never
 *  in the container) and the alias resolving, which is how the container gets to the Mac.
 *  The other two are offered everywhere — one takes any URL, the other a public endpoint. */
export function offeredProviders(detection: DetectionReading): readonly Provider[] {
  const appleWorks = detection !== null && detection.dockerDesktopOnMacos && detection.aliasResolves;
  return appleWorks ? PROVIDER_ORDER : PROVIDER_ORDER.filter((candidate) => candidate !== "apple_fm");
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
