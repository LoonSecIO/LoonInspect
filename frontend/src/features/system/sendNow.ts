/** Send now (#408), the parts of the page that are decisions rather than markup: whether
 *  the button shows, and when it cannot send, which reason the page says under it. Kept
 *  pure so the frontend lane (#285) can pin every state (docs/diagnosability.md rule 1). */

import type { DataSharingSettings } from "@/features/system/api";

/** `hidden`: the role cannot send, and the read-only notice already says what it can do.
 *  `blockedEnv` / `blockedOff`: shown, disabled, with the reason beneath. `ready`: a click
 *  sends, and only "an exchange is already running" is left for the server to say. */
export type SendNowAvailability = "hidden" | "blockedEnv" | "blockedOff" | "ready";

export function sendNowAvailability(
  settings: Pick<DataSharingSettings, "tier" | "envDisabled">,
  canWrite: boolean
): SendNowAvailability {
  if (!canWrite) return "hidden";
  // The override first, as the server checks it first: it is the stronger reason — with
  // it set, choosing a tier would still send nothing.
  if (settings.envDisabled) return "blockedEnv";
  if (settings.tier === "off") return "blockedOff";
  return "ready";
}

/** The host a row was sent to, for the result's lead sentence. The row carries the whole
 *  endpoint; an operator reads the host, and a value that is not a URL is shown as is. */
export function endpointHost(endpoint: string): string {
  try {
    return new URL(endpoint).hostname || endpoint;
  } catch {
    return endpoint;
  }
}
