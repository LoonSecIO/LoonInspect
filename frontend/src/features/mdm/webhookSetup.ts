/**
 * The decisions behind the webhook setup panel (#406), kept out of the component so the
 * node test lane can pin them (frontend/vitest.config.ts runs pure modules only).
 *
 * The panel answers the three things Jamf Pro's webhook form asks for — the address to
 * post to, the header to authenticate with, and which events — plus whether this side
 * is receiving at all. The secret is made here, in the browser, and travels to the
 * server exactly once, in the PATCH that saves it: no response ever carries it back
 * (docs/auth-design.md §4.7, ruled by Kyle 2026-09-12 on #406).
 */

import type { MdmConnection } from "@/features/mdm/types";

/** The header Jamf Pro sends; the one `backend/app/api/webhooks.py` reads first. */
export const WEBHOOK_HEADER_NAME = "X-API-Key";

/** The two events LoonInspect acts on — `REACTIVE_WEBHOOK_EVENTS` in
 *  backend/app/mdm/jamf/client.py — in the order the guide sets them up. A Jamf webhook
 *  carries one event, so these are two webhooks. */
export const WEBHOOK_EVENTS = ["ComputerInventoryCompleted", "ComputerAdded"] as const;

/** The Jamf Pro side, step by step. */
export const JAMF_WEBHOOKS_GUIDE = "https://github.com/LoonSecIO/LoonInspect/blob/main/docs/jamf-webhooks.md";

/** Bytes of randomness in a generated secret — the 32 the document used to ask admins
 *  to take from `openssl rand -base64 32`. */
export const SECRET_BYTES = 32;

/** Where the API answers, which is where the webhook endpoint lives too: the SPA's own
 *  origin unless the build points `VITE_API_BASE_URL` somewhere absolute. */
export function webhookOrigin(apiBaseUrl: string, pageOrigin: string): string {
  return new URL(apiBaseUrl, pageOrigin).origin;
}

/** The address a Jamf Pro webhook posts to. The secret never goes in it: a path segment
 *  ends up in proxy logs and anything else that records a URL (webhooks.py). */
export function webhookUrl(origin: string, connectionId: number): string {
  return `${origin.replace(/\/+$/, "")}/webhooks/jamf/${connectionId}`;
}

/** Why Jamf Pro may not be able to use the address as shown, most decisive first:
 *  `localhost` is never Jamf's to reach, a private address is reachable only from an
 *  on-premises Jamf Pro on the same network, and plain `http` would put the header —
 *  the whole authentication — on the wire in the clear. */
export type OriginWarning = "localhost" | "private" | "http";

export function originWarning(origin: string): OriginWarning | null {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127\./.test(host)) {
    return "localhost";
  }
  if (isPrivateHost(host)) return "private";
  if (url.protocol === "http:") return "http";
  return null;
}

function isPrivateHost(host: string): boolean {
  if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".lan") || host.endsWith(".home.arpa")) {
    return true;
  }
  // No dot at all is a single-label name, which only a local resolver answers.
  if (!host.includes(".") && !host.includes(":")) return true;
  const octets = host.split(".").map(Number);
  if (octets.length === 4 && octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
    const [a, b] = octets;
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  // IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
  return /^f[cd][0-9a-f]{2}:/.test(host) || /^fe[89ab][0-9a-f]:/.test(host);
}

/** What Jamf Pro's Header Authentication field takes: a JSON object of header names to
 *  values. Built with JSON.stringify, not a template, so a typed secret holding a quote
 *  or a backslash still yields an object Jamf can parse. */
export function headerObject(secret: string): string {
  return JSON.stringify({ [WEBHOOK_HEADER_NAME]: secret });
}

/** A new secret: SECRET_BYTES from the browser's CSPRNG, as unpadded base64url so it
 *  pastes into JSON and a header without escaping. `random` is the seam the tests use. */
export function generateSecret(
  random: (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer> = (bytes) => crypto.getRandomValues(bytes)
): string {
  const bytes = random(new Uint8Array(SECRET_BYTES));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The panel's status line, in the order the server refuses a webhook
 *  (`rejection_reason` in webhooks.py): each state names the one thing still missing. */
export type WebhookStatus = "inactive" | "off" | "noSecret" | "receiving";

export function webhookStatus(
  connection: Pick<MdmConnection, "isActive" | "capabilityWebhooks" | "hasWebhookSecret">
): WebhookStatus {
  if (!connection.isActive) return "inactive";
  if (!connection.capabilityWebhooks) return "off";
  if (!connection.hasWebhookSecret) return "noSecret";
  return "receiving";
}

/** What one save sends when receiving is switched. Turning it on without a secret
 *  brings a new one in the same request, so the page never produces the state where
 *  every webhook is refused; turning it off keeps the secret for the next time. */
export function receivePatch(
  on: boolean,
  hasWebhookSecret: boolean,
  newSecret: () => string = generateSecret
): { capabilityWebhooks: boolean; webhookSecret?: string } {
  if (on && !hasWebhookSecret) return { capabilityWebhooks: true, webhookSecret: newSecret() };
  return { capabilityWebhooks: on };
}
