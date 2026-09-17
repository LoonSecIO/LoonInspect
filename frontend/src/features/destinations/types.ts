export type DestinationType = "generic_webhook" | "splunk_hec" | "elastic" | "runreveal";
export type AuthType = "none" | "bearer" | "header" | "splunk_hec" | "elastic_api_key";

export interface Destination {
  id: number;
  name: string;
  type: DestinationType;
  url: string;
  authType: AuthType;
  authHeaderName: string | null;
  /** Elastic only: the index (or data stream) the bulk POST targets. Null means the
   *  backend's data-stream-friendly default. */
  elasticIndex: string | null;
  /** Whether a secret is stored — never the secret itself. There is no read path for
   *  it; the admin who set it typed it, so there's nothing to show back. */
  hasSecret: boolean;
  enabled: boolean;
  /** Null means "all event types" — the default, and how the legacy single-webhook
   *  setup behaved before destinations existed. */
  subscribedEvents: string[] | null;
  /** The most recent upstream refusal for this destination, read from the delivery
   *  rows. Null when nothing has failed. This is the diagnosis the delivery loop
   *  already wrote down and that nothing used to read back. */
  lastError: string | null;
  /** Deliveries still queued or mid-retry, and deliveries that exhausted their retries. */
  pendingCount: number;
  failedCount: number;
  /** `failedCount` is a lifetime count that a redrive zeroes; this is the same rows inside
   *  the trailing 24 hours — the window the nightly `outbox.failed_24h` counts fleet-wide.
   *  The pair is "has it ever failed" beside "is it failing now". */
  failed24h: number;
  /** When the oldest dead letter here stops being redrivable: its event is purged with it,
   *  and the gap it left in the trail is permanent after that. Null when there are none. */
  deadLetterOldestExpiresAt: string | null;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateDestinationInput {
  name: string;
  type: DestinationType;
  url: string;
  authType: AuthType;
  authHeaderName?: string | null;
  authSecret?: string | null;
  elasticIndex?: string | null;
  enabled: boolean;
}

export interface UpdateDestinationInput {
  name?: string;
  url?: string;
  authType?: AuthType;
  authHeaderName?: string | null;
  authSecret?: string | null;
  elasticIndex?: string | null;
  enabled?: boolean;
}

/** `GET /api/outbox` (#468). The three states are named once, in `app/schemas/outbox.py`, and
 *  this is their wire shape. Ages are null when a set is empty — never 0, which would read as
 *  "produced this second". */
export interface OutboxDepth {
  held: { events: number; oldestAgeSeconds: number | null; reason: "no_enabled_destination" | null };
  pending: { deliveries: number; oldestAgeSeconds: number | null };
  deadLettered: { deliveries: number; oldestExpiresAt: string | null };
  retention: { eventRetentionDays: number; deadLetterRetentionDays: number; nextPurgeAt: string };
}
