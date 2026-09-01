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
