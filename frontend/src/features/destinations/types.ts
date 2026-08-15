export type DestinationType = "generic_webhook" | "splunk_hec";
export type AuthType = "none" | "bearer" | "header" | "splunk_hec";

export interface Destination {
  id: number;
  name: string;
  type: DestinationType;
  url: string;
  authType: AuthType;
  authHeaderName: string | null;
  /** Whether a secret is stored — never the secret itself. There is no read path for
   *  it; the admin who set it typed it, so there's nothing to show back. */
  hasSecret: boolean;
  enabled: boolean;
  /** Null means "all event types" — the default, and how the legacy single-webhook
   *  setup behaved before destinations existed. */
  subscribedEvents: string[] | null;
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
  enabled: boolean;
}

export interface UpdateDestinationInput {
  name?: string;
  url?: string;
  authType?: AuthType;
  authHeaderName?: string | null;
  authSecret?: string | null;
  enabled?: boolean;
}
