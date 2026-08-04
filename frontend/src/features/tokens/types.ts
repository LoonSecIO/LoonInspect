export interface ApiToken {
  id: string;
  name: string;
  scopes: string[];
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
}

/** Only ever returned by the create call. `token` is the raw secret and is not
 *  recoverable afterwards — the server stored only its hash. */
export interface ApiTokenCreated extends ApiToken {
  token: string;
}

export interface CreateTokenInput {
  name: string;
  scopes: string[];
  expiresInDays: number | null;
}
