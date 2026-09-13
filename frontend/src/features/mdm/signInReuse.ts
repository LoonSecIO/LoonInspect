/**
 * Sign-in reuse (#412): what a connection keeps of its Jamf Pro sign-in between runs.
 * Kept out of the form so the node test lane can pin the ruling — three modes, in this
 * order, and Cache and hold the default (Kyle, 2026-09-12). The backend's side is
 * backend/app/mdm/jamf/sign_in.py; its column is held to the same three words.
 */

import type { MdmConnection, TokenCacheMode } from "@/features/mdm/types";

/** Least kept to most: the order the form lists them in. */
export const TOKEN_CACHE_MODES: readonly TokenCacheMode[] = ["no_cache", "cache_and_hold", "perpetual"];

export const DEFAULT_TOKEN_CACHE_MODE: TokenCacheMode = "cache_and_hold";

/** The mode a form starts on: the connection's own, or the default for a new one. */
export function tokenCacheModeOf(connection?: Pick<MdmConnection, "tokenCacheMode"> | null): TokenCacheMode {
  return connection?.tokenCacheMode ?? DEFAULT_TOKEN_CACHE_MODE;
}
