import type { DeviceChange, UserFilter } from "@/features/changes/types";

/** The assigned person on the change feed's URL (#446, R13 option a). The person is a dimension
 *  stamped on a change row (#447) and the one whose filter value travels: an operator pastes the
 *  feed's URL into Slack. So the URL carries `user=u_…`, the keyed token the backend stamps
 *  beside the names, and the page turns it back into a name only on screen. */

/** The backend's shape (`app.changes.person_token`). Only the prefix matters here: this decides
 *  what to *show*, and what to *match* is the server's business. */
const isToken = (value: string) => value.startsWith("u_");

/** What a click on a row's person applies: the token, never the name. A row derived before the
 *  stamp existed carries none, and then there is nothing to press. */
export function rowUserToken(row: DeviceChange): string | undefined {
  const token = row.deviceMeta?.userToken;
  return typeof token === "string" && token ? token : undefined;
}

/** The person as the row itself names them — what that press reads as. */
export function rowUserName(row: DeviceChange): string | undefined {
  for (const key of ["realName", "username", "email"] as const) {
    const value = row.deviceMeta?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

/** The `user` value the URL should carry, or null to leave it alone: typed text the response
 *  resolved to one person becomes that person's token, so the link copied a moment later has no
 *  name in it, while text matching two people is still the question that was asked. */
export function userTokenRewrite(applied: string | undefined, resolved: UserFilter | null | undefined): string | null {
  if (!applied || !resolved?.token || resolved.token === applied) return null;
  return resolved.token;
}

export interface UserChipWords { named: (name: string) => string; matching: (value: string) => string; unresolved: string }

/** What the chip says — never the token, which names nobody a reader can recognise. One the
 *  server could not resolve (a rotated key, rows older than the stamp) reads as the page's words
 *  for a person it cannot name, the empty table below saying the rest. */
export function userChipLabel(applied: string, resolved: UserFilter | null | undefined, words: UserChipWords): string {
  if (!isToken(applied)) return words.matching(applied);
  return resolved?.token === applied && resolved.display ? words.named(resolved.display) : words.unresolved;
}
