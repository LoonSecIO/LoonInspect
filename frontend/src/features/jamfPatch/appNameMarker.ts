/** What the Jamf Patch surfaces say about a title's app name, and nothing else (#478).
 *
 *  Jamf leaves the top-level `appName` null on 513 of its 1,553 titles — every versioned
 *  line, "Wireshark 4.2" among them — and #385 takes the name out of the patches' own
 *  `killApps` for the title's bundle ID, stamping `appNameSource`. A derived name is a
 *  **possible miss, never a wrong key** (`docs/app-catalog.md` §2a), which is not the same
 *  confidence as a name Jamf published, so the page says which it is looking at.
 *
 *  Four answers, and the two silent ones are the point:
 *  - `derived` — a name read out of the patch definition. The only annotated case.
 *  - `unnamed` — nothing names an app for this title, so it has no app name to show and
 *    its versions carry no content keys. Said in words rather than left as a blank cell.
 *  - `plain` — the ordinary case: a name, shown as a fact. A `jamf` source, and equally a
 *    source this build has never heard of, because an annotation nobody can read is worse
 *    than none.
 *  - `none` — no name and no claim: a row written before the rule existed (`appNameSource`
 *    null), which `_needs_refresh` re-reads exactly once.
 */
export type AppNameMarker = "derived" | "unnamed" | "plain" | "none";

export function appNameMarker(title: { appName: string | null; appNameSource: string | null }): AppNameMarker {
  const name = (title.appName ?? "").trim();
  // No name is not a claim about a name: only the source that says so may speak.
  if (name === "") return title.appNameSource === "unnamed" ? "unnamed" : "none";
  return title.appNameSource === "kill_apps" ? "derived" : "plain";
}
