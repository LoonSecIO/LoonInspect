/** Where a person with a problem is sent, in one place.
 *
 *  Every URL here derives from a single repository slug so a typo in the org name
 *  cannot exist in one link and not another, and so the flip-day check (#26, Phase 3
 *  — "these links resolve") has one constant to read rather than five string literals
 *  spread through JSX. Pure data and one pure function: no React, no fetch, nothing
 *  that needs a DOM. This is the module the frontend test runner (#285) should aim at
 *  for this feature.
 *
 *  These GitHub URLs 404 until the repository goes public (#26). That is deliberate:
 *  the reverse — flipping public with no support path in the product — is the failure
 *  this page exists to prevent, and no external user exists before the flip.
 */

/** The repository. Public from the flip; the only source of the three GitHub URLs. */
export const SUPPORT_REPO = "LoonSecIO/LoonInspect";

/** MacAdmins Slack is a separate community with its own signup, so the join page is
 *  the first of the two links. A deep link to the channel is useless to a reader with
 *  no account, which is most readers the first time they need this page. */
const MACADMINS_JOIN = "https://macadmins.org/";

/** …and the channel itself, for the reader who is already in that workspace and
 *  should not have to go back through the front door to find one channel. Both are
 *  shown, which is the ruling: the join page for the account-less reader, the channel
 *  for everyone else (#301). */
const MACADMINS_CHANNEL = "https://macadmins.slack.com/channels/loonsecio";

/** The community channel inside that workspace. Rendered as an identifier, never
 *  translated. */
export const SLACK_CHANNEL = "#loonsecio";

/** The fallback SECURITY.md already publishes. Nothing on this page adds an address
 *  the policy does not already carry. */
export const SECURITY_EMAIL = "security@loonsec.io";

const GITHUB = `https://github.com/${SUPPORT_REPO}`;

export const SUPPORT_LINKS = {
  /** Read before writing: the answer is often already filed. */
  issues: `${GITHUB}/issues`,
  newIssue: `${GITHUB}/issues/new`,
  /** GitHub private vulnerability reporting — Security → Report a vulnerability.
   *  Never the public tracker: SECURITY.md rules this and the page repeats it. */
  privateReport: `${GITHUB}/security/advisories/new`,
  /** GitHub's rendering of SECURITY.md, which survives the file moving. */
  securityPolicy: `${GITHUB}/security/policy`,
  slackJoin: MACADMINS_JOIN,
  slackChannel: MACADMINS_CHANNEL
} as const;

/** What the copy button puts on the clipboard, or null when there is nothing worth
 *  copying. `useBuildVersion` answers null both while the request is in flight and
 *  after it fails, and a stray whitespace-only build string would otherwise arm a
 *  button that silently copies nothing. */
export function copyableBuild(version: string | null | undefined): string | null {
  const trimmed = version?.trim() ?? "";
  return trimmed === "" ? null : trimmed;
}
