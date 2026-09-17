/**
 * Is what somebody typed an id, and where does an id go (#533)?
 *
 * The pattern mirrors `_ALLOWED_ID` (`backend/app/core/vuln.py`) term for term — the two
 * namespaces §5 mints — and is **not widened here**: `LOCAL-` is reserved and nothing
 * LoonInspect ships mints one, a `GHSA-` id belongs to neither, and both stay search text in
 * the box rather than becoming a refusal on a route. Case is the backend's case.
 */
const FINDING_ID = /^(CVE-\d{4}-\d{4,}|LoonVD-\d{4}-\d{6})$/;

/** The id a query is, or `null` for a query that is search text. */
export function findingIdIn(query: string): string | null {
  const value = query.trim();
  return FINDING_ID.test(value) ? value : null;
}

/** Where an id is answered: its own page, never a filter on a list of builds. */
export function findingPath(id: string): string {
  return `/posture/vulnerabilities/${encodeURIComponent(id)}`;
}

/** Where the id goes next, for a `CVE-` id alone. **The reader's browser makes that call and
 *  this container makes none** (§2): an id query from a customer's pod would tell NIST what
 *  that fleet runs. A `LoonVD-` id links nowhere — ours, and resolvable nowhere else. */
export function nvdDetail(id: string): string | null {
  return id.startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${id}` : null;
}
