/**
 * Is what somebody typed an id, and where does an id go (#533)? The pattern mirrors `_ALLOWED_ID`
 * (`backend/app/core/vuln.py`) term for term — the two namespaces §5 mints — and is **not widened
 * here**: `LOCAL-` is reserved and nothing LoonInspect ships mints one, a `GHSA-` id belongs to
 * neither, and both stay search text in the box rather than becoming a refusal on a route.
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

/** Where a key pressed in the search box goes — **the id it holds, on Enter, and nowhere on any
 *  other keystroke**. Typing is not asking: the sequence number is open-ended, so `CVE-2025-1162` is
 *  a whole id on the way to `CVE-2025-11626`, and routing on change left for a page about a
 *  different id at the thirteenth character. The reader says when the id is finished. */
export function findingRoute(key: string, query: string): string | null {
  const id = key === "Enter" ? findingIdIn(query) : null;
  return id === null ? null : findingPath(id);
}

/** Where the id goes next, for a `CVE-` id alone, and only for a shape the server would accept —
 *  a hand-edited URL reaches this page too. **The reader's browser makes that call and this
 *  container makes none** (§2). A `LoonVD-` id links nowhere: ours, resolvable nowhere else. */
export function nvdDetail(id: string): string | null {
  const finding = findingIdIn(id);
  return finding?.startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${finding}` : null;
}
