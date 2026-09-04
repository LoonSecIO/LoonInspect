import type { ChangePolicy, DeviceChange } from "@/features/changes/types";

/**
 * How a change row is turned into words — shared by the Changes table and the Overview
 * feed, which rendered it twice and identically until #307.
 *
 * The rule the whole module exists to keep: **a row's value columns show the fields that
 * moved, never the entry they moved inside.** `derive.py` stores the whole canonical
 * entry body as `old_value`/`new_value` and stores `details.changedFields` beside it, so
 * the fields are already named; printing the bodies instead put an app's version off the
 * right-hand edge of a truncated cell while the two cells stayed identical for their
 * entire visible width.
 */

/**
 * The section vocabulary, in the order the policy document presents it: the eight scalar
 * sections `FIELD_RULES` covers, then the seven list sections `ENTRY_RULES` covers
 * (`backend/app/changes/policy.py`). Fifteen names — `SECTIONS` in
 * `backend/app/mdm/jamf/contract.py`, plus `definition`, which is a smart group's own
 * record and has no inventory section behind it.
 *
 * Deliberately a constant rather than a read of the policy document, which carries the
 * same list. A dropdown built from a fetch is empty while that fetch is in flight and
 * empty forever if it fails, and an empty filter control tells the same lie an empty feed
 * does (#150). The field *labels* below do come from that fetch, because their failure
 * mode is a raw field name rather than a missing control.
 */
export const SECTION_ORDER = [
  "general",
  "hardware",
  "operating_system",
  "user_and_location",
  "purchasing",
  "security",
  "disk_encryption",
  "definition",
  "applications",
  "extension_attributes",
  "group_memberships",
  "configuration_profiles",
  "local_user_accounts",
  "certificates",
  "software_updates"
] as const;

/**
 * Field labels, keyed by where the field lives. Scalar fields and entry fields are
 * namespaced apart because `applications` (a section) and `application` (an entry kind)
 * are one letter and one meaning apart.
 */
export type LabelMap = Record<string, string>;

const fieldKey = (section: string, field: string) => `field:${section}.${field}`;
const entryKey = (kind: string, field: string) => `entry:${kind}.${field}`;

/** Every label the policy document carries, flattened into one lookup. */
export function labelsFromPolicy(policy: ChangePolicy): LabelMap {
  const labels: LabelMap = {};
  for (const section of policy.sections) {
    for (const f of section.fields) labels[fieldKey(section.section, f.field)] = f.label;
  }
  for (const entry of policy.entries) {
    for (const f of entry.fields) labels[entryKey(entry.kind, f.name)] = f.label;
  }
  return labels;
}

/**
 * The value of one leaf. `null` means "nothing here" and is the caller's to render — as
 * an em dash on one side of a pair, or as an omission.
 */
export function scalarText(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  // An extension attribute's `values` is a sorted list, not a scalar (`contract.py`), and
  // so are the handful of string lists the scalar sections carry.
  if (Array.isArray(value)) return value.length ? value.map(String).join(", ") : null;
  if (typeof value === "object") return JSON.stringify(value);
  const text = String(value);
  return text === "" ? null : text;
}

/** The `{ "value": … }` envelope `_wrap` puts around a scalar field change. */
function unwrap(value: Record<string, unknown> | null): unknown {
  if (value === null) return null;
  if ("value" in value && Object.keys(value).length === 1) return value.value;
  return value;
}

/** One thing that moved. */
export interface DiffLine {
  key: string;
  /** `null` when the What column already names the field, so the line is the pair alone. */
  label: string | null;
  from: string | null;
  to: string | null;
  /**
   * Whether this line is a before/after pair. An entry that appeared or vanished whole is
   * not: there is no other side, and an arrow pointing at an em dash would invent one.
   */
  pair: boolean;
}

/**
 * The two or three fields that say *which* entry appeared or vanished, per kind. Identity
 * fields are omitted — the What column is already showing those — and so is everything
 * else in the body, which is the blob this issue exists to stop printing.
 */
const SUMMARY_FIELDS: Record<string, readonly string[]> = {
  application: ["version", "bundleId"],
  extension_attribute: ["values"],
  group_membership: ["smartGroup"],
  configuration_profile: ["profileIdentifier"],
  local_user_account: ["fullName", "admin"],
  // The fingerprint is the identity and is already in the What column; the common name is
  // the only human-readable thing a certificate has, and it lives in the body.
  certificate: ["commonName", "expirationDate"],
  software_update: ["version", "packageName"]
};

/**
 * What changed, as lines. Empty when the row has nothing to show a pair for — the
 * collapsed-system-apps row, which carries a count and no entry at all, and whose
 * sentence belongs to `detailText`.
 */
export function diffLines(row: DeviceChange, labels: LabelMap = {}): DiffLine[] {
  // A scalar field change. The What column already names the field, so the line is the
  // pair alone.
  if (row.field) {
    return [
      {
        key: row.field,
        label: null,
        from: scalarText(unwrap(row.oldValue)),
        to: scalarText(unwrap(row.newValue)),
        pair: true
      }
    ];
  }

  const kind = row.entryKind;
  if (!kind) return [];

  if (row.change === "added" || row.change === "removed") {
    const body = (row.change === "added" ? row.newValue : row.oldValue) ?? {};
    const summary = (SUMMARY_FIELDS[kind] ?? [])
      .map((field) => scalarText(body[field]))
      .filter((text): text is string => text !== null)
      .join(" · ");
    if (!summary) return [];
    return [
      {
        key: row.change,
        label: null,
        from: row.change === "removed" ? summary : null,
        to: row.change === "added" ? summary : null,
        pair: false
      }
    ];
  }

  // `updated`. `details.changedFields` is the list `derive.py` wrote, already narrowed to
  // the fields the policy has enabled. Diffing the two bodies here instead would be
  // *wider* — it would print a change the ledger deliberately declined to log.
  const changed = row.details?.changedFields;
  if (!Array.isArray(changed)) return [];
  return changed.map((raw) => {
    const field = String(raw);
    return {
      key: field,
      label: labels[entryKey(kind, field)] ?? field,
      from: scalarText(row.oldValue?.[field]),
      to: scalarText(row.newValue?.[field]),
      pair: true
    };
  });
}

/**
 * The identity of the thing that changed, for display. Preference order, then everything
 * the identity holds — a certificate carries only a SHA-1 fingerprint, and the fingerprint
 * is better than nothing.
 */
export function identityOf(identity: Record<string, unknown> | null): string {
  if (!identity) return "";
  for (const key of ["name", "username", "groupId", "profileIdentifier", "definitionId", "commonName"]) {
    if (identity[key] !== undefined && identity[key] !== null) return String(identity[key]);
  }
  return Object.values(identity).map(String).join(" ");
}

/**
 * The value that, typed into the `artifact` filter, would find this row again — or `null`
 * when no such value exists.
 *
 * `artifact` matches exactly four expressions: `entry_label`, and `name`, `bundleId` and
 * `username` inside `entry_identity` (`backend/app/api/changes.py`). A certificate is
 * identified only by its fingerprint and carries no label, so it matches none of them, and
 * a field change has no entry at all. Offering the click anyway would hand the operator a
 * filter that returns nothing — and an empty feed reads as "nothing happened", which is
 * the one thing this product refuses to let a shape say by accident.
 */
export function artifactValueOf(row: DeviceChange): string | null {
  if (row.entryLabel) return row.entryLabel;
  const identity = row.entryIdentity;
  if (!identity) return null;
  for (const key of ["name", "bundleId", "username"]) {
    const value = identity[key];
    if (value !== undefined && value !== null && String(value) !== "") return String(value);
  }
  return null;
}

/** The What column, in two halves so a caller can make the identity clickable. */
export interface What {
  /** The section or entry kind, already localized. */
  head: string;
  /** The thing itself — an app name, a group, a field. Empty when the head says it all. */
  identity: string;
}

export function whatOf(
  row: DeviceChange,
  labels: LabelMap,
  t: { section: (name: string) => string; entryKind: (kind: string) => string }
): What {
  if (row.field) {
    return { head: t.section(row.section), identity: labels[fieldKey(row.section, row.field)] ?? row.field };
  }
  return {
    head: row.entryKind ? t.entryKind(row.entryKind) : t.section(row.section),
    identity: row.entryLabel ?? identityOf(row.entryIdentity)
  };
}
