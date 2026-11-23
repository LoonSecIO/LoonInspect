export type ScopeField = "managed" | "contact" | "inventory" | "group" | "ea" | "site" | "department" | "building" | "os_version";
export type ScopeOperator = "is" | "is_not" | "contains" | "within" | "older" | "unknown";
export type ScopeRule = { field: ScopeField; operator: ScopeOperator; value: string; key: string };
export type DeviceScope = { connectionId?: number | null; match: "all" | "any"; rules: ScopeRule[] };
export const defaultScope: DeviceScope = { match: "all", rules: [] };
export type ScopeOptions = { devices: number; connections: { id: number; name: string }[];
  groups: { connectionId: number; id: string; name: string }[]; attributes: { id: string; name: string }[] };
export type PlanOption = { source: string; status: string; title: string; reference: string; targetVersion: string;
  url: string; observedAt: string | null; sourceRevision: string; detail: string };
export type PlannedApp = { appHash: string; name: string; bundleId: string; devices: number; status: string;
  targetVersion: string | null; versions: { version: string; shortVersion: string | null; devices: number; relation: string }[];
  options: PlanOption[]; gaps: string[]; steps: string[] };
export type PlanSummary = { id: string; title: string; createdAt: string; revision: number; researchStatus: string;
  applications: { appHash: string; name: string }[] };
export type PatchPlan = { id: string; title: string; createdAt: string; createdBy: string; revision: number; sha256: string;
  researchStatus: string; researchStartedAt: string | null;
  snapshot: { organization: string; status: string; asOf: string; scope: DeviceScope; scopeDescription: string[];
    operatorReview?: Record<string, string>;
    scopedDevices: number; applicationDevices: number; applications: PlannedApp[]; limitations: string[];
    sources: { connectionId: number; name: string; mdm: string; devices: number;
      oldestInventoryAt: string | null; newestInventoryAt: string | null; unknownInventoryDates: number }[] };
  research: { detail: string; completedAt?: string; applications?: { appHash: string; status: string; detail: string;
    checkedAt: string; url?: string; revision?: string; label?: string; signingTeam?: string; sha256?: string }[];
    ai?: { status: string; provider: string; requestedModel?: string; reportedModel?: string; completedAt?: string;
      detail: string; priorities?: Record<string, number[]> } | null } | null };

export function readScope(raw: string): DeviceScope | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const scope = parsed as DeviceScope;
    return ["all", "any"].includes(scope.match) && Array.isArray(scope.rules) && scope.rules.length <= 20
      && scope.rules.every(r => r && typeof r.field === "string" && typeof r.value === "string" && typeof r.key === "string") ? scope : null;
  } catch { return null; }
}
