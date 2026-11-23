export type ScopeField = "managed" | "supervised" | "contact" | "inventory" | "group" | "ea" | "site" | "department" | "building" | "os_version";
export type ScopeOperator = "is" | "is_not" | "contains" | "like" | "not_like" | "matches_regex" | "does_not_match_regex" | "before" | "after" | "within" | "older" | "unknown";
export type ScopeRule = { field: ScopeField; operator: ScopeOperator; value: string; key: string };
export type ScopeGroup = { match: "all" | "any"; rules: ScopeNode[] };
export type ScopeNode = ScopeRule | ScopeGroup;
export type ScopeMode = "advanced_search" | "smart_group";
export type DeviceScope = ScopeGroup & { connectionId?: number | null; mode?: ScopeMode };
export const defaultScope: DeviceScope = { match: "all", rules: [] };
export const scopeFields: [ScopeField, string][] = [["managed", "Managed"], ["supervised", "Supervised"], ["group", "Jamf group"], ["contact", "Last contact"],
  ["inventory", "Last inventory"], ["ea", "Extension attribute"], ["site", "Site"], ["department", "Department ID"],
  ["building", "Building ID"], ["os_version", "macOS version"]];
export const comparisonLabels: Record<ScopeOperator, string> = {
  before: "before date", after: "after date", like: "like", not_like: "not like", matches_regex: "matches regex", does_not_match_regex: "does not match regex",
  is: "is", is_not: "is not", contains: "contains", within: "within days", older: "older than days", unknown: "is unknown",
};
export function operators(field: ScopeField): ScopeOperator[] {
  if (field === "contact" || field === "inventory") return ["within", "older", "before", "after", "unknown"];
  if (field === "managed" || field === "supervised") return ["is", "unknown"];
  if (field === "group") return ["is", "is_not"];
  if (field === "ea") return ["is", "is_not", "like", "not_like", "matches_regex", "does_not_match_regex", "unknown"];
  return ["is", "is_not", "contains", "unknown"];
}
export function newRule(field: ScopeField = "managed"): ScopeRule {
  return { field, operator: operators(field)[0], value: field === "managed" || field === "supervised" ? "true" : field === "contact" || field === "inventory" ? "14" : "", key: "" };
}
export function isScopeGroup(node: ScopeNode): node is ScopeGroup { return "rules" in node; }
export function scopeSize(scope: ScopeGroup): { groups: number; conditions: number } {
  return scope.rules.reduce((total, node) => {
    const child = isScopeGroup(node) ? scopeSize(node) : { groups: 0, conditions: 1 };
    return { groups: total.groups + child.groups, conditions: total.conditions + child.conditions };
  }, { groups: 1, conditions: 0 });
}
export function changeScope(scope: DeviceScope, path: number[], change: (node: ScopeNode) => ScopeNode | null): DeviceScope {
  function descend(node: ScopeNode, indices: number[]): ScopeNode | null {
    if (!indices.length) return change(node);
    if (!isScopeGroup(node)) return node;
    const [index, ...rest] = indices;
    return { ...node, rules: node.rules.flatMap((child, i) => {
      const result = i === index ? descend(child, rest) : child;
      return result ? [result] : [];
    }) };
  }
  return descend(scope, path) as DeviceScope;
}

/** Match the bounded server vocabulary; invalid JSON never broadens into an applied empty scope. */
export function readScope(raw: string): DeviceScope | null {
  try {
    if (raw.length > 12000) return null;
    let groups = 0, conditions = 0;
    const fail = () => { throw new Error("Invalid device scope"); };
    function node(value: unknown, depth: number, root = false): ScopeNode {
      if (!value || typeof value !== "object" || Array.isArray(value)) return fail();
      const item = value as Record<string, unknown>;
      if ("rules" in item) {
        if (++groups > 10 || depth > 4 || !Array.isArray(item.rules) || item.rules.length > 20 || (!root && !item.rules.length)) return fail();
        if (Object.keys(item).some(key => !["rules", "match", ...(root ? ["connectionId", "mode"] : [])].includes(key))) return fail();
        const match = item.match ?? "all";
        if (match !== "all" && match !== "any") return fail();
        return { match, rules: item.rules.map(child => node(child, depth + 1)) };
      }
      if (++conditions > 20 || Object.keys(item).some(key => !["field", "operator", "value", "key"].includes(key))) return fail();
      const { field, operator = "is", value: ruleValue = "", key = "" } = item;
      if (!scopeFields.some(([name]) => name === field) || !operators(field as ScopeField).includes(operator as ScopeOperator)) return fail();
      if (typeof ruleValue !== "string" || typeof key !== "string" || ruleValue.length > 255 || key.length > 255) return fail();
      if (operator !== "unknown" && !ruleValue.trim()) return fail();
      if ((field === "managed" || field === "supervised") && operator !== "unknown" && !["true", "false"].includes(ruleValue)) return fail();
      if ((field === "contact" || field === "inventory") && (operator === "within" || operator === "older")
        && (!/^\d+$/.test(ruleValue) || +ruleValue < 1 || +ruleValue > 3650)) return fail();
      if ((operator === "before" || operator === "after") && !validDate(ruleValue)) return fail();
      if ((field === "ea" || field === "group") && !key.trim()) return fail();
      if (field === "group" && (!/^\d+$/.test(key) || +key < 1 || +key > 2147483647)) return fail();
      return { field, operator, value: ruleValue, key } as ScopeRule;
    }
    const parsed = JSON.parse(raw);
    const scope = node(parsed, 1, true);
    if (!isScopeGroup(scope)) return null;
    const connectionId = parsed.connectionId;
    if (connectionId != null && (!Number.isInteger(connectionId) || connectionId < 1 || connectionId > 2147483647)) return null;
    const mode = parsed.mode;
    if (mode !== undefined && mode !== "advanced_search" && mode !== "smart_group") return null;
    if (mode === "smart_group" && hasManagedRule(scope)) return null;
    return { ...scope, ...(mode ? { mode } : {}), ...(connectionId != null ? { connectionId } : {}) };
  } catch { return null; }
}

export function hasManagedRule(group: ScopeGroup): boolean {
  return group.rules.some(node => isScopeGroup(node) ? hasManagedRule(node) : node.field === "managed");
}
export function isDateOperator(operator: ScopeOperator): boolean { return operator === "before" || operator === "after"; }
function validDate(value: string): boolean {
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value) || value.startsWith("0000")) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}
export function changeComparison(rule: ScopeRule, operator: ScopeOperator): ScopeRule {
  const changingDateType = isDateOperator(operator) !== isDateOperator(rule.operator);
  return { ...rule, operator, value: operator === "unknown" || changingDateType ? "" : rule.value || newRule(rule.field).value };
}
