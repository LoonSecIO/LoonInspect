import { describe, expect, it } from "vitest";
import { changeScope, defaultScope, newRule, readScope, scopeSize, type ScopeNode } from "./deviceScope";

describe("nested device scope JSON", () => {
  it("round trips old flat scopes and nested AND/OR without losing connection", () => {
    const scope = { connectionId: 7, match: "all" as const, rules: [newRule(), { match: "any" as const, rules: [newRule("contact"), newRule("inventory")] }] };
    expect(readScope(JSON.stringify(scope))).toEqual(scope);
    expect(readScope(JSON.stringify({ match: "all", rules: [{ field: "managed", value: "true" }] }))).toEqual({ ...defaultScope, rules: [newRule()] });
    const next = changeScope(scope, [1, 0], () => null);
    expect(scopeSize(next)).toEqual({ groups: 2, conditions: 2 });
    expect(next.connectionId).toBe(7);
    expect(scopeSize(scope).conditions).toBe(3);
  });
  it("rejects malformed imports, empty inner groups, unsupported fields and global limits", () => {
    const bad = ["{", '{"rules":[],"match":"xor"}', '{"rules":[],"connectionId":true}',
      JSON.stringify({ rules: [{ match: "any", rules: [] }] }),
      JSON.stringify({ rules: [{ field: "script", value: "anything" }] }),
      JSON.stringify({ rules: [newRule("contact"), { field: "managed", value: "perhaps" }] }),
      JSON.stringify({ rules: Array.from({ length: 3 }, () => ({ rules: Array.from({ length: 8 }, () => newRule()) })) })];
    let nested: ScopeNode = newRule();
    for (let i = 0; i < 5; i++) nested = { match: "all", rules: [nested] };
    bad.push(JSON.stringify(nested));
    for (const raw of bad) expect(readScope(raw), raw).toBeNull();
  });
});
