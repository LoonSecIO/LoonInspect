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

describe("Jamf-style scope comparisons", () => {
  it("validates calendar dates and text comparisons without interpreting PostgreSQL regex in JavaScript", () => {
    for (const field of ["contact", "inventory"]) {
      for (const operator of ["before", "after"]) {
        expect(readScope(JSON.stringify({ rules: [{ field, operator, value: "2024-02-29" }] }))).not.toBeNull();
        for (const value of ["2023-02-29", "2024-02-30", "2024-2-29", "0000-01-01", "14"]) {
          expect(readScope(JSON.stringify({ rules: [{ field, operator, value }] }))).toBeNull();
        }
      }
    }
    for (const operator of ["like", "not_like", "matches_regex", "does_not_match_regex"]) {
      expect(readScope(JSON.stringify({ rules: [{ field: "ea", key: "Ring", operator, value: "[[:alpha:]]+" }] }))).not.toBeNull();
    }
  });
  it("preserves smart group mode and refuses explicit Managed conditions at any depth", () => {
    const scope = { mode: "smart_group", match: "all", rules: [newRule("supervised")] };
    expect(readScope(JSON.stringify(scope))).toEqual(scope);
    expect(readScope(JSON.stringify({ ...scope, rules: [{ match: "any", rules: [newRule()] }] }))).toBeNull();
    expect(readScope(JSON.stringify({ ...scope, mode: "guess" }))).toBeNull();
  });
});
