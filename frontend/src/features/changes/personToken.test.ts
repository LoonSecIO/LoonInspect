import { expect, it } from "vitest";
import { rowUserToken, userChipLabel, userTokenRewrite } from "@/features/changes/personToken";
import type { DeviceChange } from "@/features/changes/types";
import { en } from "@/i18n/en";

/** The person on the change feed's URL (#446): a press puts the token in the bar, a reader sees
 *  the name. */

const TOKEN = "u_7Qa1bZ-x9KcD2fGh";
const words = en.changes.hiddenChips.person;
const row = (deviceMeta: Record<string, unknown> | null): DeviceChange => ({ id: 1, deviceMeta }) as unknown as DeviceChange;

it("applies a row's token and never its name, and offers no press without one", () => {
  expect(rowUserToken(row({ userToken: TOKEN, realName: "Dana Okonkwo" }))).toBe(TOKEN);
  expect([rowUserToken(row({ realName: "Dana" })), rowUserToken(row(null))]).toEqual([undefined, undefined]);
});

it("rewrites a typed name the response resolved to one person, and nothing else", () => {
  expect(userTokenRewrite("dana", { token: TOKEN, display: "Dana Okonkwo" })).toBe(TOKEN);
  // Already a token; text that matched more than one person or none; no filter at all.
  expect(userTokenRewrite(TOKEN, { token: TOKEN, display: "Dana" })).toBeNull();
  expect(userTokenRewrite("dana", { token: null, display: null })).toBeNull();
  expect(userTokenRewrite("dana", null)).toBeNull();
  expect(userTokenRewrite(undefined, { token: TOKEN, display: "Dana" })).toBeNull();
});

it("shows the chip as a person and never as the token", () => {
  const named = userChipLabel(TOKEN, { token: TOKEN, display: "Dana Okonkwo" }, words);
  const stale = userChipLabel(TOKEN, { token: TOKEN, display: null }, words);
  expect([named, stale]).toEqual(["Assigned user Dana Okonkwo", words.unresolved]);
  // A rotated key, a link older than the stamp, or an echo still in flight: still no token shown.
  for (const label of [named, stale, userChipLabel(TOKEN, null, words)]) expect(label).not.toContain(TOKEN);
  // Still text: quoted as typed, whether or not it resolved to one person.
  expect(userChipLabel("dana", null, words)).toBe("Assigned user matching “dana”");
  expect(userChipLabel("dana", { token: TOKEN, display: "Dana Okonkwo" }, words)).toBe("Assigned user matching “dana”");
});
