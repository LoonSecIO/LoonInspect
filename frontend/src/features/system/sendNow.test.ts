/** Send now (#408): every state the button can be in says why. Frontend lane (#285). */

import { describe, expect, it } from "vitest";
import { endpointHost, sendNowAvailability } from "@/features/system/sendNow";

describe("sendNowAvailability", () => {
  it("a role that cannot write gets no button at all, whatever the settings say", () => {
    expect(sendNowAvailability({ tier: "reveal", envDisabled: false }, false)).toBe("hidden");
    expect(sendNowAvailability({ tier: "off", envDisabled: true }, false)).toBe("hidden");
  });

  it("the environment override outranks the tier, as it does on the server", () => {
    expect(sendNowAvailability({ tier: "keys", envDisabled: true }, true)).toBe("blockedEnv");
    expect(sendNowAvailability({ tier: "off", envDisabled: true }, true)).toBe("blockedEnv");
  });

  it("an off tier has nothing to send", () => {
    expect(sendNowAvailability({ tier: "off", envDisabled: false }, true)).toBe("blockedOff");
  });

  it("either sharing tier can send", () => {
    expect(sendNowAvailability({ tier: "keys", envDisabled: false }, true)).toBe("ready");
    expect(sendNowAvailability({ tier: "reveal", envDisabled: false }, true)).toBe("ready");
  });
});

describe("endpointHost", () => {
  it("names the host of the endpoint the row was sent to", () => {
    expect(endpointHost("https://api.loonsec.io/v1/exchange")).toBe("api.loonsec.io");
    expect(endpointHost("https://api.staging.next.loonsec.io/v1/exchange")).toBe("api.staging.next.loonsec.io");
  });

  it("shows a value that is not a URL as it is, rather than nothing", () => {
    expect(endpointHost("not a url")).toBe("not a url");
    expect(endpointHost("")).toBe("");
  });
});
