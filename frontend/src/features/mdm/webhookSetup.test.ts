import { describe, expect, it } from "vitest";
import {
  SECRET_BYTES,
  WEBHOOK_EVENTS,
  generateSecret,
  headerObject,
  originWarning,
  receivePatch,
  webhookOrigin,
  webhookStatus,
  webhookUrl
} from "@/features/mdm/webhookSetup";

describe("webhookUrl", () => {
  it("is the origin, the route and the connection id", () => {
    expect(webhookUrl("https://203.0.113.10:8001", 3)).toBe("https://203.0.113.10:8001/webhooks/jamf/3");
  });

  it("does not double a trailing slash", () => {
    expect(webhookUrl("https://inspect.example.com/", 12)).toBe("https://inspect.example.com/webhooks/jamf/12");
  });
});

describe("webhookOrigin", () => {
  it("is the page's origin when the API is same-origin (the default /api)", () => {
    expect(webhookOrigin("/api", "https://inspect.example.com")).toBe("https://inspect.example.com");
  });

  it("is the API's origin when the build points it elsewhere", () => {
    expect(webhookOrigin("https://api.example.com/api", "https://app.example.com")).toBe("https://api.example.com");
  });
});

describe("originWarning", () => {
  it.each([
    ["http://localhost:8001", "localhost"],
    ["https://localhost:8443", "localhost"],
    ["http://127.0.0.1:8001", "localhost"],
    ["http://[::1]:8001", "localhost"],
    ["https://app.localhost", "localhost"],
    ["https://10.0.4.20", "private"],
    ["https://172.16.0.9", "private"],
    ["https://172.31.255.1", "private"],
    ["https://192.168.1.50:8001", "private"],
    ["https://169.254.10.10", "private"],
    ["https://loon.local", "private"],
    ["https://host.docker.internal:8001", "private"],
    ["https://inspect", "private"],
    ["https://[fd12:3456::1]", "private"],
    ["http://inspect.example.com", "http"],
    ["http://203.0.113.10:8001", "http"]
  ])("%s is %s", (origin, expected) => {
    expect(originWarning(origin)).toBe(expected);
  });

  it.each(["https://203.0.113.10:8001", "https://inspect.example.com", "https://172.32.0.1", "https://[2001:db8::1]"])(
    "%s needs no warning",
    (origin) => {
      expect(originWarning(origin)).toBeNull();
    }
  );

  it("does not throw on something that is not a URL", () => {
    expect(originWarning("not a url")).toBeNull();
  });
});

describe("headerObject", () => {
  it("is valid JSON with exactly the one header Jamf Pro should send", () => {
    const parsed = JSON.parse(headerObject("abc123"));
    expect(Object.keys(parsed)).toEqual(["X-API-Key"]);
    expect(parsed["X-API-Key"]).toBe("abc123");
  });

  it("survives a typed secret holding characters JSON must escape", () => {
    const typed = 'a"quote\\andé';
    expect(JSON.parse(headerObject(typed))["X-API-Key"]).toBe(typed);
  });
});

describe("generateSecret", () => {
  it(`draws ${SECRET_BYTES} bytes and encodes them as unpadded base64url`, () => {
    let asked = 0;
    const secret = generateSecret((bytes) => {
      asked = bytes.length;
      return bytes.fill(0xfb);
    });
    expect(asked).toBe(SECRET_BYTES);
    // 32 bytes → 43 characters, no padding, no + or /.
    expect(secret).toHaveLength(43);
    expect(secret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(secret.startsWith("-_")).toBe(true);
  });

  it("uses the platform CSPRNG by default, and two draws differ", () => {
    const first = generateSecret();
    const second = generateSecret();
    expect(first).toHaveLength(43);
    expect(first).not.toBe(second);
  });

  it("drops into the header object without escaping", () => {
    const secret = generateSecret();
    expect(headerObject(secret)).toBe(`{"X-API-Key":"${secret}"}`);
  });
});

describe("webhookStatus", () => {
  const base = { isActive: true, capabilityWebhooks: true, hasWebhookSecret: true };

  it("names the first thing missing, in the order the server refuses", () => {
    expect(webhookStatus({ ...base, isActive: false, capabilityWebhooks: false })).toBe("inactive");
    expect(webhookStatus({ ...base, capabilityWebhooks: false, hasWebhookSecret: false })).toBe("off");
    expect(webhookStatus({ ...base, hasWebhookSecret: false })).toBe("noSecret");
    expect(webhookStatus(base)).toBe("receiving");
  });
});

describe("receivePatch", () => {
  const minted = () => "minted-secret";

  it("turning on without a secret brings one, so the page never makes the refuse-everything state", () => {
    expect(receivePatch(true, false, minted)).toEqual({ capabilityWebhooks: true, webhookSecret: "minted-secret" });
  });

  it("turning on with a secret keeps it", () => {
    expect(receivePatch(true, true, minted)).toEqual({ capabilityWebhooks: true });
  });

  it("turning off never touches the secret", () => {
    expect(receivePatch(false, true, minted)).toEqual({ capabilityWebhooks: false });
    expect(receivePatch(false, false, minted)).toEqual({ capabilityWebhooks: false });
  });
});

describe("WEBHOOK_EVENTS", () => {
  it("are the two the server acts on, and never the check-in", () => {
    expect([...WEBHOOK_EVENTS].sort()).toEqual(["ComputerAdded", "ComputerInventoryCompleted"]);
    expect(WEBHOOK_EVENTS).not.toContain("ComputerCheckIn");
  });
});
