import { describe, expect, it } from "vitest";
import { findingIdIn, findingPath, findingRoute, nvdDetail } from "./findingId";

describe("an id in the search box", () => {
  it("routes the two namespaces §5 mints, trimmed, whatever the sequence number's length", () => {
    expect(findingIdIn("CVE-2025-1492")).toBe("CVE-2025-1492");
    expect(findingIdIn("  CVE-2025-11626 ")).toBe("CVE-2025-11626");
    expect(findingIdIn("LoonVD-2026-000042")).toBe("LoonVD-2026-000042");
  });

  it("leaves everything else as search text rather than routing it to a refusal", () => {
    // Reserved, unlicensed, half an id, the wrong case, an app name. None of them is a lookup.
    for (const typed of ["LOCAL-2026-000042", "GHSA-72mh-4hwj-fh5w", "CVE-2025", "cve-2025-1492", "Wireshark"]) {
      expect(findingIdIn(typed)).toBeNull();
    }
  });

  it("is routed on Enter and on no keystroke, so a longer id can be finished", () => {
    // The box, keystroke by keystroke: routing on change left for `CVE-2025-1162` at the
    // thirteenth character, which made every five-digit CVE untypable.
    const typed = "CVE-2025-11626";
    for (let i = 1; i <= typed.length; i += 1) expect(findingRoute(typed.charAt(i - 1), typed.slice(0, i))).toBeNull();
    expect(findingRoute("Enter", typed)).toBe("/posture/vulnerabilities/CVE-2025-11626");
    expect(findingRoute("Enter", "  LoonVD-2026-000042 ")).toBe("/posture/vulnerabilities/LoonVD-2026-000042");
    // Enter on search text is not a route: the lists below are already answering it.
    expect(findingRoute("Enter", "Wireshark")).toBeNull();
  });

  it("is answered on its own page, and left to the reader's browser at NVD for a CVE alone", () => {
    expect(findingPath("CVE-2025-1492")).toBe("/posture/vulnerabilities/CVE-2025-1492");
    expect(nvdDetail("CVE-2025-1492")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2025-1492");
    expect(nvdDetail("LoonVD-2026-000042")).toBeNull();
    // A hand-edited URL reaches the page too, and only the shape the server accepts links out.
    expect(nvdDetail("CVE-not-an-id")).toBeNull();
  });
});
