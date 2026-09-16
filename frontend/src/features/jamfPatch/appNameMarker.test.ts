import { describe, expect, it } from "vitest";
import { appNameMarker } from "./appNameMarker";

const title = (appName: string | null, appNameSource: string | null) => ({ appName, appNameSource });

describe("appNameMarker", () => {
  it("annotates a name read out of the patch definition, and only that one", () => {
    // The three live Wireshark lines: Jamf publishes no appName, killApps names the app.
    expect(appNameMarker(title("Wireshark.app", "kill_apps"))).toBe("derived");
    expect(appNameMarker(title("Wireshark.app", "jamf"))).toBe("plain");
  });

  it("says a title nothing names an app for is unnamed rather than blank", () => {
    expect(appNameMarker(title(null, "unnamed"))).toBe("unnamed");
    expect(appNameMarker(title("", "unnamed"))).toBe("unnamed");
  });

  it("a row from before the rule claims nothing either way", () => {
    // `app_name_source` is NULL on rows written before #385; `_needs_refresh` re-reads
    // exactly those once, and until it has they are not evidence of anything.
    expect(appNameMarker(title(null, null))).toBe("none");
    expect(appNameMarker(title("Slack.app", null))).toBe("plain");
  });

  it("shows a name under a source this build does not know, and marks nothing", () => {
    // Additive server, older page: an unread annotation is worse than none.
    expect(appNameMarker(title("Slack.app", "something_new"))).toBe("plain");
    expect(appNameMarker(title(null, "something_new"))).toBe("none");
  });

  it("whitespace is not a name", () => {
    expect(appNameMarker(title("   ", "kill_apps"))).toBe("none");
    expect(appNameMarker(title("   ", "unnamed"))).toBe("unnamed");
  });
});
