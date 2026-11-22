// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { LocaleProvider } from "@/i18n/LocaleContext";
import { FleetOperatorNotes } from "./FleetOperatorNotes";

afterEach(cleanup);

function renderNote(bundleId: string) {
  render(<LocaleProvider><FleetOperatorNotes bundleId={bundleId} /></LocaleProvider>);
}

it("separates the Falcon correlation value from the label query", () => {
  renderNote("com.crowdstrike.falcon.App");
  expect(screen.getByText(/restricted per-device Jamf extension attribute/)).toBeTruthy();
  expect(screen.getByText(/^SELECT 1 FROM apps/).textContent).toBe("SELECT 1 FROM apps WHERE bundle_identifier = 'com.crowdstrike.falcon.App' LIMIT 1;");
});

it("describes what the Zwift bundle actually measures", () => {
  renderNote("com.zwift.ZwiftLauncher");
  expect(screen.getByText(/Track the game build separately/)).toBeTruthy();
  expect(screen.getByRole("link", { name: /Zwift/ }).getAttribute("href")).toContain("forums.zwift.com/");
});

it("gives a verification step when the observed identifier cannot be used for a label", () => {
  renderNote("Unidentified tool");
  expect(screen.queryByText(/^SELECT 1 FROM apps/)).toBeNull();
  expect(screen.getByText(/Verify the app’s bundle identifier/)).toBeTruthy();
});
