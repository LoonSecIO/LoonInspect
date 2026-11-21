import type { VersionResponse } from "@/features/system/api";
import type { Translations } from "@/i18n/en";

type Words = Translations["support"];
export const isMacApp = (identity: VersionResponse | null | undefined) => identity?.kind === "mac-app";

/** A short release in the Mac chrome; the backend stamp still identifies a container. */
export function buildLabel(identity: VersionResponse, words: Words): string {
  return isMacApp(identity)
    ? `${words.macApp}${identity.appVersion?.trim() ? ` ${identity.appVersion.trim()}` : ""}`
    : identity.version;
}

export function buildRows(identity: VersionResponse, words: Words): [string, string][] {
  const backend: [string, string] = [words.backendBuild, identity.version];
  return isMacApp(identity)
    ? [
        [words.appVersion, identity.appVersion?.trim() || words.notRecorded],
        [words.appBuild, identity.appBuild?.trim() || words.notRecorded],
        backend
      ]
    : [backend];
}

/** All identities needed in a report, without inferring a bundle version from a backend stamp. */
export function copyableBuild(identity: VersionResponse | null | undefined, words: Words): string | null {
  if (!identity?.version?.trim()) return null;
  return isMacApp(identity)
    ? buildRows(identity, words).map(([label, value]) => `${label}: ${value}`).join("\n")
    : identity.version.trim();
}
