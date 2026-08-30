import { useEffect, useState } from "react";
import { getVersion } from "@/features/system/api";

/** The build this instance is running, or null until the answer arrives (and on a
 *  failed request — a chrome element nobody came to read should not show an error).
 *
 *  Asks /api/system/version rather than reading the auth store. The store writes
 *  `version` only in bootstrap(), which never re-runs — every call site guards on
 *  status === "unknown" — and on a claimed instance bootstrap runs while anonymous,
 *  where the probe now withholds the build. So a bootstrap-then-login sequence in one
 *  page load would leave the store holding null forever (issue #130). */
export function useBuildVersion(): string | null {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getVersion()
      .then((result) => {
        if (!cancelled) setVersion(result.version);
      })
      .catch(() => {
        // Unreachable backend or a stale session: stay silent.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return version;
}
