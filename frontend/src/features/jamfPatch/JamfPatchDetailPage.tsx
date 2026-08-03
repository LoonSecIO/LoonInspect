import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { getJamfPatchTitle } from "@/features/jamfPatch/api";
import type { JamfPatchTitleDetail } from "@/features/jamfPatch/types";
import { useLocale } from "@/i18n/LocaleContext";

export function JamfPatchDetailPage() {
  const { t } = useLocale();
  const { titleId } = useParams<{ titleId: string }>();

  const [title, setTitle] = useState<JamfPatchTitleDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!titleId) return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    getJamfPatchTitle(titleId)
      .then((response) => {
        if (!cancelled) setTitle(response);
      })
      .catch(() => {
        if (!cancelled) setError(t.jamfPatch.detail.errorLoading);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [titleId, t]);

  return (
    <section className="space-y-6">
      <div>
        <Link to="/devices/applications/jamf-patch" className="text-sm text-muted-foreground hover:underline">
          {t.jamfPatch.detail.back}
        </Link>
      </div>

      {loading && <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.loading}</p>}
      {!loading && error && <p className="text-sm text-destructive">{error}</p>}
      {!loading && !error && !title && <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.notFound}</p>}

      {!loading && !error && title && (
        <>
          <div>
            <p className="text-sm font-medium text-muted-foreground">{t.jamfPatch.eyebrow}</p>
            <h1 className="text-3xl font-bold tracking-tight">{title.name}</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              {title.publisher ?? "—"} · {title.bundleId ?? "—"} · {t.jamfPatch.tableCurrentVersion}:{" "}
              {title.currentVersion}
            </p>
          </div>

          <div className="overflow-x-auto rounded-lg border bg-card">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/30 text-left text-muted-foreground">
                <tr>
                  <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableVersion}</th>
                  <th className="px-4 py-2 font-medium">{t.jamfPatch.detail.tableReleaseDate}</th>
                </tr>
              </thead>
              <tbody>
                {title.patches.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-muted-foreground" colSpan={2}>
                      {t.jamfPatch.detail.empty}
                    </td>
                  </tr>
                )}
                {title.patches.map((patch, index) => (
                  <tr key={`${patch.version}-${index}`} className="border-b last:border-0">
                    <td className="px-4 py-2 font-medium">{patch.version}</td>
                    <td className="px-4 py-2">
                      {patch.releaseDate ? new Date(patch.releaseDate).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.versionsTotal(title.patches.length)}</p>
        </>
      )}
    </section>
  );
}
