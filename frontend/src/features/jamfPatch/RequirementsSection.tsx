import type { JamfPatchRequirementGroup, JamfPatchRequirementTest } from "@/features/jamfPatch/types";
import { useLocale } from "@/i18n/LocaleContext";

export function formatTest(test: JamfPatchRequirementTest): string {
  const subject = test.type === "extensionAttribute" ? `EA "${test.name}"` : test.name;
  return `${subject} ${test.operator} "${test.value}"`;
}

export function RequirementsSection({ groups }: { groups: JamfPatchRequirementGroup[] }) {
  const { t } = useLocale();

  if (groups.length === 0) {
    return <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.requirementsEmpty}</p>;
  }

  return (
    <div className="space-y-2">
      {groups.map((group, index) => (
        <div key={index}>
          {index > 0 && (
            <p className="py-1 text-center text-xs font-medium uppercase text-muted-foreground">
              {t.jamfPatch.detail.requirementsOr}
            </p>
          )}
          <div className="rounded-lg border bg-card p-3">
            <ul className="space-y-1 text-sm">
              {group.tests.map((test, testIndex) => (
                <li key={testIndex} className="flex items-center gap-2">
                  {testIndex > 0 && (
                    <span className="text-xs font-medium text-muted-foreground">{t.jamfPatch.detail.requirementsAnd}</span>
                  )}
                  <span>{formatTest(test)}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ))}
    </div>
  );
}
