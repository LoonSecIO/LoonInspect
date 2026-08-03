import { useMemo, useState } from "react";
import { CheckCircle2, HelpCircle, XCircle } from "lucide-react";
import type { JamfPatchRequirementGroup } from "@/features/jamfPatch/types";
import { formatTest } from "@/features/jamfPatch/RequirementsSection";
import { evaluateRequirements, type TestFacts, type TestOutcome } from "@/features/jamfPatch/requirementsEvaluator";
import { useLocale } from "@/i18n/LocaleContext";

// Status colors are fixed (never themed) per the dataviz palette: good/warning/critical.
const STATUS_COLORS = {
  good: "#0ca30c",
  warning: "#fab219",
  critical: "#d03b3b"
} as const;

const inputClasses =
  "rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

const EMPTY_FACTS: TestFacts = {
  appName: "",
  bundleId: "",
  shortVersion: "",
  bundleVersion: "",
  extensionAttributeName: "",
  extensionAttributeValue: ""
};

function OutcomeIcon({ outcome }: { outcome: TestOutcome }) {
  if (outcome === "pass") return <CheckCircle2 className="h-4 w-4 shrink-0" style={{ color: STATUS_COLORS.good }} />;
  if (outcome === "fail") return <XCircle className="h-4 w-4 shrink-0" style={{ color: STATUS_COLORS.critical }} />;
  return <HelpCircle className="h-4 w-4 shrink-0" style={{ color: STATUS_COLORS.warning }} />;
}

export function RequirementsTestPanel({ requirements }: { requirements: JamfPatchRequirementGroup[] }) {
  const { t } = useLocale();
  const [facts, setFacts] = useState<TestFacts>(EMPTY_FACTS);

  const result = useMemo(() => evaluateRequirements(requirements, facts), [requirements, facts]);

  function update(patch: Partial<TestFacts>) {
    setFacts((current) => ({ ...current, ...patch }));
  }

  const verdictLabel = {
    matched: t.jamfPatch.detail.testVerdictMatched,
    not_matched: t.jamfPatch.detail.testVerdictNotMatched,
    inconclusive: t.jamfPatch.detail.testVerdictInconclusive
  }[result.verdict];

  const verdictColor = {
    matched: STATUS_COLORS.good,
    not_matched: STATUS_COLORS.critical,
    inconclusive: STATUS_COLORS.warning
  }[result.verdict];

  const verdictIcon =
    result.verdict === "matched" ? (
      <CheckCircle2 className="h-4 w-4 shrink-0" style={{ color: verdictColor }} />
    ) : result.verdict === "not_matched" ? (
      <XCircle className="h-4 w-4 shrink-0" style={{ color: verdictColor }} />
    ) : (
      <HelpCircle className="h-4 w-4 shrink-0" style={{ color: verdictColor }} />
    );

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">{t.jamfPatch.detail.testAppName}</span>
          <input
            className={`${inputClasses} w-full`}
            value={facts.appName}
            onChange={(e) => update({ appName: e.target.value })}
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">{t.jamfPatch.detail.testBundleId}</span>
          <input
            className={`${inputClasses} w-full`}
            value={facts.bundleId}
            onChange={(e) => update({ bundleId: e.target.value })}
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">{t.jamfPatch.detail.testShortVersion}</span>
          <input
            className={`${inputClasses} w-full`}
            value={facts.shortVersion}
            onChange={(e) => update({ shortVersion: e.target.value })}
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">{t.jamfPatch.detail.testBundleVersion}</span>
          <input
            className={`${inputClasses} w-full`}
            value={facts.bundleVersion}
            onChange={(e) => update({ bundleVersion: e.target.value })}
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">{t.jamfPatch.detail.testEaName}</span>
          <input
            className={`${inputClasses} w-full`}
            value={facts.extensionAttributeName}
            onChange={(e) => update({ extensionAttributeName: e.target.value })}
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">{t.jamfPatch.detail.testEaValue}</span>
          <input
            className={`${inputClasses} w-full`}
            value={facts.extensionAttributeValue}
            onChange={(e) => update({ extensionAttributeValue: e.target.value })}
          />
        </label>
      </div>

      <div className="flex items-center gap-2 text-sm font-semibold" style={{ color: verdictColor }}>
        {verdictIcon}
        {verdictLabel}
      </div>

      {requirements.length === 0 && <p className="text-sm text-muted-foreground">{t.jamfPatch.detail.requirementsEmpty}</p>}

      <div className="space-y-2">
        {result.groups.map((groupResult, index) => (
          <div key={index}>
            {index > 0 && (
              <p className="py-1 text-center text-xs font-medium uppercase text-muted-foreground">
                {t.jamfPatch.detail.requirementsOr}
              </p>
            )}
            <div className="rounded-lg border bg-card p-3">
              <ul className="space-y-1 text-sm">
                {groupResult.tests.map(({ test, outcome }, testIndex) => (
                  <li key={testIndex} className="flex items-center gap-2">
                    <OutcomeIcon outcome={outcome} />
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
    </div>
  );
}
