import { useState } from "react";
import { Button } from "@/components/ui/button";
import { FlaskLogo } from "@/components/icons/FlaskLogo";
import { useLocale } from "@/i18n/LocaleContext";

export function AIPage() {
  const { t } = useLocale();
  const [enabled, setEnabled] = useState(false);
  const [testMessage, setTestMessage] = useState<string | null>(null);

  function handleTest() {
    // Visual stub only — the eventual test action proxies down to a terminal command
    // on the host macOS device. Nothing to call yet, but a silent no-op button is a
    // worse stub than one that's honest about doing nothing.
    setTestMessage(t.ai.testStubMessage);
  }

  return (
    <section className="space-y-6">
      <div>
        <p className="text-sm font-medium text-muted-foreground">{t.ai.eyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.ai.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t.ai.description}</p>
      </div>

      <div className="rounded-lg border border-dashed bg-muted/30 p-3 text-sm text-muted-foreground">
        {t.ai.previewBanner}
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        <div className="flex flex-col justify-between gap-4 rounded-lg border bg-card p-4">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-muted text-primary">
              <FlaskLogo className="h-5 w-5" />
            </div>
            <div>
              <p className="font-medium leading-tight">{t.ai.appleAi.name}</p>
              <p className="text-xs text-muted-foreground">{t.ai.appleAi.subtitle}</p>
            </div>
          </div>

          <p className="text-sm text-muted-foreground">{t.ai.appleAi.description}</p>

          <div className="flex items-center gap-2">
            <Button
              variant={enabled ? "default" : "outline"}
              size="sm"
              onClick={() => {
                setEnabled((current) => !current);
                setTestMessage(null);
              }}
            >
              {enabled ? t.ai.enabled : t.ai.enable}
            </Button>
            <Button variant="outline" size="sm" disabled={!enabled} onClick={handleTest}>
              {t.ai.test}
            </Button>
          </div>

          {testMessage && <p className="text-xs text-muted-foreground">{testMessage}</p>}
        </div>
      </div>
    </section>
  );
}
