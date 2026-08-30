import { Check } from "lucide-react";
import { Link } from "react-router";
import { useLocale } from "@/i18n/LocaleContext";

const actionLinkClasses =
  "inline-flex h-9 w-fit items-center justify-center rounded-md px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
const primaryAction = `${actionLinkClasses} bg-primary text-primary-foreground hover:bg-primary/90`;
const secondaryAction = `${actionLinkClasses} border border-input bg-background hover:bg-accent hover:text-accent-foreground`;

interface StepProps {
  index: number;
  title: string;
  body: string;
  action: string;
  href: string;
  done: boolean;
  /** True for the first step still outstanding — the only one whose action is primary.
   *  Three equally loud buttons is three decisions; there is only ever one next thing. */
  next: boolean;
  optional?: boolean;
}

function Step({ index, title, body, action, href, done, next, optional }: StepProps) {
  const { t } = useLocale();

  return (
    <li className="flex gap-4 px-5 py-4">
      <span
        aria-hidden
        className={
          done
            ? "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground"
            : "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-input text-sm font-medium text-muted-foreground"
        }
      >
        {done ? <Check className="h-4 w-4" /> : index}
      </span>

      <div className="min-w-0 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className={done ? "font-semibold text-muted-foreground" : "font-semibold"}>{title}</h2>
          <span className="sr-only">{t.overview.stepLabel(index)}</span>
          {optional && (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
              {t.overview.stepOptional}
            </span>
          )}
          {done && <span className="text-xs font-medium text-muted-foreground">{t.overview.stepDone}</span>}
        </div>
        <p className="max-w-2xl text-sm text-muted-foreground">{body}</p>
        {!done && (
          <Link to={href} className={next ? primaryAction : secondaryAction}>
            {action}
          </Link>
        )}
      </div>
    </li>
  );
}

/**
 * The empty state, which is the state every new pod opens in and therefore the most
 * designed one on this page (#104).
 *
 * Every check mark comes from an endpoint — a connection exists, a sync has landed, a
 * destination is configured. Nothing here is remembered in a cookie or in
 * localStorage: a browser's memory of what someone did is not evidence that the pod is
 * in that state, and the first time those two disagree the stepper would be lying about
 * the product's own configuration.
 *
 * `destinationAdded` is null when the signed-in role cannot read destinations. The
 * optional step is then hidden rather than shown unchecked — an unverifiable claim
 * about state is worse than no claim.
 */
export function SetupStepper({ connected, synced, destinationAdded }: {
  connected: boolean;
  synced: boolean;
  destinationAdded: boolean | null;
}) {
  const { t } = useLocale();
  // The required steps decide what "next" is; the optional one never competes for it.
  const nextIndex = !connected ? 1 : !synced ? 2 : 0;

  return (
    <section className="space-y-6">
      <div className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">{t.overview.setupEyebrow}</p>
        <h1 className="text-3xl font-bold tracking-tight">{t.overview.setupTitle}</h1>
        <p className="max-w-2xl text-lg text-muted-foreground">{t.overview.promise}</p>
      </div>

      <ol className="divide-y rounded-lg border bg-card text-card-foreground shadow-sm">
        <Step
          index={1}
          title={t.overview.step1Title}
          body={t.overview.step1Body}
          action={t.overview.step1Action}
          href="/settings/connections"
          done={connected}
          next={nextIndex === 1}
        />
        <Step
          index={2}
          title={t.overview.step2Title}
          body={t.overview.step2Body}
          action={t.overview.step2Action}
          href="/settings/connections"
          done={synced}
          next={nextIndex === 2}
        />
        {destinationAdded !== null && (
          <Step
            index={3}
            title={t.overview.step3Title}
            body={t.overview.step3Body}
            action={t.overview.step3Action}
            href="/settings/destinations"
            done={destinationAdded}
            next={false}
            optional
          />
        )}
      </ol>
    </section>
  );
}
