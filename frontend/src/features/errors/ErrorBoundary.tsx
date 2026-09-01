import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useLocale } from "@/i18n/LocaleContext";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Clears an error already on screen when it changes. The in-shell mount passes the
   *  route path, so navigating away from a broken page recovers without a reload.
   *  Rejected alternative: `key={pathname}` on the boundary. It clears the error too,
   *  but it also remounts the entire page subtree on every navigation — including the
   *  Applications tabs, which change the path while keeping one parent mounted. */
  resetKey?: string;
}

interface ErrorBoundaryState {
  failed: boolean;
}

/** What the user sees instead of a blank document.
 *
 *  Deliberately says nothing about the exception. A render-time throw in this app is
 *  usually a component reading a field of an API response that isn't shaped the way it
 *  expected, and the message, the stack frames and the props all routinely quote that
 *  response — device serials, account emails, connection names. None of it belongs on
 *  a screen someone might be sharing, so the detail goes to the console and the page
 *  gets a fixed string.
 */
function RenderFailure() {
  const { t } = useLocale();

  return (
    <section
      role="alert"
      className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-6 py-16 text-center"
    >
      <AlertTriangle className="h-6 w-6 text-destructive" />
      <h1 className="text-lg font-semibold">{t.errors.crashTitle}</h1>
      <p className="max-w-md text-sm text-muted-foreground">{t.errors.crashDescription}</p>
      <p className="max-w-md text-xs text-muted-foreground">{t.errors.crashDetailNote}</p>
      <div className="flex items-center gap-2">
        {/* Document loads, not router navigation. At the outer mount there is no route
            change to reset on, and a client-side navigate leaves behind whatever module
            or store state produced the throw — which is how a "recovered" page throws
            again on the next render. A reload is the only recovery that is correct at
            both mounts. */}
        <Button size="sm" onClick={() => window.location.reload()}>
          {t.errors.reload}
        </Button>
        <Button size="sm" variant="outline" onClick={() => window.location.assign("/")}>
          {t.errors.backToOverview}
        </Button>
      </div>
    </section>
  );
}

/** Catches render-time exceptions in its subtree.
 *
 *  Without one, React 18+ unmounts the whole tree on an uncaught render error and the
 *  user is left looking at an empty <body> with the only diagnosis in the console.
 *
 *  Must be mounted inside LocaleProvider: the fallback reads the dictionary through
 *  useLocale(), which throws without it — and a fallback that throws is the blank page
 *  again, one level up.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { failed: false };

  // Keeps a flag, not the error. Holding the Error in state is how its message ends up
  // rendered by the next person to touch the fallback; there is nothing to leak if the
  // component never has it.
  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    // The only place the detail goes. Console, not the DOM, and not an upload: this is
    // a self-hosted product and nothing here phones home.
    console.error("[LoonInspect] a component failed to render", error, info.componentStack);
  }

  componentDidUpdate(previous: ErrorBoundaryProps) {
    if (this.state.failed && previous.resetKey !== this.props.resetKey) {
      this.setState({ failed: false });
    }
  }

  render() {
    return this.state.failed ? <RenderFailure /> : this.props.children;
  }
}
