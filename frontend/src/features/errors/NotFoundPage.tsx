import { Compass } from "lucide-react";
import { Link, useLocation } from "react-router";
import { useLocale } from "@/i18n/LocaleContext";

/** Rendered for any path the router doesn't recognise.
 *
 *  Mounted inside the authenticated shell, not beside /login. Putting it next to the
 *  public routes was the obvious placement and was rejected: an unmatched path would
 *  then answer "does this address exist?" to anyone who can reach the port — /devices
 *  redirects to sign-in, /nonsense would not — while every real route refuses to say
 *  anything before authentication. Inside the shell, both answers are the same login
 *  redirect, and a signed-in typist still gets the nav and sidebar to click out with.
 */
export function NotFoundPage() {
  const { t } = useLocale();
  const location = useLocation();

  // Capped, and rendered as text — React escapes it, so the cap isn't about injection:
  // it stops a multi-kilobyte URL from pushing the way out off the bottom of the page.
  const requested = `${location.pathname}${location.search}`.slice(0, 120);

  return (
    <section className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed bg-muted/30 px-6 py-16 text-center">
      <Compass className="h-6 w-6 text-muted-foreground" />
      <h1 className="text-lg font-semibold">{t.errors.notFoundTitle}</h1>
      <p className="max-w-md text-sm text-muted-foreground">{t.errors.notFoundDescription}</p>
      <p className="max-w-md text-xs text-muted-foreground">
        {t.errors.notFoundPathLabel}: <code className="break-all text-foreground">{requested}</code>
      </p>
      <Link to="/" className="text-sm font-medium hover:underline">
        {t.errors.backToOverview}
      </Link>
    </section>
  );
}
