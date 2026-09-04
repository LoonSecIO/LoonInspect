import type { ReactNode } from "react";
import { ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { useLocale } from "@/i18n/LocaleContext";

interface ExternalLinkProps {
  href: string;
  className?: string;
  children: ReactNode;
}

/** The first anchor tags in this codebase are on the Support page, so the house
 *  pattern for leaving the app is decided here, once:
 *
 *  - `target="_blank"` — the app is a session someone is in the middle of. A support
 *    link that navigates away from a half-filled connection form costs them the form.
 *  - `rel="noopener noreferrer"` — `noopener` severs `window.opener` so the opened
 *    page cannot reach back into this tab; `noreferrer` keeps this instance's own
 *    hostname out of the request. A self-hosted deployment's URL is nobody else's
 *    business, and an air-gapped one is entitled to have its link simply fail rather
 *    than announce itself first.
 *  - The new tab is announced to screen readers rather than left as a surprise, and
 *    the arrow glyph is decorative.
 *
 *  Internal navigation keeps using react-router's `NavLink`/`Link`; this is only for
 *  destinations outside the app.
 */
export function ExternalLink({ href, className, children }: ExternalLinkProps) {
  const { t } = useLocale();

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={cn(
        "inline-flex items-center gap-1 font-medium text-primary underline underline-offset-4 hover:no-underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        className
      )}
    >
      {children}
      <ArrowUpRight aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
      <span className="sr-only"> {t.common.opensInNewTab}</span>
    </a>
  );
}
