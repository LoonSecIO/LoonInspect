import type { ReactNode } from "react";

const ISO_DATE = /\d{4}-\d{2}-\d{2}/g;

/**
 * A sentence that may wrap anywhere but inside an ISO date: a browser breaks "2026-09-01" at a hyphen
 * ("2026-" above "09-01") wherever the line runs out, in a list of updates, a fix line or a narrow
 * cell. Each date is a span of its own that does not wrap; the rest of the sentence is plain text.
 */
export function KeepDates({ text }: { text: string }) {
  const parts: ReactNode[] = [];
  let at = 0;
  for (const found of text.matchAll(ISO_DATE)) {
    if (found.index > at) parts.push(text.slice(at, found.index));
    parts.push(<span key={found.index} className="whitespace-nowrap">{found[0]}</span>);
    at = found.index + found[0].length;
  }
  if (at < text.length) parts.push(text.slice(at));
  return <>{parts}</>;
}
