import type { PropsWithChildren } from "react";

/** The page area beside the sidebar. `min-w-0` is load-bearing (#349): a flex item's
 *  default `min-width: auto` is its content's min-content width, and a table's is its
 *  columns, so without it this element grew to fit the widest table on the page — 1024px
 *  on a 375px phone — and every `overflow-x-auto` wrapper around a table had nothing to
 *  scroll. With it the wrappers scroll and the page stays as wide as the viewport. */
export function MainContainer({ children }: PropsWithChildren) {
  return <main className="min-w-0 flex-1 p-4">{children}</main>;
}
