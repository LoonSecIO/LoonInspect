/**
 * The loading mark (#720): a node-lane check of the markup `renderToStaticMarkup` produces,
 * since this suite runs with no DOM (vitest.config.ts). `useId` mints whatever this React
 * gives a server render — every assertion reads the id back out of the markup rather than
 * assume its shape, so a future React that mints ids differently does not fail this for the
 * wrong reason.
 */

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { LoonLoading } from "@/components/icons/LoonLoading";

describe("LoonLoading", () => {
  it("renders the caller's label as plain text beside the mark", () => {
    const markup = renderToStaticMarkup(<LoonLoading label="Loading devices…" />);
    expect(markup).toContain("<span>Loading devices…</span>");
  });

  it("hides the mark from assistive tech: the label is what a screen reader gets", () => {
    const markup = renderToStaticMarkup(<LoonLoading label="Loading devices…" />);
    const svg = markup.match(/<svg\b[^>]*>/)?.[0] ?? "";
    expect(svg).toContain('aria-hidden="true"');
    expect(svg).toContain('focusable="false"');
  });

  it("draws the loon once, in <defs>, and both <use> copies reference it", () => {
    const markup = renderToStaticMarkup(<LoonLoading label="x" />);
    const paths = [...markup.matchAll(/<path id="([^"]+)"/g)].map((match) => match[1]);
    expect(paths).toHaveLength(1); // one compound path, never redrawn
    const [id] = paths;
    const uses = [...markup.matchAll(/<use href="#([^"]+)"/g)].map((match) => match[1]);
    expect(uses).toEqual([id, id]); // the rest of the bird, then the back that beats
  });

  it("clips both copies with a clipPath the same svg defines", () => {
    const markup = renderToStaticMarkup(<LoonLoading label="x" />);
    const clipPaths = new Set([...markup.matchAll(/<clipPath id="([^"]+)"/g)].map((match) => match[1]));
    const referenced = [...markup.matchAll(/clip-path="url\(#([^)]+)\)"/g)].map((match) => match[1]);
    expect(referenced).toHaveLength(2);
    for (const id of referenced) expect(clipPaths.has(id), id).toBe(true);
  });

  it("gives two instances on one page different ids, so neither steals the other's clip", () => {
    const markup = renderToStaticMarkup(
      <>
        <LoonLoading label="a" />
        <LoonLoading label="b" />
      </>
    );
    const ids = [...markup.matchAll(/<path id="([^"]+)"/g)].map((match) => match[1]);
    expect(ids).toHaveLength(2);
    expect(ids[0]).not.toBe(ids[1]);
  });
});
