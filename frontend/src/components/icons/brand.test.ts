import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// The brand files (#321) live outside src/: index.html links them, and Vite copies
// frontend/public/ into the build verbatim. This lane reads them as bytes.
const frontend = (relative: string) => fileURLToPath(new URL(`../../../${relative}`, import.meta.url));
const text = (relative: string) => readFileSync(frontend(relative), "utf8");

const attributes = (tag: string): Record<string, string> =>
  Object.fromEntries([...tag.matchAll(/([\w:-]+)="([^"]*)"/g)].map((match) => [match[1], match[2]]));

const iconLinks = () =>
  [...text("index.html").matchAll(/<link\b[^>]*>/g)]
    .map((match) => attributes(match[0]))
    .filter((link) => link.rel === "icon" || link.rel === "apple-touch-icon");

/** An href without its `?v=` query: the file it names in public/. */
const withoutQuery = (href: string) => href.split("?")[0];

/** Every `d` in a file, each as its subpaths, whitespace-normalised: the subpath is the
 * unit a favicon may drop but never alter. */
const paths = (source: string) =>
  [...source.matchAll(/\sd="([^"]*)"/g)].map((match) =>
    match[1]
      .split(/(?=M )/)
      .map((part) => part.trim().replace(/\s+/g, " "))
      .filter(Boolean)
  );
const subpaths = (source: string) => paths(source).flat();

/** Every circle, as "cx cy r": the eye, which a favicon may not move or enlarge either. */
const circles = (source: string) =>
  [...source.matchAll(/<circle\b[^>]*>/g)].map((match) => {
    const circle = attributes(match[0]);
    return `${circle.cx} ${circle.cy} ${circle.r}`;
  });

/** PNG chunks in file order, after the 8-byte signature. */
function pngChunks(relative: string) {
  const bytes = readFileSync(frontend(relative));
  expect(bytes.subarray(0, 8)).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const chunks: { type: string; data: Buffer }[] = [];
  for (let offset = 8; offset < bytes.length; ) {
    const length = bytes.readUInt32BE(offset);
    chunks.push({ type: bytes.toString("latin1", offset + 4, offset + 8), data: bytes.subarray(offset + 8, offset + 8 + length) });
    offset += 12 + length;
  }
  return chunks;
}

function pngHeader(relative: string) {
  const [ihdr, ...rest] = pngChunks(relative);
  expect(ihdr.type).toBe("IHDR"); // the PNG spec puts it first
  return {
    width: ihdr.data.readUInt32BE(0),
    height: ihdr.data.readUInt32BE(4),
    colourType: ihdr.data[9],
    chunkTypes: rest.map((chunk) => chunk.type)
  };
}

/** An ICO's directory: a 6-byte header (reserved, type, image count), then 16 bytes an
 * image. A width or height byte of 0 means 256. */
function icoDirectory(relative: string) {
  const bytes = readFileSync(frontend(relative));
  const count = bytes.readUInt16LE(4);
  return {
    reserved: bytes.readUInt16LE(0),
    type: bytes.readUInt16LE(2), // 1 is an icon, 2 a cursor
    images: Array.from({ length: count }, (_, index) => {
      const entry = 6 + index * 16;
      const length = bytes.readUInt32LE(entry + 8);
      const offset = bytes.readUInt32LE(entry + 12);
      return {
        width: bytes[entry] || 256,
        height: bytes[entry + 1] || 256,
        insideFile: length > 0 && offset + length <= bytes.length
      };
    })
  };
}

describe("the favicon wiring in index.html", () => {
  it("links the ICO, the SVG and the touch icon, ICO first so a browser that takes SVG ends on the SVG", () => {
    // Of the icons a browser can use it takes the last in tree order. The ICO says
    // sizes="32x32": "any" would make Chrome prefer it to the SVG.
    expect(iconLinks().map((link) => ({ ...link, href: withoutQuery(link.href) }))).toEqual([
      { rel: "icon", href: "/favicon.ico", sizes: "32x32" },
      { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" },
      { rel: "apple-touch-icon", href: "/apple-touch-icon.png" }
    ]);
  });

  it("every icon link carries a ?v= query, the key a changed mark ships under", () => {
    // A browser keeps a favicon by its URL long after the page reloads (2026-09-15: a
    // new mark stayed invisible in the tab); the query is what a change bumps.
    for (const link of iconLinks()) {
      expect(link.href, link.href).toMatch(/\?v=\d+$/);
    }
  });

  it("the SVG switches to its dark ink itself; no icon link is gated on a media query", () => {
    // Firefox ignores `media` on an icon link and takes the last SVG, so a dark-only
    // second file showed a paper-coloured mark on a light Firefox tab.
    expect(iconLinks().filter((link) => "media" in link)).toEqual([]);
    expect(text("public/favicon.svg")).toMatch(/@media \(prefers-color-scheme: dark\) \{ path \{ fill: #F6F2E7 \} \}/);
  });

  it("every linked file, and the master loon.svg, exists in public/", () => {
    for (const href of [...iconLinks().map((link) => withoutQuery(link.href)), "/loon.svg"]) {
      expect(existsSync(frontend(`public${href}`)), href).toBe(true);
    }
  });
});

describe("the brand files", () => {
  it.each(["favicon.svg", "loon.svg"])("%s has a square viewBox and no editor transform", (file) => {
    const svg = text(`public/${file}`);
    const root = attributes(svg.match(/<svg\b[^>]*>/)?.[0] ?? "");
    const [, , width, height] = (root.viewBox ?? "").split(/[\s,]+/).map(Number);
    expect(width).toBeGreaterThan(0);
    expect(width).toBe(height);
    // The traced files this replaced carried translate/scale transforms (#321).
    expect(svg).not.toMatch(/transform=/);
  });

  it("favicon.ico is a real icon file, with 16, 32 and 48 px images", () => {
    // Browsers ask for /favicon.ico on their own. Without the file the request fell
    // through to the SPA shell and came back 200 text/html.
    expect(icoDirectory("public/favicon.ico")).toEqual({
      reserved: 0,
      type: 1,
      images: [
        { width: 16, height: 16, insideFile: true },
        { width: 32, height: 32, insideFile: true },
        { width: 48, height: 48, insideFile: true }
      ]
    });
  });

  it("apple-touch-icon.png is the 180 px iOS asks for", () => {
    expect(pngHeader("public/apple-touch-icon.png")).toMatchObject({ width: 180, height: 180 });
  });

  it("apple-touch-icon.png carries no alpha: iOS paints transparency black", () => {
    const { colourType, chunkTypes } = pngHeader("public/apple-touch-icon.png");
    // 0 greyscale, 2 truecolour, 3 palette; 4 and 6 carry an alpha channel, and a
    // palette image gets transparency only through a tRNS chunk.
    expect([0, 2, 3]).toContain(colourType);
    expect(chunkTypes).not.toContain("tRNS");
  });

  it("favicon.svg is the loon alone: no hexagon frame, back hexagons or ripples", () => {
    // loon.svg's paths in order: the hexagon frame (outer and inner outline); the body,
    // the wing and the six back hexagons; the two ripples. The favicon keeps two
    // subpaths and the eye (2026-09-15: the frame made the 16 px mark too busy).
    const [frame, [body, wing, ...backHexagons], ...ripples] = paths(text("public/loon.svg"));
    expect(frame).toHaveLength(2);
    expect(backHexagons).toHaveLength(6);
    expect(ripples).toHaveLength(2);
    const kept = subpaths(text("public/favicon.svg"));
    expect(kept.filter((subpath) => frame.includes(subpath))).toEqual([]);
    expect(kept).toEqual([body, wing]);
  });

  it("the favicons and the in-app mark are loon.svg with detail removed, never redrawn", () => {
    const master = new Set(subpaths(text("public/loon.svg")));
    const masterEyes = new Set(circles(text("public/loon.svg")));
    for (const file of ["public/favicon.svg", "src/components/icons/LoonLogo.tsx"]) {
      const kept = subpaths(text(file));
      expect(kept.length, file).toBeGreaterThan(0);
      expect(kept.filter((subpath) => !master.has(subpath)), file).toEqual([]);
      // The eye too: enlarging it so it shows at 16 px would be a redraw.
      expect(circles(text(file)).length, file).toBeGreaterThan(0);
      expect(circles(text(file)).filter((eye) => !masterEyes.has(eye)), file).toEqual([]);
    }
  });
});
