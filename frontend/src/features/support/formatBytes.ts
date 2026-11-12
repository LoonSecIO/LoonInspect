/** Bytes the way README.md and KNOWN_ISSUES.md count them: GB = 10⁹, one decimal (#786). */
export function formatBytes(bytes: number, locale: string): string {
  const fmt = (n: number) => new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(n);
  if (bytes >= 1e9) return `${fmt(bytes / 1e9)} GB`;
  if (bytes >= 1e6) return `${fmt(bytes / 1e6)} MB`;
  return `${fmt(bytes / 1e3)} kB`;
}
