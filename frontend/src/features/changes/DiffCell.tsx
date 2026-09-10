import type { DiffLine } from "@/features/changes/render";

/**
 * What moved, field by field. Shared by the Changes table and the device page (#300).
 *
 * Values wrap rather than truncate. The column exists because truncation put an app's new
 * version off the right-hand edge while the two cells beside it stayed identical for their
 * whole visible width — so a cell that runs long here takes a second line instead.
 */
export function DiffCell({ lines }: { lines: DiffLine[] }) {
  // Nothing to pair: the collapsed-system-apps row carries a count and no entry, and its
  // sentence is already printed under What.
  if (lines.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <div className="max-w-sm space-y-0.5 break-words">
      {lines.map((line) => (
        <div key={line.key} className="flex flex-wrap items-baseline gap-x-2">
          {line.label && <span className="text-xs text-muted-foreground">{line.label}</span>}
          <span className="font-mono text-xs">
            {line.pair ? (
              <>
                <span className="text-muted-foreground">{line.from ?? "—"}</span>
                <span className="px-1.5 text-muted-foreground">→</span>
                <span className="font-medium text-foreground">{line.to ?? "—"}</span>
              </>
            ) : (
              (line.from ?? line.to)
            )}
          </span>
        </div>
      ))}
    </div>
  );
}
