import type { ChangeLevel } from "@/features/changes/types";

/**
 * The alert kind vocabulary, mirroring `KINDS` in `backend/app/alerts/service.py`.
 *
 * Closed, and closed on purpose: a later kind is one more name here, one more entry in
 * that tuple, and a row in `docs/alerts.md` — never a reshape of this type or the row it
 * produces on `/`.
 */
export type AlertKind = "new_app";

/**
 * One latch the product is holding open — or one it has closed.
 *
 * There is no acknowledge here and there never will be: an alert is opened by the sync
 * path when its condition becomes true and closed by the same path when the condition
 * stops being true (`docs/alerts.md` §1). So an open row means "true of the fleet right
 * now", not "somebody has not got to it yet", and nothing in this app may offer a button
 * that pretends otherwise.
 */
export interface Alert {
  id: number;
  kind: AlertKind;
  /** The change log's closed `high | normal | low`, decided by the backend. Never
   *  re-graded on this side — one vocabulary, one owner. */
  level: ChangeLevel;
  deviceId: number;
  /** The device's hostname, joined at read time rather than stored, so a rename shows. */
  deviceLabel: string;
  appHash: string;
  appName: string;
  bundleId: string;
  openedAt: string;
  closedAt: string | null;
}

export interface AlertListResponse {
  items: Alert[];
  /** Every row that matched, not just the page. Needs Attention shows five and counts
   *  the remainder honestly, and a fleet-wide install opens one latch per device — so
   *  the total is what keeps that count from understating the truth. */
  total: number;
  page: number;
  pageSize: number;
}

export interface AlertFilters {
  /** Open latches (the default) or the closed history. */
  open?: boolean;
  kind?: AlertKind;
  page?: number;
  pageSize?: number;
}
