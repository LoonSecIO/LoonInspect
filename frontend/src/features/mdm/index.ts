export type MdmProvider = "jamf" | "simplemdm" | "addigy" | "fleet" | "nano";

export interface MdmSyncStatus {
  provider: MdmProvider;
  lastSyncAt: string | null;
  status: "idle" | "syncing" | "failed";
  deviceCount: number;
}