export type MdmProviderType = "jamf" | "simplemdm" | "addigy" | "fleet" | "nano";
export type PatchManagementProvider = "none" | "jamf" | "loonsecio";

export interface MdmSyncStatus {
  provider: MdmProviderType;
  lastSyncAt: string | null;
  status: "idle" | "syncing" | "failed";
  deviceCount: number;
}

export interface MdmConnection {
  id: number;
  name: string;
  provider: MdmProviderType;
  baseUrl: string;
  isActive: boolean;
  patchManagementProvider: PatchManagementProvider;
  loonsecioDataSharingEnabled: boolean;
  hasClientSecret: boolean;
  hasApiKey: boolean;
  hasWebhookSecret: boolean;
  hasLoonsecioLicenseKey: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MdmConnectionInput {
  name: string;
  provider: MdmProviderType;
  baseUrl: string;
  isActive?: boolean;
  clientId?: string;
  clientSecret?: string;
  apiKey?: string;
  webhookSecret?: string;
  patchManagementProvider?: PatchManagementProvider;
  loonsecioLicenseKey?: string;
  loonsecioDataSharingEnabled?: boolean;
}
