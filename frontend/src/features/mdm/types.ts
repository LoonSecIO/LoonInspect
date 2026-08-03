export type MdmProviderType = "jamf" | "simplemdm" | "addigy" | "nano";
export type PatchManagementProvider = "none" | "jamf" | "loonsecio";

export interface MdmSyncStatus {
  provider: MdmProviderType;
  lastSyncAt: string | null;
  status: "idle" | "syncing" | "failed";
  deviceCount: number;
}

export interface ProviderCredentialField {
  key: string;
  label: string;
  secret: boolean;
}

export interface ProviderInfo {
  provider: MdmProviderType;
  credentialFields: ProviderCredentialField[];
}

export interface MdmConnection {
  id: number;
  name: string;
  provider: MdmProviderType;
  baseUrl: string;
  isActive: boolean;
  patchManagementProvider: PatchManagementProvider;
  loonsecioDataSharingEnabled: boolean;
  credentialFieldsSet: string[];
  hasWebhookSecret: boolean;
  hasLoonsecioLicenseKey: boolean;
  userAgentOverride: string | null;
  capabilityDevices: boolean;
  capabilityUsers: boolean;
  capabilityWebhooks: boolean;
  capabilityJamfPro: boolean;
  lastSuccessfulAuthAt: string | null;
  credentialsRotatedAt: string | null;
  credentialsFingerprint: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MdmConnectionInput {
  name: string;
  provider: MdmProviderType;
  baseUrl: string;
  isActive?: boolean;
  credentials?: Record<string, string>;
  webhookSecret?: string;
  patchManagementProvider?: PatchManagementProvider;
  loonsecioLicenseKey?: string;
  loonsecioDataSharingEnabled?: boolean;
  userAgentOverride?: string;
  capabilityDevices?: boolean;
  capabilityUsers?: boolean;
  capabilityWebhooks?: boolean;
  capabilityJamfPro?: boolean;
}

export interface MdmConnectionTestInput {
  connectionId?: number;
  provider: MdmProviderType;
  baseUrl: string;
  clientId: string;
  clientSecret?: string;
  userAgentOverride?: string;
}

export interface MdmConnectionTestResult {
  success: boolean;
  message: string;
  detail?: string;
}
