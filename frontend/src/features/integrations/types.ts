import type { Translations } from "@/i18n/en";

export type IntegrationStatus = "available" | "comingSoon";
export type VendorId = keyof Translations["integrations"]["vendors"];
export type GroupId = keyof Translations["integrations"]["groups"];

export interface IntegrationVendor {
  id: VendorId;
  status: IntegrationStatus;
  href?: string;
  logoUrl?: string;
  logoUrlDark?: string;
}

export interface IntegrationGroup {
  id: GroupId;
  vendors: IntegrationVendor[];
}
