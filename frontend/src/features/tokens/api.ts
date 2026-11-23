import { apiRequest } from "@/config/api";
import type { ApiToken, ApiTokenCreated, CreateTokenInput } from "@/features/tokens/types";

export function listTokens(organizationId?: string): Promise<ApiToken[]> {
  return apiRequest<ApiToken[]>("/auth/tokens", organizationId ? { headers: { "X-Expected-Tenant-ID": organizationId } } : {});
}

export function createToken(input: CreateTokenInput, organizationId?: string): Promise<ApiTokenCreated> {
  return apiRequest<ApiTokenCreated>("/auth/tokens", {
    method: "POST",
    ...(organizationId ? { headers: { "X-Expected-Tenant-ID": organizationId } } : {}),
    json: input
  });
}

export function revokeToken(id: string, organizationId?: string): Promise<void> {
  return apiRequest<void>(`/auth/tokens/${encodeURIComponent(id)}`, {
    method: "DELETE", ...(organizationId ? { headers: { "X-Expected-Tenant-ID": organizationId } } : {}),
  });
}
