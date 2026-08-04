import { apiRequest } from "@/config/api";
import type { ApiToken, ApiTokenCreated, CreateTokenInput } from "@/features/tokens/types";

export function listTokens(): Promise<ApiToken[]> {
  return apiRequest<ApiToken[]>("/auth/tokens");
}

export function createToken(input: CreateTokenInput): Promise<ApiTokenCreated> {
  return apiRequest<ApiTokenCreated>("/auth/tokens", {
    method: "POST",
    json: input
  });
}

export function revokeToken(id: string): Promise<void> {
  return apiRequest<void>(`/auth/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
}
