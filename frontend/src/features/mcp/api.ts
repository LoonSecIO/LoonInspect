import { apiRequest } from "@/config/api";

export interface McpSettings {
  organizationId: string;
  enabled: boolean;
  aiFeaturesEnabled: boolean;
  canManage: boolean;
  endpoint: string;
  scopes: { value: string; label: string; description: string }[];
  requiredScopes: string[];
  disclosure: string;
}

const organizationHeader = (organizationId: string) => ({ "X-Expected-Tenant-ID": organizationId });

export function getMcpSettings(organizationId: string): Promise<McpSettings> {
  return apiRequest("/mcp/settings", { headers: organizationHeader(organizationId) });
}

export function updateMcpSettings(organizationId: string, enabled: boolean): Promise<McpSettings> {
  return apiRequest("/mcp/settings", { method: "PATCH", headers: organizationHeader(organizationId), json: { enabled } });
}

export function testMcpConnection(organizationId: string, token: string): Promise<{ ok: boolean; toolCount: number; organizationId: string }> {
  return apiRequest("/mcp/test", { method: "POST", headers: organizationHeader(organizationId), json: { token } });
}
