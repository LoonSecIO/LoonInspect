import { apiRequest } from "@/config/api";
import type { AuthStatusResponse, AuthUser, SetupInput } from "@/features/auth/types";

export function getAuthStatus(): Promise<AuthStatusResponse> {
  return apiRequest<AuthStatusResponse>("/auth/status");
}

export function getCurrentUser(): Promise<AuthUser> {
  return apiRequest<AuthUser>("/auth/me");
}

export function login(email: string, password: string): Promise<AuthUser> {
  return apiRequest<AuthUser>("/auth/login", {
    method: "POST",
    json: { email, password }
  });
}

export function completeSetup(input: SetupInput): Promise<AuthUser> {
  return apiRequest<AuthUser>("/auth/setup", {
    method: "POST",
    json: input
  });
}

export function logout(): Promise<void> {
  return apiRequest<void>("/auth/logout", { method: "POST" });
}

/** Act for another tenant the account holds a membership in (#36). The server revokes
 *  this session and issues a new one for the target; the caller reloads. */
export function switchTenant(tenantId: string): Promise<AuthUser> {
  return apiRequest<AuthUser>("/auth/switch-tenant", { method: "POST", json: { tenantId } });
}
