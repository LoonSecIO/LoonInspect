import { apiRequest } from "@/config/api";
import type { AuthStatusResponse, AuthUser, LoginAnswer, MfaChallenge, SetupInput } from "@/features/auth/types";

export function getAuthStatus(): Promise<AuthStatusResponse> {
  return apiRequest<AuthStatusResponse>("/auth/status");
}

export function getCurrentUser(): Promise<AuthUser> {
  return apiRequest<AuthUser>("/auth/me");
}

/** The password step. An account with a second factor is answered HTTP 202 with a
 *  challenge instead of a session (#653); `apiRequest` hands back any 2xx body alike, so
 *  the body tells the two apart: only a challenge has a `challenge`. */
export async function login(email: string, password: string): Promise<LoginAnswer> {
  const body = await apiRequest<AuthUser | MfaChallenge>("/auth/login", {
    method: "POST",
    json: { email, password }
  });
  return "challenge" in body ? { challenge: body } : { user: body };
}

/** The second step: the challenge and a six-digit code or a recovery code. Answers as a
 *  password-only sign-in does; a refusal is a 401 whose sentence is the server's. */
export function loginMfa(challenge: string, code: string): Promise<AuthUser> {
  return apiRequest<AuthUser>("/auth/login/mfa", {
    method: "POST",
    json: { challenge, code }
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
