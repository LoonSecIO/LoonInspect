import { apiRequest } from "@/config/api";
import type { Account, CreateAccountInput, MfaConfirmation, MfaEnrolment, MfaStatus, UpdateAccountInput } from "@/features/accounts/types";

export function listAccounts(): Promise<Account[]> {
  return apiRequest<Account[]>("/accounts");
}

export function createAccount(input: CreateAccountInput): Promise<Account> {
  return apiRequest<Account>("/accounts", { method: "POST", json: input });
}

export function updateAccount(id: string, input: UpdateAccountInput): Promise<Account> {
  return apiRequest<Account>(`/accounts/${encodeURIComponent(id)}`, {
    method: "PATCH",
    json: input
  });
}

export function resetPassword(id: string, newPassword: string): Promise<void> {
  return apiRequest<void>(`/accounts/${encodeURIComponent(id)}/reset-password`, {
    method: "POST",
    json: { newPassword }
  });
}

export function changeOwnPassword(currentPassword: string, newPassword: string): Promise<void> {
  return apiRequest<void>("/auth/change-password", {
    method: "POST",
    json: { currentPassword, newPassword }
  });
}

/** Two-step sign-in (#653): whether this account has a second factor, and its recovery codes left. */
export function getMfaStatus(): Promise<MfaStatus> {
  return apiRequest<MfaStatus>("/auth/mfa");
}

/** A fresh secret, shown once. A browser session only (a bearer token is refused); 409 once confirmed. */
export function enrolMfa(): Promise<MfaEnrolment> {
  return apiRequest<MfaEnrolment>("/auth/mfa/enrol", { method: "POST" });
}

/** The code that proves the phone holds the secret; answers with the recovery codes, once. */
export function confirmMfa(code: string): Promise<MfaConfirmation> {
  return apiRequest<MfaConfirmation>("/auth/mfa/confirm", { method: "POST", json: { code } });
}

export function regenerateRecoveryCodes(code: string): Promise<MfaConfirmation> {
  return apiRequest<MfaConfirmation>("/auth/mfa/recovery-codes", { method: "POST", json: { code } });
}

/** The lost-phone path, never one's own: every session of the account ends, and it signs in with the password. */
export function removeSecondFactor(id: string): Promise<void> {
  return apiRequest<void>(`/accounts/${encodeURIComponent(id)}/mfa`, { method: "DELETE" });
}
