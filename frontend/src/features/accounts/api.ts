import { apiRequest } from "@/config/api";
import type { Account, CreateAccountInput, UpdateAccountInput } from "@/features/accounts/types";

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
