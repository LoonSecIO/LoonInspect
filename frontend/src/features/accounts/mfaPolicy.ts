import { sentence } from "@/features/accounts/twoStep";
import { useAuthStore } from "@/features/auth/store";
import { putMfaPolicy } from "@/features/settings/api";
import type { MfaPolicy } from "@/features/settings/types";

/** Sets the policy (#653). It holds its setter too, so the account is read again: held, it is routed to My Account. */
export async function savePolicy(policy: MfaPolicy, fallback: string): Promise<{ policy: MfaPolicy } | { error: string }> {
  try {
    const saved = await putMfaPolicy(policy);
    await useAuthStore.getState().refreshUser().catch(() => undefined);
    return { policy: saved.mfaRequired };
  } catch (caught) {
    return { error: sentence(caught, fallback) };
  }
}
