import { listPasskeys, passkeyRegistrationOptions, removePasskey, savePasskey } from "@/features/accounts/api";
import type { Passkey } from "@/features/accounts/types";
import { answerError, ceremonyError, createPasskey } from "@/features/auth/passkeys";
import { useAuthStore } from "@/features/auth/store";
import type { Translations } from "@/i18n/en";

/**
 * My Account's passkey panel (#955) as moves the node test lane can walk, in the shape of the two-step panel
 * (twoStep.ts): closed → form (a name and the current password) → the browser's ceremony → closed with a notice;
 * closed → confirm a removal → closed. `refresh` asks the page to read the list again. Every refusal is the
 * server's sentence where it gave one, or the page's own for what the browser ended (auth.passkeys).
 */
export type PasskeyRead = { state: "loading" } | { state: "failed" } | { state: "ready"; passkeys: Passkey[] };

export type PasskeyPanel =
  | { step: "closed"; error: string | null; notice: string | null }
  | { step: "form"; error: string | null }
  | { step: "remove"; passkey: Passkey; error: string | null };

export type PasskeyMove = { panel: PasskeyPanel; refresh: boolean };

export const PANEL_CLOSED: PasskeyPanel = { step: "closed", error: null, notice: null };

export function readPasskeys(): Promise<PasskeyRead> {
  return listPasskeys().then(
    (passkeys): PasskeyRead => ({ state: "ready", passkeys }),
    (): PasskeyRead => ({ state: "failed" })
  );
}

/** Add a passkey: the current password earns a challenge, the browser makes the passkey, the server adds it. A
 *  refusal at any step keeps the form up with its sentence; the name and the password stay for another try. */
export async function addPasskey(name: string, currentPassword: string, t: Translations, origin: string): Promise<PasskeyMove> {
  const copy = t.auth.passkeys;
  let options: PublicKeyCredentialCreationOptionsJSON;
  try {
    options = (await passkeyRegistrationOptions(currentPassword)).publicKey;
  } catch (caught) {
    return { panel: { step: "form", error: answerError(caught, copy) }, refresh: false };
  }
  let credential: RegistrationResponseJSON;
  try {
    credential = await createPasskey(options);
  } catch (caught) {
    return { panel: { step: "form", error: ceremonyError(caught, copy, "add", origin) ?? copy.cancelledAdd }, refresh: false };
  }
  try {
    const added = await savePasskey(name, credential);
    // A policy that held this account lets go now, the way a confirmed code does (#653): read who it is again.
    if (useAuthStore.getState().user?.mfaEnrolmentRequired) await useAuthStore.getState().refreshUser().catch(() => undefined);
    return { panel: { step: "closed", error: null, notice: t.myAccount.passkeys.addedNotice(added.name) }, refresh: true };
  } catch (caught) {
    return { panel: { step: "form", error: answerError(caught, copy) }, refresh: false };
  }
}

/** Remove one passkey. Every session it signed in ends, so this one may have: the auth store asks again whether
 *  this browser is still signed in, and the sign-in page follows when it is not. */
export async function dropPasskey(passkey: Passkey, t: Translations): Promise<PasskeyMove> {
  try {
    await removePasskey(passkey.id);
  } catch (caught) {
    return { panel: { step: "remove", passkey, error: answerError(caught, t.auth.passkeys) }, refresh: false };
  }
  await useAuthStore.getState().bootstrap();
  return { panel: PANEL_CLOSED, refresh: true };
}
