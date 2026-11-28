import { create } from "zustand";
import { setUnauthorizedHandler } from "@/config/api";
import * as authApi from "@/features/auth/api";
import { passkeySignInFlow, type PasskeyCopy, type SignInOutcome } from "@/features/auth/passkeys";
import type { AuthStatus, AuthUser, MfaChallenge, PermissionName, SetupInput } from "@/features/auth/types";
import { clearReviewDrafts } from "@/features/catalog/patchPlanDraft";

interface AuthStore {
  status: AuthStatus;
  user: AuthUser | null;
  /** Backend build version from /auth/status; null until the probe returns, and also
   *  null for an anonymous caller on a claimed instance (#130). Only the first-run
   *  setup page reads this — signed-in surfaces use BuildVersion, which asks
   *  /system/version and so is not stale after a login in the same page load. */
  version: string | null;
  bootstrap: () => Promise<void>;
  /** Resolves null once signed in, or with the challenge an account with a second factor
   *  answers first (#653); the store stays signed out until `loginMfa` redeems it. */
  login: (email: string, password: string) => Promise<MfaChallenge | null>;
  loginMfa: (challenge: string, code: string) => Promise<void>;
  /** One passkey sign-in (#955): signed in when the outcome says so, and otherwise left signed out. */
  signInWithPasskey: (mode: "conditional" | "modal", signal: AbortSignal, copy: PasskeyCopy) => Promise<SignInOutcome>;
  refreshUser: () => Promise<void>;
  completeSetup: (input: SetupInput) => Promise<void>;
  logout: () => Promise<void>;
}

export const useAuthStore = create<AuthStore>((set) => ({
  status: "unknown",
  user: null,
  version: null,

  /** Resolves which of the three entry states the app is in, before any route renders.
   *  Called once on mount; /auth/status is public so it works while signed out. */
  async bootstrap() {
    try {
      const status = await authApi.getAuthStatus();
      set({ version: status.version });

      if (status.setupRequired) {
        set({ status: "setup-required", user: null });
        return;
      }

      if (!status.authenticated) {
        set({ status: "unauthenticated", user: null });
        return;
      }

      set({ status: "authenticated", user: await authApi.getCurrentUser() });
    } catch {
      // Including a network failure: treating an unreachable backend as signed-out
      // shows the login page rather than an app shell whose every panel errors.
      set({ status: "unauthenticated", user: null });
    }
  },

  async login(email, password) {
    const answer = await authApi.login(email, password);
    if ("challenge" in answer) return answer.challenge;
    set({ status: "authenticated", user: answer.user });
    return null;
  },

  async loginMfa(challenge, code) {
    // Exactly what a password-only login sets: the second step ends in the same session.
    set({ status: "authenticated", user: await authApi.loginMfa(challenge, code) });
  },

  async signInWithPasskey(mode, signal, copy) {
    const outcome = await passkeySignInFlow(mode, signal, copy);
    // The same session a password sign-in ends in; no code step follows a passkey (#955, default 1).
    if (outcome.kind === "signed-in") set({ status: "authenticated", user: outcome.user });
    return outcome;
  },

  async refreshUser() {
    set({ user: await authApi.getCurrentUser() });
  },

  async completeSetup(input) {
    // Setup signs the new administrator straight in — the server issues the session
    // with the 201, so there's no reason to make them log in again immediately.
    set({ status: "authenticated", user: await authApi.completeSetup(input) });
  },

  async logout() {
    try {
      await authApi.logout();
    } finally {
      // Local state clears even if the request failed, so a user who clicked "sign
      // out" is never left looking at a signed-in UI. Unsaved patch-plan review notes go
      // with the account that typed them: the next person in this tab neither reads them
      // nor gets their prompts. The 401 handler below keeps them for a returning user.
      clearReviewDrafts();
      set({ status: "unauthenticated", user: null });
    }
  }
}));

setUnauthorizedHandler(() => {
  useAuthStore.setState({ status: "unauthenticated", user: null });
});

export const MY_ACCOUNT = "/settings/my-account";
/** While the policy holds this account (#653) the server answers only My Account's set-up, so every other page goes there. */
export function enrolmentRedirect(user: AuthUser | null, pathname: string): string | null {
  return user?.mfaEnrolmentRequired && pathname !== MY_ACCOUNT ? MY_ACCOUNT : null;
}

/** Presentational only. Hiding a control the caller can't use is a courtesy; the
 *  server rejects the request regardless of what the UI chose to render. */
export function useHasPermission(permission: PermissionName): boolean {
  return useAuthStore((state) => state.user?.permissions.includes(permission) ?? false);
}
