import { create } from "zustand";
import { setUnauthorizedHandler } from "@/config/api";
import * as authApi from "@/features/auth/api";
import type { AuthStatus, AuthUser, PermissionName, SetupInput } from "@/features/auth/types";

interface AuthStore {
  status: AuthStatus;
  user: AuthUser | null;
  bootstrap: () => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  completeSetup: (input: SetupInput) => Promise<void>;
  logout: () => Promise<void>;
}

export const useAuthStore = create<AuthStore>((set) => ({
  status: "unknown",
  user: null,

  /** Resolves which of the three entry states the app is in, before any route renders.
   *  Called once on mount; /auth/status is public so it works while signed out. */
  async bootstrap() {
    try {
      const status = await authApi.getAuthStatus();

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
    set({ status: "authenticated", user: await authApi.login(email, password) });
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
      // out" is never left looking at a signed-in UI.
      set({ status: "unauthenticated", user: null });
    }
  }
}));

setUnauthorizedHandler(() => {
  useAuthStore.setState({ status: "unauthenticated", user: null });
});

/** Presentational only. Hiding a control the caller can't use is a courtesy; the
 *  server rejects the request regardless of what the UI chose to render. */
export function useHasPermission(permission: PermissionName): boolean {
  return useAuthStore((state) => state.user?.permissions.includes(permission) ?? false);
}
