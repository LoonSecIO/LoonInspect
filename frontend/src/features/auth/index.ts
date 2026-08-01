export type AuthStatus = "unknown" | "authenticated" | "unauthenticated";

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
}

export interface AuthState {
  status: AuthStatus;
  user: AuthUser | null;
}