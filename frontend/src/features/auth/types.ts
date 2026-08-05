/** "unknown" is the pre-bootstrap state. It exists so a page refresh renders a
 *  loading state rather than flashing the login screen at someone already signed in. */
export type AuthStatus = "unknown" | "setup-required" | "authenticated" | "unauthenticated";

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
  roles: string[];
  /** Effective permissions resolved server-side from roles. Used only to decide what
   *  to render — the API enforces the same rules independently. */
  permissions: string[];
  isBreakGlass: boolean;
}

/** Mirrors app/core/permissions.py. Hand-maintained: these strings must match the
 *  backend enum values exactly, since a typo here fails open in the UI (the API still
 *  refuses, but the user gets a 403 instead of a hidden control). */
export const PERMISSIONS = {
  DEVICE_READ: "device:read",
  APP_READ: "app:read",
  VULN_READ: "vuln:read",
  CONNECTION_READ: "connection:read",
  CONNECTION_WRITE: "connection:write",
  CONNECTION_CREDENTIAL_READ: "connection:credential-read",
  PATCH_CATALOG_SYNC: "patch:catalog-sync",
  DEVICE_SYNC: "device:sync",
  FEATURE_FLAG_WRITE: "feature-flag:write",
  ACCOUNT_READ: "account:read",
  ACCOUNT_WRITE: "account:write",
  AUDIT_READ: "audit:read",
  TOKEN_CREATE: "token:create"
} as const;

export type PermissionName = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export interface AuthStatusResponse {
  setupRequired: boolean;
  authenticated: boolean;
}

export interface SetupInput {
  claimToken: string;
  email: string;
  displayName: string;
  password: string;
}
