export interface Account {
  id: string;
  email: string;
  displayName: string;
  status: string;
  roles: string[];
  isBreakGlass: boolean;
  isServiceAccount: boolean;
  /** Non-null means an external system owns this record; local edits to the fields it
   *  manages get reverted on the next sync. */
  externalSource: string | null;
  createdAt: string;
  lastLoginAt: string | null;
  /** A confirmed second factor guards this account's sign-in (#653): what "Remove second factor" removes. */
  mfaEnrolled: boolean;
}

export interface CreateAccountInput {
  email: string;
  displayName: string;
  password: string;
  roles: string[];
}

export interface UpdateAccountInput {
  displayName?: string;
  status?: string;
  roles?: string[];
}

/** Mirrors app/core/permissions.py Role. */
export const ROLES = ["admin", "analyst", "auditor", "viewer"] as const;

/** Two-step sign-in (#653), as `GET /api/auth/mfa` answers it (app/schemas/mfa.py). */
export interface MfaStatus {
  enrolled: boolean;
  /** Set-up was started and never proved by a code, so the factor is still off. */
  pending: boolean;
  confirmedAt: string | null;
  recoveryCodesRemaining: number;
}

/** Shown once: the secret as text and as the otpauth:// URL the QR code carries. */
export interface MfaEnrolment {
  secret: string;
  otpauthUrl: string;
}

/** Shown once: the ten recovery codes, each good for one sign-in without the phone. */
export interface MfaConfirmation {
  recoveryCodes: string[];
  confirmedAt: string;
}
