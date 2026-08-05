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
