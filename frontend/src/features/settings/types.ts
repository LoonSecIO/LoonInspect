export interface FeatureFlag {
  key: string;
  label: string;
  description: string;
  enabled: boolean;
}

/** Whose sign-in must end in a code from an authenticator app (#653); break-glass accounts are never asked. */
export const MFA_POLICIES = ["off", "admins", "everyone"] as const;
export type MfaPolicy = (typeof MFA_POLICIES)[number];
