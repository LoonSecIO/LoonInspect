export interface DetectedUser {
  id: number;
  displayName: string;
  username: string;
  email: string | null;
  department: string | null;
  source: "jamf";
  assignedDevices: string[];
  loggedInDevices: string[];
  lastSeenAt: string | null;
}

// Placeholder data for the Users stub — replace with a real /api/users endpoint
// once we sync assigned/logged-in user fields from each MDM provider.
export const MOCK_USERS: DetectedUser[] = [
  {
    id: 1,
    displayName: "Alicia Reyes",
    username: "areyes",
    email: "alicia.reyes@example.com",
    department: "Engineering",
    source: "jamf",
    assignedDevices: ["AREYES-MBP14"],
    loggedInDevices: ["AREYES-MBP14"],
    lastSeenAt: "2026-07-30T14:22:00Z"
  },
  {
    id: 2,
    displayName: "Marcus Chen",
    username: "mchen",
    email: "marcus.chen@example.com",
    department: "Sales",
    source: "jamf",
    assignedDevices: ["MCHEN-MBA13"],
    loggedInDevices: [],
    lastSeenAt: "2026-07-28T09:05:00Z"
  },
  {
    id: 3,
    displayName: "Priya Natarajan",
    username: "pnatarajan",
    email: "priya.natarajan@example.com",
    department: "IT",
    source: "jamf",
    assignedDevices: ["PNAT-MBP16", "PNAT-IPAD"],
    loggedInDevices: ["PNAT-MBP16"],
    lastSeenAt: "2026-08-01T18:47:00Z"
  }
];
