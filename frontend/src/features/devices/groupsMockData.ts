export interface DeviceGroup {
  id: number;
  name: string;
  type: "smart" | "static";
  description: string;
  deviceCount: number;
  source: "jamf" | "loonsecio";
}

// Placeholder data for the Groups stub. The backend does observe groups now —
// smart-group definitions are fetched and canonicalized into the observation ledger,
// device records carry group_membership entries, and runs count groups — but no read
// API surfaces any of it yet, so this page still renders these.
export const MOCK_GROUPS: DeviceGroup[] = [
  {
    id: 1,
    name: "Engineering — macOS",
    type: "smart",
    description: "Department is Engineering and OS version is 14.x",
    deviceCount: 84,
    source: "jamf"
  },
  {
    id: 2,
    name: "Non-compliant patch status",
    type: "smart",
    description: "Has one or more apps with a patch available",
    deviceCount: 37,
    source: "loonsecio"
  },
  {
    id: 3,
    name: "Executive devices",
    type: "static",
    description: "Manually assigned",
    deviceCount: 12,
    source: "jamf"
  }
];
