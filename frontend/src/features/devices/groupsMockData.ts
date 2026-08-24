export interface DeviceGroup {
  id: number;
  name: string;
  type: "smart" | "static";
  description: string;
  deviceCount: number;
  source: "jamf" | "loonsecio";
}

// Placeholder data for the Groups stub — no backend concept for device groups
// exists yet (DeviceFilterCriteria is the closest analogue, see backend/app/schemas/devices.py).
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
