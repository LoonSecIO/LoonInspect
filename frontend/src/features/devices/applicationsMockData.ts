export interface FleetApplication {
  id: number;
  name: string;
  bundleId: string;
  version: string;
  installCount: number;
  compliant: boolean | null;
  patchAvailable: boolean | null;
}

// Placeholder data for the Applications stub — replace with a real
// /api/applications endpoint that aggregates installed_apps once we're ready.
export const MOCK_APPLICATIONS: FleetApplication[] = [
  {
    id: 1,
    name: "Google Chrome",
    bundleId: "com.google.Chrome",
    version: "127.0.6533.89",
    installCount: 214,
    compliant: true,
    patchAvailable: false
  },
  {
    id: 2,
    name: "Zoom",
    bundleId: "us.zoom.xos",
    version: "6.1.6",
    installCount: 198,
    compliant: false,
    patchAvailable: true
  },
  {
    id: 3,
    name: "Slack",
    bundleId: "com.tinyspeck.slackmacgap",
    version: "4.39.95",
    installCount: 176,
    compliant: true,
    patchAvailable: false
  },
  {
    id: 4,
    name: "1Password 8",
    bundleId: "com.1password.1password",
    version: "8.10.36",
    installCount: 152,
    compliant: null,
    patchAvailable: null
  }
];
