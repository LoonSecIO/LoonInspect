export interface ComplianceRow {
  id: number;
  appName: string;
  compliantDevices: number;
  nonCompliantDevices: number;
}

// Placeholder data for the Compliance stub — replace with a real aggregation
// over installed_apps.is_compliant once we're ready.
export const MOCK_COMPLIANCE: ComplianceRow[] = [
  { id: 1, appName: "Google Chrome", compliantDevices: 214, nonCompliantDevices: 0 },
  { id: 2, appName: "Zoom", compliantDevices: 151, nonCompliantDevices: 47 },
  { id: 3, appName: "Slack", compliantDevices: 176, nonCompliantDevices: 0 },
  { id: 4, appName: "1Password 8", compliantDevices: 140, nonCompliantDevices: 12 }
];

export function complianceRate(row: ComplianceRow): number {
  const total = row.compliantDevices + row.nonCompliantDevices;
  if (total === 0) return 0;
  return Math.round((row.compliantDevices / total) * 100);
}
