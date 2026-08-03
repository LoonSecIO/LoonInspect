import { Route, Routes } from "react-router";
import { App } from "@/App";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { DevicesPage } from "@/features/devices/DevicesPage";
import { ApplicationsPage } from "@/features/devices/ApplicationsPage";
import { ApplicationsOverviewPage } from "@/features/devices/ApplicationsOverviewPage";
import { GroupsPage } from "@/features/devices/GroupsPage";
import { CompliancePage } from "@/features/devices/CompliancePage";
import { UsersPage } from "@/features/users/UsersPage";
import { IntegrationsPage } from "@/features/integrations/IntegrationsPage";
import { ConnectionsPage } from "@/features/mdm/ConnectionsPage";
import { FeatureFlagsPage } from "@/features/settings/FeatureFlagsPage";
import { VulnerabilitiesPage } from "@/features/vulnerabilities/VulnerabilitiesPage";
import { JamfPatchPage } from "@/features/jamfPatch/JamfPatchPage";
import { JamfPatchDetailPage } from "@/features/jamfPatch/JamfPatchDetailPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<App />}>
        <Route index element={<OverviewPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/applications" element={<ApplicationsPage />}>
          <Route index element={<ApplicationsOverviewPage />} />
          <Route path="jamf-patch" element={<JamfPatchPage />} />
          <Route path="jamf-patch/:titleId" element={<JamfPatchDetailPage />} />
        </Route>
        <Route path="devices/groups" element={<GroupsPage />} />
        <Route path="devices/compliance" element={<CompliancePage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="integrations" element={<IntegrationsPage />} />
        <Route path="settings/connections" element={<ConnectionsPage />} />
        <Route path="settings/feature-flags" element={<FeatureFlagsPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
      </Route>
    </Routes>
  );
}
