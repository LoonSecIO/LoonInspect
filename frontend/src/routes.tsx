import { Route, Routes } from "react-router";
import { App } from "@/App";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { DevicesPage } from "@/features/devices/DevicesPage";
import { ApplicationsPage } from "@/features/devices/ApplicationsPage";
import { GroupsPage } from "@/features/devices/GroupsPage";
import { CompliancePage } from "@/features/devices/CompliancePage";
import { UsersPage } from "@/features/users/UsersPage";
import { IntegrationsPage } from "@/features/integrations/IntegrationsPage";
import { ConnectionsPage } from "@/features/mdm/ConnectionsPage";
import { VulnerabilitiesPage } from "@/features/vulnerabilities/VulnerabilitiesPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<App />}>
        <Route index element={<OverviewPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/applications" element={<ApplicationsPage />} />
        <Route path="devices/groups" element={<GroupsPage />} />
        <Route path="devices/compliance" element={<CompliancePage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="integrations" element={<IntegrationsPage />} />
        <Route path="settings/connections" element={<ConnectionsPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
      </Route>
    </Routes>
  );
}
