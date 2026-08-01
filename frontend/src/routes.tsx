import { Route, Routes } from "react-router";
import { App } from "@/App";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { DevicesPage } from "@/features/devices/DevicesPage";
import { ConnectionsPage } from "@/features/mdm/ConnectionsPage";
import { VulnerabilitiesPage } from "@/features/vulnerabilities/VulnerabilitiesPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<App />}>
        <Route index element={<OverviewPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="settings/connections" element={<ConnectionsPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
      </Route>
    </Routes>
  );
}
