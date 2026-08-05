import { Route, Routes } from "react-router";
import { App } from "@/App";
import { AccountsPage } from "@/features/accounts/AccountsPage";
import { MyAccountPage } from "@/features/accounts/MyAccountPage";
import { LoginPage } from "@/features/auth/LoginPage";
import { RequireAuth } from "@/features/auth/RequireAuth";
import { RequirePermission } from "@/features/auth/RequirePermission";
import { SetupPage } from "@/features/auth/SetupPage";
import { PERMISSIONS } from "@/features/auth/types";
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
import { ApiTokensPage } from "@/features/tokens/ApiTokensPage";
import { VulnerabilitiesPage } from "@/features/vulnerabilities/VulnerabilitiesPage";
import { JamfPatchPage } from "@/features/jamfPatch/JamfPatchPage";
import { JamfPatchDetailPage } from "@/features/jamfPatch/JamfPatchDetailPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/setup" element={<SetupPage />} />

      {/* Everything below renders only once RequireAuth has confirmed a session.
          The server enforces this independently — this guard is for the UI, not
          the security boundary. */}
      <Route element={<RequireAuth />}>
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
        <Route element={<RequirePermission permission={PERMISSIONS.CONNECTION_READ} />}>
          <Route path="settings/connections" element={<ConnectionsPage />} />
        </Route>
        <Route element={<RequirePermission permission={PERMISSIONS.FEATURE_FLAG_WRITE} />}>
          <Route path="settings/feature-flags" element={<FeatureFlagsPage />} />
        </Route>
        <Route element={<RequirePermission permission={PERMISSIONS.TOKEN_CREATE} />}>
          <Route path="settings/api-tokens" element={<ApiTokensPage />} />
        </Route>
        <Route element={<RequirePermission permission={PERMISSIONS.ACCOUNT_READ} />}>
          <Route path="settings/accounts" element={<AccountsPage />} />
        </Route>
        {/* No permission gate — everyone manages their own profile. */}
        <Route path="settings/my-account" element={<MyAccountPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
