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
import { SmartGroupCostPage } from "@/features/smartGroups/SmartGroupCostPage";
import { CompliancePage } from "@/features/devices/CompliancePage";
import { IntegrationsPage } from "@/features/integrations/IntegrationsPage";
import { AIPage } from "@/features/ai/AIPage";
import { ChangesPage } from "@/features/changes/ChangesPage";
import { ChangeTrackingPage } from "@/features/changes/ChangeTrackingPage";
import { ConnectionsPage } from "@/features/mdm/ConnectionsPage";
import { FeatureFlagsPage } from "@/features/settings/FeatureFlagsPage";
import { DataSharingPage } from "@/features/system/DataSharingPage";
import { ApiTokensPage } from "@/features/tokens/ApiTokensPage";
import { DestinationsPage } from "@/features/destinations/DestinationsPage";
import { VulnerabilitiesPage } from "@/features/vulnerabilities/VulnerabilitiesPage";
import { JamfPatchPage } from "@/features/jamfPatch/JamfPatchPage";
import { JamfPatchDetailPage } from "@/features/jamfPatch/JamfPatchDetailPage";
import { CatalogPage } from "@/features/catalog/CatalogPage";
import { NotFoundPage } from "@/features/errors/NotFoundPage";

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
          <Route path="catalog" element={<CatalogPage />} />
          <Route path="jamf-patch" element={<JamfPatchPage />} />
          <Route path="jamf-patch/:titleId" element={<JamfPatchDetailPage />} />
        </Route>
        <Route path="devices/groups" element={<GroupsPage />} />
        <Route path="devices/groups/cost" element={<SmartGroupCostPage />} />
        <Route path="devices/compliance" element={<CompliancePage />} />
        <Route path="devices/changes" element={<ChangesPage />} />
        {/* No /users route: nothing on the backend serves MDM-synced people, and a
            route rendering an empty table of eight columns Jamf's users would fill
            is a promise, not a page. It comes back with the endpoint (#95). */}
        <Route path="integrations" element={<IntegrationsPage />} />
        <Route path="ai" element={<AIPage />} />
        <Route element={<RequirePermission permission={PERMISSIONS.CONNECTION_READ} />}>
          <Route path="settings/connections" element={<ConnectionsPage />} />
          <Route path="settings/change-tracking" element={<ChangeTrackingPage />} />
        </Route>
        <Route element={<RequirePermission permission={PERMISSIONS.FEATURE_FLAG_WRITE} />}>
          <Route path="settings/feature-flags" element={<FeatureFlagsPage />} />
        </Route>
        {/* SYSTEM_READ to match the backend's GET gate and the sidebar item — the
            page itself hides its write controls without SYSTEM_WRITE. */}
        <Route element={<RequirePermission permission={PERMISSIONS.SYSTEM_READ} />}>
          <Route path="settings/data-sharing" element={<DataSharingPage />} />
        </Route>
        <Route element={<RequirePermission permission={PERMISSIONS.TOKEN_CREATE} />}>
          <Route path="settings/api-tokens" element={<ApiTokensPage />} />
        </Route>
        <Route element={<RequirePermission permission={PERMISSIONS.ACCOUNT_READ} />}>
          <Route path="settings/accounts" element={<AccountsPage />} />
        </Route>
        <Route element={<RequirePermission permission={PERMISSIONS.DESTINATION_READ} />}>
          <Route path="settings/destinations" element={<DestinationsPage />} />
        </Route>
        {/* No permission gate — everyone manages their own profile. */}
        <Route path="settings/my-account" element={<MyAccountPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
        {/* Last child on purpose, and inside the shell rather than beside /login: a
            signed-out visitor keeps getting the same sign-in redirect for a typo as
            for a real page, so an unmatched path never reveals which paths exist.
            Route ranking, not order, is what keeps this from shadowing anything —
            react-router scores a static segment above a splat, so /login and every
            route above still win. */}
        <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
