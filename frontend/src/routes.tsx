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
import { SmartGroupCostPage } from "@/features/smartGroups/SmartGroupCostPage";
import { ChangesPage } from "@/features/changes/ChangesPage";
import { ChangeTrackingPage } from "@/features/changes/ChangeTrackingPage";
import { ConnectionsPage } from "@/features/mdm/ConnectionsPage";
import { FeatureFlagsPage } from "@/features/settings/FeatureFlagsPage";
import { DataSharingPage } from "@/features/system/DataSharingPage";
import { ApiTokensPage } from "@/features/tokens/ApiTokensPage";
import { DestinationsPage } from "@/features/destinations/DestinationsPage";
import { JamfPatchPage } from "@/features/jamfPatch/JamfPatchPage";
import { JamfPatchDetailPage } from "@/features/jamfPatch/JamfPatchDetailPage";
import { CatalogPage } from "@/features/catalog/CatalogPage";
import { SupportPage } from "@/features/support/SupportPage";
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
        {/* No /devices/groups and no /devices/compliance: both rendered rows a
            developer typed (#95). What each promised already exists under a truer
            name — the groups the ledger holds are on the cost page below, and
            per-title devices-on-latest is on Devices › Applications › Jamf Patch,
            from real matching. Either returns only once it can show something
            those two cannot. */}
        <Route path="devices/groups/cost" element={<SmartGroupCostPage />} />
        <Route path="devices/changes" element={<ChangesPage />} />
        {/* No /users route: nothing on the backend serves MDM-synced people, and a
            route rendering an empty table of eight columns Jamf's users would fill
            is a promise, not a page. It comes back with the endpoint (#95). */}
        {/* No /integrations: eleven of its sixteen cards were "coming soon" — one of
            them (Webhook) for a destination type that ships — and the two surfaces
            that connect anything are Settings › Connections and Destinations. The
            vendor marks under public/logos/ are deliberately left in place: the
            page comes back once its grid is mostly real (#95). */}
        {/* No /ai: nothing AI lands before the public flip (#28 is v1). The
            `ai_features` switch under Settings › Feature Flags is where "it's
            coming" lives now that the page does not (#112, #95). */}
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
        {/* Deliberately not wrapped in RequirePermission, unlike every other
            /settings route above (#301). This page exists for the person something
            is already broken for — a Viewer, or somebody whose problem *is* that
            they lack access — and a support page you need a capability to read
            refuses exactly the reader who came to it. It reads nothing privileged:
            /system/version is authenticated-but-unprivileged for this reason, and
            the rest of the page is four links. */}
        <Route path="settings/support" element={<SupportPage />} />
        {/* Still no /vulnerabilities, and #251 is the session that decided so rather
            than deferring again. The corpus edge — covered / unknown_app / off,
            dated by corpusAsOf — is now on Devices › Applications › Catalog, beside
            the apps it is an answer about, because that tab's grain (one row per
            distinct build) is exactly the grain the corpus is keyed on. A page here
            would have been a heading, one date and a link to that table: the "nav
            destination that does nothing" #95 ruled against, and it would have put
            the honest sentence about what we do not know somewhere a person has to
            go looking for it instead of where they are already reading. It comes
            back when it can show something the Catalog tab cannot — the per-finding
            lifecycle records, which are post-v0 (docs/vulnerabilities.md §6). */}
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
