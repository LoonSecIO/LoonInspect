import { Navigate, Route, Routes } from "react-router";
import { App } from "@/App";
import { AccountsPage } from "@/features/accounts/AccountsPage";
import { MyAccountPage } from "@/features/accounts/MyAccountPage";
import { LoginPage } from "@/features/auth/LoginPage";
import { RequireAuth } from "@/features/auth/RequireAuth";
import { RequireFlag } from "@/features/auth/RequireFlag";
import { RequirePermission } from "@/features/auth/RequirePermission";
import { SetupPage } from "@/features/auth/SetupPage";
import { PERMISSIONS } from "@/features/auth/types";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { DevicesPage } from "@/features/devices/DevicesPage";
import { DevicePage } from "@/features/devices/DevicePage";
import { ApplicationsPage } from "@/features/devices/ApplicationsPage";
import { ApplicationsOverviewPage } from "@/features/devices/ApplicationsOverviewPage";
import { ApplicationRecordPage } from "@/features/devices/ApplicationRecordPage";
import { SmartGroupCostPage } from "@/features/smartGroups/SmartGroupCostPage";
import { ChangesPage } from "@/features/changes/ChangesPage";
import { ChangeTrackingPage } from "@/features/changes/ChangeTrackingPage";
import { ConnectionsPage } from "@/features/mdm/ConnectionsPage";
import { FeatureFlagsPage } from "@/features/settings/FeatureFlagsPage";
import { DataSharingPage } from "@/features/system/DataSharingPage";
import { AISettingsPage } from "@/features/ai/AISettingsPage";
import { ApiTokensPage } from "@/features/tokens/ApiTokensPage";
import { DestinationsPage } from "@/features/destinations/DestinationsPage";
import { JamfPatchPage } from "@/features/jamfPatch/JamfPatchPage";
import { JamfPatchDetailPage } from "@/features/jamfPatch/JamfPatchDetailPage";
import { CatalogPage } from "@/features/catalog/CatalogPage";
import { VulnerabilitiesPage } from "@/features/vulnerabilities/VulnerabilitiesPage";
import { VulnerabilityLookupPage } from "@/features/vulnerabilities/VulnerabilityLookupPage";
import { CompliancePage } from "@/features/compliance/CompliancePage";
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
          {/* After the three static children on purpose, so static-over-dynamic ranking
              is visible to a reader and not merely true to the router (#299). The key
              is app_hash, never bundleId: two apps sharing a bundle ID under different
              names are two records. */}
          <Route path=":appHash" element={<ApplicationRecordPage />} />
        </Route>
        {/* No /devices/groups: it rendered rows a developer typed (#95), and what it
            promised already exists under a truer name — the groups the ledger holds are
            on the cost page below, and per-title devices-on-latest is on Devices ›
            Applications › Jamf Patch, from real matching. /devices/compliance went the
            same day, and #95 ruled it returns when it can show something real: it has,
            as Posture › Compliance below (#536), read from the observation ledger. */}
        <Route path="devices/groups/cost" element={<SmartGroupCostPage />} />
        <Route path="devices/changes" element={<ChangesPage />} />
        {/* Declared after the static /devices children on purpose: react-router ranks a
            static segment above a dynamic one, so /devices/applications and
            /devices/changes still win, and a reader sees why without knowing that (#300). */}
        <Route path="devices/:deviceId" element={<DevicePage />} />
        {/* No /users route: nothing on the backend serves MDM-synced people, and a
            route rendering an empty table of eight columns Jamf's users would fill
            is a promise, not a page. It comes back with the endpoint (#95). */}
        {/* No /integrations: eleven of its sixteen cards were "coming soon" — one of
            them (Webhook) for a destination type that ships — and the two surfaces
            that connect anything are Settings › Connections and Destinations. The
            vendor marks under public/logos/ are deliberately left in place: the
            page comes back once its grid is mostly real (#95). */}
        {/* Still no top-level /ai (#95). What exists is Settings › AI below: the test
            box (#319), one prompt to an endpoint the admin names — listed in the sidebar,
            and reachable at all, only while the `ai_features` switch is on (#402). */}
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
        {/* SYSTEM_READ like data-sharing: the page reads the switches and the
            provider table for anyone with it, and hides Send without SYSTEM_WRITE,
            which is what the backend's POST gate requires.

            Then the flag, inside the permission and never instead of it (#402): the
            master switch owns the whole area — the page's own two reads answer 409 while
            it is off — so the route says so rather than drawing a page whose every panel
            is refused. Permission outside, because the narrower refusal is the truer one
            for an account that may not open Settings › AI at all. */}
        <Route element={<RequirePermission permission={PERMISSIONS.SYSTEM_READ} />}>
          <Route element={<RequireFlag flag="ai_features" />}>
            <Route path="settings/ai" element={<AISettingsPage />} />
          </Route>
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
        {/* Gated like the seven other /settings routes that carry a permission, and
            DEVICE_READ is the gate on purpose (#301). (The exception above,
            /settings/my-account, is deliberately ungated — everyone manages their own
            profile — so "every /settings route" would be one route too many.)

            This was first built ungated, on the product argument that a support page
            serves the person something is already broken for — possibly their own
            access — so it should refuse nobody. Kyle overruled it on GRC grounds and
            that frame wins: this product holds encrypted MDM credentials for a
            customer's whole Mac fleet, the repository is about to be public, and one
            row in the route table with no permission on it is a finding on every
            questionnaire it ever meets. The cost is never the single finding — it is
            the scrutiny it invites into everything adjacent, forever, and the
            re-explaining to every reviewer who greps this file.

            DEVICE_READ specifically, because it is the floor every authenticated role
            already holds: permissions.py defines _INVENTORY_READ = {DEVICE_READ,
            APP_READ, VULN_READ}, Role.viewer is exactly that set, and analyst, auditor
            and admin are supersets of it. So the route table shows a gate and no role
            is locked out of the page they reach precisely when something is already
            broken. Adding a role without DEVICE_READ would be the one change that
            breaks that, which is the right place for it to surface.

            Rejected: minting a SUPPORT_READ permission. Cleaner semantics, but it
            costs an enum member plus an edit to all four role sets in permissions.py
            to gate the six links this page draws — and a permission every role holds
            unconditionally is a gate in name only, which is what DEVICE_READ already
            is here. Don't redo this analysis.

            The genuinely locked-out reader — no session at all — is answered on the
            login page, which already responds without auth and so adds no new route
            and no new finding. */}
        <Route element={<RequirePermission permission={PERMISSIONS.DEVICE_READ} />}>
          <Route path="settings/support" element={<SupportPage />} />
        </Route>
        {/* The slot #95 reserved and #251 declined to fill, filled (#529). What it waited
            for was never the per-finding lifecycle records but something the Catalog tab
            cannot show, and this is it: a fleet ranking the Catalog can only sort over the
            page in hand. The Catalog's own column stays where it is.

            VULN_READ and NO RequireFlag, deliberately. The flag decides what is LISTED;
            hidden from the nav means hidden, not refused, so a shared link opens for anyone
            who may read inventory and renders the corpus banner and its *why* block when
            nothing answers. Settings › AI above is the other shape — there the flag owns the
            whole area and the route says so; here a route gate would refuse the very reader
            the banner exists to explain things to. */}
        <Route element={<RequirePermission permission={PERMISSIONS.VULN_READ} />}>
          <Route path="posture/vulnerabilities" element={<VulnerabilitiesPage />} />
          {/* One finding id, and the builds whose answer names it (#533). Same permission, still
              no flag: an id is a link somebody sends, and the page refuses the shape or names
              why nothing answers rather than 404ing the reader who followed it. */}
          <Route path="posture/vulnerabilities/:vulnID" element={<VulnerabilityLookupPage />} />
          {/* The address #95 reserved keeps working, now that /posture is the prefix. */}
          <Route path="vulnerabilities" element={<Navigate to="/posture/vulnerabilities" replace />} />
        </Route>
        {/* AUDIT_READ, the endpoint's own permission and the sidebar entry's (#536), whole-page per
            docs/data-access-grain.md. No flag: nothing here waits on a corpus. */}
        <Route element={<RequirePermission permission={PERMISSIONS.AUDIT_READ} />}>
          <Route path="posture/compliance" element={<CompliancePage />} />
        </Route>
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
