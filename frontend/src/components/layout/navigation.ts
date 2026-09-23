import {
  AppWindow,
  Database,
  FileCheck,
  Flag,
  FlaskConical,
  Gauge,
  History,
  Home,
  KeyRound,
  LifeBuoy,
  ListChecks,
  Plug,
  Send,
  Settings,
  Share2,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  UserCircle,
  UserCog,
  type LucideIcon
} from "lucide-react";
import { PERMISSIONS, type PermissionName } from "@/features/auth/types";
import type { Translations } from "@/i18n/en";

/**
 * The navigation tree — what the product lists, and the rules for what one account sees.
 *
 * Pure on purpose, and separate from the components that draw it: two surfaces render
 * this tree (the sidebar at `md` and above, the drawer below it — #141), and the rules
 * here are the ones a screenshot cannot check. A hidden entry that should be visible is
 * a missing feature to the person it hides from, and a visible entry pointing at a page
 * the reader is then refused is #301's bug. `navigation.test.ts` pins them in the
 * frontend test lane ([#285](https://github.com/LoonSecIO/LoonInspect/issues/285)).
 */

export type NavKey = keyof Translations["nav"];

const EMPTY: ReadonlySet<string> = new Set();

export interface NavItem {
  labelKey: NavKey;
  icon: LucideIcon;
  to: string;
  end: boolean;
  /** Omitted where every role can see the page. */
  permission?: PermissionName;
  /** Listed only while this feature flag is on (Settings › AI, #319). Where `requires` is
   *  declared too the flag is that requirement's OVERRIDE and not a second condition —
   *  see `visibleNavigation`. */
  flag?: string;
  /** Listed only while the session found this data answering (#529). A per-item data gate,
   *  never a section's: a section follows its children, and Compliance below — #536's evidence
   *  report, read from this tenant's own ledger — is not governed by the corpus. */
  requires?: "corpus" | "intelligenceAccess";
  children?: NavItem[];
}

export const navigationItems: NavItem[] = [
  { labelKey: "overview", icon: Home, to: "/", end: true },
  {
    labelKey: "devices",
    icon: Database,
    to: "/devices",
    end: false,
    children: [
      { labelKey: "applications", icon: AppWindow, to: "/devices/applications", end: false },
      { labelKey: "smartGroupCost", icon: Gauge, to: "/devices/groups/cost", end: false },
      { labelKey: "changes", icon: History, to: "/devices/changes", end: false }
    ]
  },
  // Top-level, between Devices and Settings, and pointing at its own first child the way
  // Settings points at Connections (#529). `Posture`, not `Risks`: risk is a judgement this
  // product does not make — absent-not-zero counts, no ratios stored — and a section called
  // Risks is where the first "risk score per Mac" request comes from.
  {
    labelKey: "posture",
    icon: ShieldHalf,
    to: "/posture/vulnerabilities",
    end: false,
    children: [
      {
        labelKey: "vulnerabilities",
        icon: ShieldAlert,
        to: "/posture/vulnerabilities",
        end: false,
        permission: PERMISSIONS.VULN_READ,
        // The data decides, and the flag overrides it. Not a second switch beside
        // data-sharing consent: consent is what earns the corpus, and a switch nobody
        // knows to flip is a step 3.
        requires: "corpus",
        flag: "vulnerabilities"
      },
      // No `requires` and no flag (#536): the report reads this tenant's own observation ledger, so there is
      // no corpus to wait on. `audit:read` is the endpoint's own permission and the route's gate (#301).
      {
        labelKey: "compliance",
        icon: FileCheck,
        to: "/posture/compliance",
        end: false,
        permission: PERMISSIONS.AUDIT_READ
      }
    ]
  },
  {
    labelKey: "settings",
    icon: Settings,
    to: "/settings/connections",
    end: false,
    children: [
      {
        labelKey: "connections",
        icon: Plug,
        to: "/settings/connections",
        end: false,
        permission: PERMISSIONS.CONNECTION_READ
      },
      {
        labelKey: "changeTracking",
        icon: ListChecks,
        to: "/settings/change-tracking",
        end: false,
        permission: PERMISSIONS.CONNECTION_READ
      },
      {
        labelKey: "featureFlags",
        icon: Flag,
        to: "/settings/feature-flags",
        end: false,
        permission: PERMISSIONS.FEATURE_FLAG_WRITE
      },
      {
        labelKey: "apiTokens",
        icon: KeyRound,
        to: "/settings/api-tokens",
        end: false,
        permission: PERMISSIONS.TOKEN_CREATE
      },
      {
        labelKey: "dataSharing",
        icon: Share2,
        to: "/settings/data-sharing",
        end: false,
        permission: PERMISSIONS.SYSTEM_READ
      },
      // Listed only where the instance offers it (#622): the rollout switches are
      // deployment configuration, never a customer toggle, so the entry follows their
      // verdict as read by `intelligenceStore`, and a failed read hides it.
      {
        labelKey: "intelligenceAccess",
        icon: ShieldCheck,
        to: "/settings/intelligence-access",
        end: false,
        permission: PERMISSIONS.SYSTEM_READ,
        requires: "intelligenceAccess"
      },
      // Flag-gated as well as permission-gated: no top-level /ai exists, and this entry
      // appears only once the `ai_features` switch is on (#319). It is judged against the
      // shared set the toggle writes into (#402), so the flag adds or removes it at once,
      // and a read that failed leaves it hidden, as it always has.
      {
        labelKey: "ai",
        icon: FlaskConical,
        to: "/settings/ai",
        end: false,
        permission: PERMISSIONS.SYSTEM_READ,
        flag: "ai_features"
      },
      {
        labelKey: "destinations",
        icon: Send,
        to: "/settings/destinations",
        end: false,
        permission: PERMISSIONS.DESTINATION_READ
      },
      {
        labelKey: "accounts",
        icon: UserCog,
        to: "/settings/accounts",
        end: false,
        permission: PERMISSIONS.ACCOUNT_READ
      },
      // Ungated: everyone has a profile and a password to change.
      { labelKey: "myAccount", icon: UserCircle, to: "/settings/my-account", end: false },
      // Last, so it is where a person scans when nothing else worked. The permission
      // matches the route's own gate in routes.tsx — DEVICE_READ, the floor every
      // role holds — so this entry cannot become a nav item pointing at a page the
      // reader is then refused (#301).
      {
        labelKey: "support",
        icon: LifeBuoy,
        to: "/settings/support",
        end: false,
        permission: PERMISSIONS.DEVICE_READ
      }
    ]
  }
];

/**
 * The tree one account may see: entries gated on a permission the account lacks or a
 * flag that is off are dropped, a section whose every child is hidden goes with them,
 * and a section whose own target was one of the hidden children is re-pointed at the
 * first child left standing.
 *
 * `answering` is the third input (#529): the data requirements this session found
 * satisfied. It defaults to the empty set, so a read that has not landed — or one that
 * FAILED — hides the entries that need it, exactly as a failed flag read does, and is
 * never reported anywhere as the data being "off".
 *
 * `permissions` arrives from the server as plain strings and is read as such; the
 * constants in `PERMISSIONS` are what narrow it, so an unknown grant is ignored rather
 * than a type error. `undefined` is the pre-bootstrap state and sees the same tree as an
 * account with no grants at all. Returns fresh arrays and never mutates the declared
 * tree — the re-pointing above would otherwise persist across accounts in one session.
 */
export function visibleNavigation(
  permissions: Iterable<string> | undefined,
  enabledFlags: ReadonlySet<string>,
  answering: ReadonlySet<string> = EMPTY
): NavItem[] {
  const granted = new Set(permissions ?? []);
  const allowed = (item: NavItem) => {
    if (item.permission && !granted.has(item.permission)) return false;
    const flagOn = item.flag !== undefined && enabledFlags.has(item.flag);
    // A `requires` entry is listed when the data answers **or** the flag overrides it. The
    // flag is not a second condition: an entry that followed both would be hidden for
    // everyone whose corpus answers and whose flag is off, which is every customer.
    if (item.requires) return flagOn || answering.has(item.requires);
    return item.flag === undefined || flagOn;
  };

  return navigationItems.filter(allowed).flatMap((item) => {
    if (!item.children) return [item];

    const children = item.children.filter(allowed);
    // A section whose every child is hidden has nothing left to show.
    if (children.length === 0) return [];

    // The parent's own target may itself be one of the hidden children (Settings
    // points at Connections). Re-point it rather than linking somewhere this
    // account will just be refused.
    const ownTargetHidden = item.children.some((child) => child.to === item.to && !allowed(child));

    return [{ ...item, children, to: ownTargetHidden ? children[0].to : item.to }];
  });
}
