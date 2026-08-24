import type { IntegrationGroup } from "@/features/integrations/types";

export const INTEGRATION_GROUPS: IntegrationGroup[] = [
  {
    id: "mdm",
    vendors: [
      { id: "jamf", status: "available", href: "/settings/connections", logoUrl: "/logos/jamf.svg" },
      // Roadmap, stated as roadmap: no code path behind these exists yet (#79).
      { id: "simplemdm", status: "comingSoon" },
      { id: "addigy", status: "comingSoon", logoUrl: "/logos/addigy.svg" }
    ]
  },
  {
    id: "siem",
    vendors: [
      { id: "runreveal", status: "comingSoon", logoUrl: "/logos/runreveal.svg" },
      { id: "elastic", status: "comingSoon" },
      { id: "splunk", status: "comingSoon" },
      { id: "datadog", status: "comingSoon", logoUrl: "/logos/datadog.svg", logoUrlDark: "/logos/datadog.png" },
      { id: "webhook", status: "comingSoon" }
    ]
  },
  {
    id: "storage",
    vendors: [
      { id: "snowflake", status: "comingSoon" },
      { id: "postgres", status: "comingSoon" }
    ]
  },
  {
    id: "messaging",
    vendors: [
      { id: "slack", status: "comingSoon" },
      { id: "discord", status: "comingSoon" },
      { id: "teams", status: "comingSoon" }
    ]
  },
  {
    id: "metadata",
    vendors: [
      { id: "jamf-metadata", status: "available", href: "/settings/connections", logoUrl: "/logos/jamf.svg" },
      { id: "nvd", status: "comingSoon" },
      { id: "loonsecio", status: "comingSoon" }
    ]
  }
];
