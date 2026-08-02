import type { IntegrationGroup } from "@/features/integrations/types";

export const INTEGRATION_GROUPS: IntegrationGroup[] = [
  {
    id: "mdm",
    vendors: [
      { id: "jamf", status: "available", href: "/settings/connections" },
      { id: "fleet", status: "available", href: "/settings/connections" },
      { id: "simplemdm", status: "available", href: "/settings/connections" },
      { id: "addigy", status: "available", href: "/settings/connections" }
    ]
  },
  {
    id: "siem",
    vendors: [
      { id: "runreveal", status: "comingSoon", logoUrl: "/logos/runreveal.svg" },
      { id: "splunk", status: "comingSoon" },
      { id: "datadog", status: "comingSoon" },
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
      { id: "discord", status: "comingSoon" }
    ]
  },
  {
    id: "metadata",
    vendors: [
      { id: "jamf-metadata", status: "available", href: "/settings/connections" },
      { id: "nvd", status: "comingSoon" },
      { id: "loonsecio", status: "available", href: "/settings/connections" }
    ]
  }
];
