export type McpClient = "codex" | "claude-code" | "claude-desktop";
export type McpConnectionMode = "mac" | "http";
export const macExecutable = "/Applications/LoonInspect.app/Contents/MacOS/LoonInspect";

/** Generated setup text contains credential references, never a connection token. */
export function clientConfiguration(client: McpClient, mode: McpConnectionMode, endpoint: string): string {
  if (mode === "mac") {
    const args = ["--mcp", "--profile", client];
    if (client === "codex") {
      return `[mcp_servers.looninspect]\ncommand = ${JSON.stringify(macExecutable)}\nargs = ${JSON.stringify(args)}\ntool_timeout_sec = 330`;
    }
    return JSON.stringify({ mcpServers: { looninspect: { command: macExecutable, args } } }, null, 2);
  }
  if (client === "codex") {
    return `[mcp_servers.looninspect]\nurl = ${JSON.stringify(endpoint)}\nbearer_token_env_var = "LOONINSPECT_MCP_TOKEN"\ntool_timeout_sec = 330`;
  }
  if (client === "claude-code") {
    return JSON.stringify({ mcpServers: { looninspect: {
      type: "http", url: endpoint, headers: { Authorization: "Bearer ${LOONINSPECT_MCP_TOKEN}" },
    } } }, null, 2);
  }
  return endpoint;
}

export function pairingCommand(client: McpClient): string {
  return `${JSON.stringify(macExecutable)} --mcp-pair --profile ${client}`;
}

export const scopeGroups = [
  { key: "inventory", scopes: ["device:read", "app:read", "vuln:read"] },
  { key: "operations", scopes: ["connection:read", "system:read", "destination:read"] },
  { key: "reports", scopes: ["audit:read"] },
  { key: "refresh", scopes: ["device:sync", "patch:catalog-sync"] },
] as const;

/** Only the documented MCP capabilities may be granted by this form. */
export function grantedMcpScopes(available: readonly string[], selected: readonly string[]): string[] {
  const known = new Set<string>(scopeGroups.flatMap(group => [...group.scopes]));
  return ["mcp:connect", ...selected.filter(scope => known.has(scope) && available.includes(scope))];
}
