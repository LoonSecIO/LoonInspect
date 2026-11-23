import { describe, expect, it } from "vitest";
import { clientConfiguration, grantedMcpScopes, pairingCommand } from "./configuration";

describe("MCP setup instructions", () => {
  it("keeps local credentials out of every client configuration and pairs distinct profiles", () => {
    for (const client of ["codex", "claude-code", "claude-desktop"] as const) {
      const config = clientConfiguration(client, "mac", "http://127.0.0.1:8000/mcp");
      expect(config).toContain("/Applications/LoonInspect.app/Contents/MacOS/LoonInspect");
      expect(config).toContain("--profile");
      expect(config).toContain(client);
      expect(config).not.toContain("token");
      expect(pairingCommand(client)).toBe(`"/Applications/LoonInspect.app/Contents/MacOS/LoonInspect" --mcp-pair --profile ${client}`);
      if (client !== "codex") expect(JSON.parse(config).mcpServers.looninspect.args).toEqual(["--mcp", "--profile", client]);
    }
  });

  it("uses each HTTP client's credential reference and gives Claude Desktop only the remote URL", () => {
    const endpoint = "https://inspect.example.test/mcp";
    expect(clientConfiguration("codex", "http", endpoint)).toContain('bearer_token_env_var = "LOONINSPECT_MCP_TOKEN"');
    expect(clientConfiguration("codex", "http", endpoint)).toContain("tool_timeout_sec = 330");
    expect(JSON.parse(clientConfiguration("claude-code", "http", endpoint)).mcpServers.looninspect).toEqual({
      type: "http", url: endpoint, headers: { Authorization: "Bearer ${LOONINSPECT_MCP_TOKEN}" },
    });
    expect(clientConfiguration("claude-desktop", "http", endpoint)).toBe(endpoint);
  });

  it("never creates inherited or credential-granting scopes, including after permissions shrink", () => {
    expect(grantedMcpScopes([], [])).toEqual(["mcp:connect"]);
    expect(grantedMcpScopes(["device:read", "connection:credential-read"], ["device:read", "device:sync", "connection:credential-read"]))
      .toEqual(["mcp:connect", "device:read"]);
  });
});
