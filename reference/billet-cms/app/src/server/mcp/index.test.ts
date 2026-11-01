import { describe, expect, test } from "bun:test";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { actorFromAuthInfo } from "./auth";
import { mcpHandler } from "./index";

const actor = {
  id: "00000000-0000-4000-8000-000000000001",
  email: "priya@example.com",
  role: "admin",
};

const authInfo: AuthInfo = {
  token: "test",
  clientId: "dev",
  scopes: ["content"],
  extra: { actor, grantId: "test-grant" },
};

const listRequest = () =>
  new Request("http://localhost/mcp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    }),
  });

describe("the MCP handler", () => {
  test("advertises the read, validate and write tools", async () => {
    const response = await mcpHandler.fetch(listRequest(), { authInfo });
    const body = await response.text();

    expect(response.status).toBe(200);
    for (const name of [
      "get_context",
      "get_slot",
      "get_page",
      "list_media",
      "validate_slot",
      "validate_page",
      "save_slot",
      "save_page",
      "publish_slot",
      "publish_page",
    ]) {
      expect(body).toContain(name);
    }
  });

  test("carries the CMS identity on AuthInfo", () => {
    expect(actorFromAuthInfo(authInfo)).toEqual(actor);
    expect(actorFromAuthInfo(undefined)).toBeNull();
  });

  test("refuses content over 1 MB before touching the database", async () => {
    const response = await mcpHandler.fetch(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "validate_slot",
            arguments: {
              slot: "home.hero",
              content: { heading: "x".repeat(1_100_000) },
            },
          },
        }),
      }),
      { authInfo },
    );
    const body = await response.text();

    expect(body).toContain("larger than 1 MB");
  });
});
