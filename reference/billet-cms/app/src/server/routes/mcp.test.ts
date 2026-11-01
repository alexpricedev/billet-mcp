import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { clearRateLimitLog } from "../middleware/rate-limit";
import { createBunRequest } from "../test-utils/bun-request";
import { handleMcp, mcpRoutes } from "./mcp";

const DEV_TOKEN = "dev-token-for-the-routes-test-0123456789";

const post = (body: unknown) =>
  createBunRequest("http://localhost/mcp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${DEV_TOKEN}`,
    },
    body: JSON.stringify(body),
  });

describe("the MCP route", () => {
  let previous: { enabled?: string; token?: string };

  beforeEach(() => {
    clearRateLimitLog();
    previous = {
      enabled: process.env.MCP_ENABLED,
      token: process.env.MCP_DEV_TOKEN,
    };
    process.env.MCP_ENABLED = "true";
    process.env.MCP_DEV_TOKEN = DEV_TOKEN;
  });

  afterEach(() => {
    for (const [key, value] of [
      ["MCP_ENABLED", previous.enabled],
      ["MCP_DEV_TOKEN", previous.token],
    ] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  test("refuses a JSON-RPC batch, which would dodge the budget and the audit", async () => {
    const call = (id: number) => ({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: "publish_page", arguments: { id: "x" } },
    });

    const response = await handleMcp(post([call(1), call(2)]));
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error.code).toBe(-32600);
  });

  test("the consent pages carry the CMS's security headers", async () => {
    const response = await mcpRoutes["/mcp/authorize"](
      createBunRequest("http://localhost/mcp/authorize"),
    );

    expect(response.status).toBe(400);
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Content-Security-Policy")).toContain(
      "default-src 'self'",
    );
  });
});
