import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";
import { testDatabase } from "../../test-utils/database";
import { cleanupTestData } from "../../test-utils/helpers";

const connection = testDatabase();

mock.module("../../services/database", () => ({
  get db() {
    return connection;
  },
  closeDatabase: async () => {},
}));

import { db } from "../../services/database";
import { getClientById, registerClient } from "./clients";

beforeEach(async () => {
  await cleanupTestData(db);
});

afterAll(async () => {
  await connection.end();
});

const claude = ["https://claude.ai/api/mcp/auth_callback"];

describe("dynamic client registration", () => {
  test("stores a public client and reads it back", async () => {
    const result = await registerClient({
      client_name: "Claude",
      redirect_uris: claude,
      token_endpoint_auth_method: "none",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.client.clientId).toStartWith("bcmcp_client_");
    const stored = await getClientById(result.client.clientId);
    expect(stored?.clientName).toBe("Claude");
    expect(stored?.redirectUris).toEqual(claude);
  });

  test("refuses a redirect on a host we do not trust", async () => {
    const result = await registerClient({
      client_name: "Phish",
      redirect_uris: ["https://evil.example/callback"],
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_redirect_uri");
  });

  test("refuses a confidential client", async () => {
    const result = await registerClient({
      client_name: "Old client",
      redirect_uris: claude,
      token_endpoint_auth_method: "client_secret_basic",
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_client_metadata");
  });

  test("cleans control characters out of the display name", async () => {
    const result = await registerClient({
      client_name: "Claude\nDesktop\u0007",
      redirect_uris: claude,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.clientName).toBe("Claude Desktop");
  });
});
