import { afterAll, describe, expect, test } from "bun:test";
import { down, up } from "./migration";
import { connect } from "./test-helpers";

const sql = connect();
afterAll(async () => {
  await sql.close();
});

const names = async (query: "tables" | "indexes" | "constraints") => {
  const rows =
    query === "tables"
      ? await sql`SELECT tablename AS name FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'mcp\\_%'`
      : query === "indexes"
        ? await sql`SELECT indexname AS name FROM pg_indexes WHERE schemaname = current_schema() AND tablename LIKE 'mcp\\_%'`
        : await sql`
            SELECT conname AS name FROM pg_constraint
            WHERE conrelid IN (SELECT oid FROM pg_class WHERE relname LIKE 'mcp\\_%')`;
  return rows.map((row: { name: string }) => row.name).sort();
};

describe("the migration", () => {
  test("up creates the mcp_ tables, down removes them, and both repeat", async () => {
    await down(sql);
    expect(await names("tables")).toEqual([]);

    await up(sql);
    expect(await names("tables")).toEqual([
      "mcp_audit",
      "mcp_auth_requests",
      "mcp_clients",
      "mcp_grants",
      "mcp_tokens",
    ]);

    await down(sql);
    expect(await names("tables")).toEqual([]);
    await up(sql);
    expect(await names("tables")).toHaveLength(5);
  });

  test("every constraint and index is named with the prefix", async () => {
    const all = [...(await names("indexes")), ...(await names("constraints"))];
    expect(all.length).toBeGreaterThan(15);
    for (const name of all) expect(name).toStartWith("mcp_");
    // Not Postgres's `_key` default for the token hash.
    expect(all).toContain("mcp_tokens_token_hash_idx");
    expect(all).toContain("mcp_grants_live_idx");
    expect(all).toContain("mcp_tokens_kind_check");
    expect(all).toContain("mcp_grants_client_id_fkey");
  });

  test("one live grant per client and person, a revoked one does not block", async () => {
    await sql`INSERT INTO mcp_clients (client_id, redirect_uris) VALUES ('c', ${sql.array(["https://claude.ai/api/mcp/auth_callback"], "TEXT")})`;
    await sql`INSERT INTO mcp_grants (client_id, identity_id) VALUES ('c', 'u')`;
    let refused = false;
    try {
      await sql`INSERT INTO mcp_grants (client_id, identity_id) VALUES ('c', 'u')`;
    } catch {
      refused = true;
    }
    expect(refused).toBe(true);
    await sql`UPDATE mcp_grants SET revoked_at = CURRENT_TIMESTAMP`;
    await sql`INSERT INTO mcp_grants (client_id, identity_id) VALUES ('c', 'u')`;
    await sql`DELETE FROM mcp_clients`;
  });
});
