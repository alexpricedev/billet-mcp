/**
 * The authorize request held across sign-in.
 *
 * The app's sign-in knows nothing about `client_id`, `state` or a PKCE
 * challenge, and putting the whole authorize URL in a query parameter would be
 * an open redirect waiting to happen. So the request is stored here, its random
 * id rides in an HttpOnly cookie, and the app sends the browser back to
 * `/mcp/authorize/continue` when that cookie is present.
 */
import type { SQL } from "bun";
import {
  MCP_AUTH_REQUEST_TTL_SECONDS,
  MCP_SCOPE,
  type McpContext,
} from "../config";

export interface McpAuthRequest {
  id: string;
  clientId: string;
  redirectUri: string;
  state: string | null;
  codeChallenge: string;
  resource: string;
  scope: string;
  expiresAt: Date;
}

interface AuthRequestRow {
  id: string;
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  resource: string;
  scope: string | null;
  expires_at: Date;
}

const toRequest = (row: AuthRequestRow): McpAuthRequest => ({
  id: row.id,
  clientId: row.client_id,
  redirectUri: row.redirect_uri,
  state: row.state,
  codeChallenge: row.code_challenge,
  resource: row.resource,
  scope: row.scope ?? MCP_SCOPE,
  expiresAt: row.expires_at,
});

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const createAuthRequest = async (
  ctx: McpContext,
  input: {
    clientId: string;
    redirectUri: string;
    state: string | null;
    codeChallenge: string;
    resource: string;
    scope: string;
  },
): Promise<McpAuthRequest> => {
  const expiresAt = new Date(Date.now() + MCP_AUTH_REQUEST_TTL_SECONDS * 1000);
  const rows = (await ctx.sql`
    INSERT INTO mcp_auth_requests
      (client_id, redirect_uri, state, code_challenge, resource, scope, expires_at)
    VALUES (
      ${input.clientId},
      ${input.redirectUri},
      ${input.state},
      ${input.codeChallenge},
      ${input.resource},
      ${input.scope},
      ${expiresAt}
    )
    RETURNING id, client_id, redirect_uri, state, code_challenge, resource, scope, expires_at
  `) as AuthRequestRow[];
  return toRequest(rows[0]);
};

export const getAuthRequest = async (
  ctx: McpContext,
  id: string,
  sql: SQL = ctx.sql,
): Promise<McpAuthRequest | null> => {
  // The id comes from a cookie or a form field: a non-UUID would be a Postgres
  // error rather than a miss.
  if (!UUID.test(id)) return null;
  const rows = (await sql`
    SELECT id, client_id, redirect_uri, state, code_challenge, resource, scope, expires_at
    FROM mcp_auth_requests
    WHERE id = ${id}
      AND expires_at > CURRENT_TIMESTAMP
  `) as AuthRequestRow[];
  return rows.length > 0 ? toRequest(rows[0]) : null;
};

export const deleteAuthRequest = async (
  ctx: McpContext,
  id: string,
  sql: SQL = ctx.sql,
): Promise<void> => {
  await sql`DELETE FROM mcp_auth_requests WHERE id = ${id}`;
};
