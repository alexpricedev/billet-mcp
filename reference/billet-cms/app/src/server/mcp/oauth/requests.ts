/**
 * The authorize request held across sign-in.
 *
 * The CMS's sign-in predates OAuth: `/sign-in` sends the browser to the site,
 * the site mints a handoff token and sends it back to `/handoff`, and the CMS
 * starts a session. None of those steps know about `client_id`, `state` or a
 * PKCE challenge, and putting the whole authorize URL in a query parameter
 * would be an open redirect waiting to happen. So the request is stored here,
 * its random id rides in an HttpOnly cookie, and `/handoff` sends the browser
 * back to the consent screen when that cookie is present.
 */
import type { SQL } from "bun";
import { db } from "../../services/database";
import { MCP_AUTH_REQUEST_TTL_SECONDS, MCP_SCOPE } from "./config";

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

export const createAuthRequest = async (input: {
  clientId: string;
  redirectUri: string;
  state: string | null;
  codeChallenge: string;
  resource: string;
  scope: string;
}): Promise<McpAuthRequest> => {
  const expiresAt = new Date(Date.now() + MCP_AUTH_REQUEST_TTL_SECONDS * 1000);
  const rows = (await db`
    INSERT INTO cms_mcp_auth_requests
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
  id: string,
  sql: SQL = db,
): Promise<McpAuthRequest | null> => {
  const rows = (await sql`
    SELECT id, client_id, redirect_uri, state, code_challenge, resource, scope, expires_at
    FROM cms_mcp_auth_requests
    WHERE id = ${id}
      AND expires_at > CURRENT_TIMESTAMP
  `) as AuthRequestRow[];
  return rows.length > 0 ? toRequest(rows[0]) : null;
};

export const deleteAuthRequest = async (
  id: string,
  sql: SQL = db,
): Promise<void> => {
  await sql`DELETE FROM cms_mcp_auth_requests WHERE id = ${id}`;
};
