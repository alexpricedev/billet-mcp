/**
 * OAuth credentials for the MCP endpoint.
 *
 * The spike's single environment token is replaced by four tables:
 *
 * - `cms_mcp_clients` — the OAuth clients that registered through DCR (Claude,
 *   ChatGPT, and a loopback client for local testing). The redirect URIs are the
 *   allowlist enforced again at authorize time.
 * - `cms_mcp_grants` — one consent: a client, the `cms_identities` person who
 *   approved it, and the one scope this CMS issues. Revoking a grant is what
 *   the Connected apps page does.
 * - `cms_mcp_tokens` — opaque, hashed access, refresh and authorization-code
 *   rows. Codes carry the PKCE challenge and redirect URI they were minted for;
 *   refresh tokens are rotated and a reused one revokes the grant.
 * - `cms_mcp_auth_requests` — the authorize request held while the browser goes
 *   through the site's sign-in and handoff, so the OAuth parameters survive a
 *   round trip that predates OAuth and knows nothing about it.
 *
 * Every relation is `cms_`-prefixed and every created index is named
 * `…_idx`, including the token hash: a UNIQUE constraint's implicit index would
 * be `cms_mcp_tokens_token_hash_key`, which breaks that convention, so the
 * uniqueness is a separately named unique index.
 */
import type { SQL } from "bun";

export const up = async (db: SQL): Promise<void> => {
  await db`
    CREATE TABLE cms_mcp_clients (
      client_id TEXT PRIMARY KEY,
      client_name TEXT NULL,
      redirect_uris TEXT[] NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `;

  await db`
    CREATE TABLE cms_mcp_grants (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      client_id TEXT NOT NULL
        REFERENCES cms_mcp_clients(client_id) ON DELETE CASCADE,
      -- A cms_identities id. No foreign key: the identities are the site's
      -- users behind a view the site owns.
      identity_id UUID NOT NULL,
      scope TEXT NOT NULL DEFAULT 'content',
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_used_at TIMESTAMPTZ NULL,
      revoked_at TIMESTAMPTZ NULL
    )
  `;

  await db`
    CREATE TABLE cms_mcp_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      grant_id UUID NOT NULL
        REFERENCES cms_mcp_grants(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh', 'code')),
      resource TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      -- Set when a code is spent or a refresh token is rotated. A refresh row
      -- that is already rotated is the reuse signal that revokes the grant.
      rotated_at TIMESTAMPTZ NULL,
      -- Codes only: the PKCE challenge and the exact redirect the code was
      -- minted for. Null on access and refresh rows.
      code_challenge TEXT NULL,
      redirect_uri TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `;

  await db`
    CREATE TABLE cms_mcp_auth_requests (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      state TEXT NULL,
      code_challenge TEXT NOT NULL,
      resource TEXT NOT NULL,
      scope TEXT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `;

  await db`CREATE UNIQUE INDEX cms_mcp_tokens_token_hash_idx ON cms_mcp_tokens(token_hash)`;
  await db`CREATE INDEX cms_mcp_tokens_grant_id_idx ON cms_mcp_tokens(grant_id)`;
  await db`CREATE INDEX cms_mcp_tokens_kind_expires_at_idx ON cms_mcp_tokens(kind, expires_at)`;
  await db`CREATE INDEX cms_mcp_grants_identity_id_idx ON cms_mcp_grants(identity_id)`;
  await db`CREATE INDEX cms_mcp_grants_client_id_idx ON cms_mcp_grants(client_id)`;
  // One live consent per (client, person). A revoked grant stays as history but
  // no longer blocks a fresh approval.
  await db`
    CREATE UNIQUE INDEX cms_mcp_grants_live_idx
    ON cms_mcp_grants(client_id, identity_id)
    WHERE revoked_at IS NULL
  `;
  await db`CREATE INDEX cms_mcp_auth_requests_expires_at_idx ON cms_mcp_auth_requests(expires_at)`;
};

export const down = async (db: SQL): Promise<void> => {
  await db`DROP TABLE IF EXISTS cms_mcp_auth_requests`;
  await db`DROP TABLE IF EXISTS cms_mcp_tokens`;
  await db`DROP TABLE IF EXISTS cms_mcp_grants`;
  await db`DROP TABLE IF EXISTS cms_mcp_clients`;
};
