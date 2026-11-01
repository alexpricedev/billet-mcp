/**
 * The package's tables, as `up` and `down` functions for an app to wrap in one
 * migration file.
 *
 * - `mcp_clients`: OAuth clients registered through DCR. The redirect URIs are
 *   the allowlist enforced again at authorize time.
 * - `mcp_grants`: one consent: a client, the person who approved it, and the
 *   one scope. Revoking a grant ends every token it issued.
 * - `mcp_tokens`: opaque, hashed access, refresh and authorization-code rows.
 *   Codes carry the PKCE challenge and redirect URI they were minted for;
 *   refresh tokens rotate and a reused one revokes the grant.
 * - `mcp_auth_requests`: the authorize request held while the browser goes
 *   through the app's sign-in.
 * - `mcp_audit`: grant approvals and revocations, and one row per tool call.
 *
 * Every constraint and index is named explicitly with the `mcp_` prefix, so the
 * names never depend on Postgres defaults. `identity_id` is TEXT with no
 * foreign key: the users belong to the app.
 */
import type { SQL } from "bun";

export const up = async (db: SQL): Promise<void> => {
  await db`
    CREATE TABLE mcp_clients (
      client_id TEXT NOT NULL,
      client_name TEXT NULL,
      redirect_uris TEXT[] NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT mcp_clients_pkey PRIMARY KEY (client_id)
    )
  `;

  await db`
    CREATE TABLE mcp_grants (
      id UUID NOT NULL DEFAULT gen_random_uuid(),
      client_id TEXT NOT NULL,
      identity_id TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT 'content',
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_used_at TIMESTAMPTZ NULL,
      revoked_at TIMESTAMPTZ NULL,
      CONSTRAINT mcp_grants_pkey PRIMARY KEY (id),
      CONSTRAINT mcp_grants_client_id_fkey FOREIGN KEY (client_id)
        REFERENCES mcp_clients (client_id) ON DELETE CASCADE
    )
  `;

  await db`
    CREATE TABLE mcp_tokens (
      id UUID NOT NULL DEFAULT gen_random_uuid(),
      grant_id UUID NOT NULL,
      token_hash TEXT NOT NULL,
      kind TEXT NOT NULL,
      resource TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      -- Set when a code is spent or a refresh token is rotated. A refresh row
      -- that is already rotated is the reuse signal that revokes the grant.
      rotated_at TIMESTAMPTZ NULL,
      -- Codes only: the PKCE challenge and the exact redirect the code was
      -- minted for. Null on access and refresh rows.
      code_challenge TEXT NULL,
      redirect_uri TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT mcp_tokens_pkey PRIMARY KEY (id),
      CONSTRAINT mcp_tokens_grant_id_fkey FOREIGN KEY (grant_id)
        REFERENCES mcp_grants (id) ON DELETE CASCADE,
      CONSTRAINT mcp_tokens_kind_check
        CHECK (kind IN ('access', 'refresh', 'code'))
    )
  `;

  await db`
    CREATE TABLE mcp_auth_requests (
      id UUID NOT NULL DEFAULT gen_random_uuid(),
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      state TEXT NULL,
      code_challenge TEXT NOT NULL,
      resource TEXT NOT NULL,
      scope TEXT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT mcp_auth_requests_pkey PRIMARY KEY (id)
    )
  `;

  await db`
    CREATE TABLE mcp_audit (
      id UUID NOT NULL DEFAULT gen_random_uuid(),
      action TEXT NOT NULL,
      actor_id TEXT NULL,
      subject_type TEXT NOT NULL,
      subject_id TEXT NULL,
      detail JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT mcp_audit_pkey PRIMARY KEY (id)
    )
  `;

  await db`CREATE UNIQUE INDEX mcp_tokens_token_hash_idx ON mcp_tokens (token_hash)`;
  await db`CREATE INDEX mcp_tokens_grant_id_idx ON mcp_tokens (grant_id)`;
  await db`CREATE INDEX mcp_tokens_kind_expires_at_idx ON mcp_tokens (kind, expires_at)`;
  await db`CREATE INDEX mcp_grants_identity_id_idx ON mcp_grants (identity_id)`;
  await db`CREATE INDEX mcp_grants_client_id_idx ON mcp_grants (client_id)`;
  // One live consent per (client, person). A revoked grant stays as history but
  // no longer blocks a fresh approval.
  await db`
    CREATE UNIQUE INDEX mcp_grants_live_idx
    ON mcp_grants (client_id, identity_id)
    WHERE revoked_at IS NULL
  `;
  await db`CREATE INDEX mcp_auth_requests_expires_at_idx ON mcp_auth_requests (expires_at)`;
  await db`CREATE INDEX mcp_audit_created_at_idx ON mcp_audit (created_at)`;
  await db`CREATE INDEX mcp_audit_action_idx ON mcp_audit (action)`;
};

export const down = async (db: SQL): Promise<void> => {
  await db`DROP TABLE IF EXISTS mcp_audit`;
  await db`DROP TABLE IF EXISTS mcp_auth_requests`;
  await db`DROP TABLE IF EXISTS mcp_tokens`;
  await db`DROP TABLE IF EXISTS mcp_grants`;
  await db`DROP TABLE IF EXISTS mcp_clients`;
};
