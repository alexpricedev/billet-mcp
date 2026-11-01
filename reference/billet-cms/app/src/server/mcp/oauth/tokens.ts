/**
 * Grants and opaque credentials.
 *
 * An access token is 32 random bytes with a `bcmcp_at_` prefix, stored as the
 * CMS's peppered HMAC. Nothing is signed: the token is meaningless outside this
 * database, so there is no key to rotate and no JWT to accidentally accept from
 * another issuer. Verification is one indexed join, an expiry check, an
 * audience check and a fresh read of `cms_identities` — the site removing the
 * person ends every token they approved at the next request.
 *
 * Refresh tokens rotate, and a rotated token presented again revokes the whole
 * grant. That is the OAuth 2.1 public-client rule: a stolen refresh token and
 * the real one racing means one of them fails, and the safe response is to make
 * both useless.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { SQL } from "bun";
import { recordAudit } from "../../services/audit";
import { findUserById, type User } from "../../services/auth";
import { db } from "../../services/database";
import { computeHMAC } from "../../utils/crypto";
import {
  MCP_ACCESS_TTL_SECONDS,
  MCP_REFRESH_TTL_SECONDS,
  MCP_SCOPE,
  mcpResource,
} from "./config";

export type McpTokenKind = "access" | "refresh" | "code";

export interface McpGrantRecord {
  id: string;
  clientId: string;
  identityId: string;
  scope: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
}

interface GrantRow {
  id: string;
  client_id: string;
  identity_id: string;
  scope: string;
  created_at: Date;
  last_used_at: Date | null;
  revoked_at: Date | null;
}

const toGrant = (row: GrantRow): McpGrantRecord => ({
  id: row.id,
  clientId: row.client_id,
  identityId: row.identity_id,
  scope: row.scope,
  createdAt: row.created_at,
  lastUsedAt: row.last_used_at,
  revokedAt: row.revoked_at,
});

const isUniqueViolation = (error: unknown): boolean => {
  if (typeof error !== "object" || error === null) return false;
  const code = (error as { errno?: unknown }).errno;
  return code === "23505";
};

/**
 * Approve (or re-approve) one client for one person.
 *
 * A live grant is reused so reconnecting the same client does not litter the
 * Connected apps page; a revoked one is left as history and a fresh grant is
 * created. The partial unique index on `(client_id, identity_id) WHERE
 * revoked_at IS NULL` is the backstop for two approvals racing.
 */
export const createOrReuseGrant = async (
  input: { clientId: string; identityId: string; scope?: string },
  sql: SQL = db,
): Promise<McpGrantRecord> => {
  const scope = input.scope ?? MCP_SCOPE;
  const find = async (): Promise<GrantRow | null> => {
    const rows = (await sql`
      SELECT id, client_id, identity_id, scope, created_at, last_used_at, revoked_at
      FROM cms_mcp_grants
      WHERE client_id = ${input.clientId}
        AND identity_id = ${input.identityId}
        AND revoked_at IS NULL
    `) as GrantRow[];
    return rows[0] ?? null;
  };

  const existing = await find();
  if (existing) return toGrant(existing);

  try {
    const rows = (await sql`
      INSERT INTO cms_mcp_grants (client_id, identity_id, scope)
      VALUES (${input.clientId}, ${input.identityId}, ${scope})
      RETURNING id, client_id, identity_id, scope, created_at, last_used_at, revoked_at
    `) as GrantRow[];
    return toGrant(rows[0]);
  } catch (error) {
    if (!isUniqueViolation(error)) throw error;
    const raced = await find();
    if (!raced) throw error;
    return toGrant(raced);
  }
};

export const getGrantById = async (
  grantId: string,
  sql: SQL = db,
): Promise<McpGrantRecord | null> => {
  const rows = (await sql`
    SELECT id, client_id, identity_id, scope, created_at, last_used_at, revoked_at
    FROM cms_mcp_grants
    WHERE id = ${grantId}
  `) as GrantRow[];
  return rows.length > 0 ? toGrant(rows[0]) : null;
};

/** Revoke a grant. Every token it issued stops verifying immediately. */
export const revokeGrant = async (
  grantId: string,
  actorId: string | null,
): Promise<boolean> => {
  const rows = await db`
    UPDATE cms_mcp_grants
    SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
    WHERE id = ${grantId}
    RETURNING id
  `;
  if (rows.length === 0) return false;
  await db`
    UPDATE cms_mcp_tokens
    SET rotated_at = COALESCE(rotated_at, CURRENT_TIMESTAMP)
    WHERE grant_id = ${grantId}
  `;
  await recordAudit({
    action: "mcp_grant.revoked",
    actorId,
    subjectType: "mcp_grant",
    subjectId: grantId,
  });
  return true;
};

const tokenPrefix = (kind: McpTokenKind): string =>
  kind === "access"
    ? "bcmcp_at_"
    : kind === "refresh"
      ? "bcmcp_rt_"
      : "bcmcp_code_";

/** Mint one opaque credential and store only its hash. */
export const mintToken = async (
  input: {
    grantId: string;
    kind: McpTokenKind;
    resource: string;
    ttlSeconds: number;
    codeChallenge?: string | null;
    redirectUri?: string | null;
  },
  sql: SQL = db,
): Promise<string> => {
  const raw = `${tokenPrefix(input.kind)}${randomBytes(32).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000);
  await sql`
    INSERT INTO cms_mcp_tokens
      (grant_id, token_hash, kind, resource, expires_at, code_challenge, redirect_uri)
    VALUES (
      ${input.grantId},
      ${computeHMAC(raw)},
      ${input.kind},
      ${input.resource},
      ${expiresAt},
      ${input.codeChallenge ?? null},
      ${input.redirectUri ?? null}
    )
  `;
  return raw;
};

export interface AccessTokenContext {
  grant: McpGrantRecord;
  actor: User;
  resource: string;
  /** Seconds since the epoch, for `AuthInfo.expiresAt`. */
  expiresAt: number;
}

interface AccessTokenRow extends GrantRow {
  resource: string;
  expires_at: Date;
}

/**
 * The grant a live access token names, or `null`.
 *
 * `resource` is checked against this deployment rather than trusted from the
 * row: a token minted for another origin must not authenticate here, even if
 * the database was copied between environments.
 */
export const verifyAccessToken = async (
  rawToken: string,
): Promise<AccessTokenContext | null> => {
  const rows = (await db`
    SELECT t.resource, t.expires_at,
           g.id, g.client_id, g.identity_id, g.scope, g.created_at,
           g.last_used_at, g.revoked_at
    FROM cms_mcp_tokens t
    JOIN cms_mcp_grants g ON g.id = t.grant_id
    WHERE t.token_hash = ${computeHMAC(rawToken)}
      AND t.kind = 'access'
  `) as AccessTokenRow[];

  if (rows.length === 0) return null;
  const row = rows[0];
  if (new Date(row.expires_at).getTime() <= Date.now()) return null;
  if (row.revoked_at !== null) return null;
  if (row.resource !== mcpResource()) return null;

  const actor = await findUserById(row.identity_id);
  if (!actor) return null;

  // Stamped at most once a minute: an agent making several calls a turn should
  // not turn every one into an UPDATE.
  await db`
    UPDATE cms_mcp_grants
    SET last_used_at = CURRENT_TIMESTAMP
    WHERE id = ${row.id}
      AND (
        last_used_at IS NULL
        OR last_used_at < CURRENT_TIMESTAMP - INTERVAL '60 seconds'
      )
  `;

  return {
    grant: toGrant(row),
    actor,
    resource: row.resource,
    expiresAt: Math.floor(new Date(row.expires_at).getTime() / 1000),
  };
};

const PKCE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * Verify an S256 PKCE verifier against the challenge the code was minted with.
 *
 * Length and alphabet are checked first: both are part of RFC 7636, and an
 * oversized verifier is a cheap way to make the hash do unnecessary work.
 */
export const verifyPkce = (verifier: string, challenge: string): boolean => {
  if (!PKCE_VERIFIER.test(verifier)) return false;
  const computed = createHash("sha256").update(verifier).digest("base64url");
  const left = Buffer.from(computed);
  const right = Buffer.from(challenge);
  return left.length === right.length && timingSafeEqual(left, right);
};

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
}

const issuePair = async (
  grant: McpGrantRecord,
  resource: string,
  sql: SQL,
): Promise<TokenPair> => ({
  accessToken: await mintToken(
    {
      grantId: grant.id,
      kind: "access",
      resource,
      ttlSeconds: MCP_ACCESS_TTL_SECONDS,
    },
    sql,
  ),
  refreshToken: await mintToken(
    {
      grantId: grant.id,
      kind: "refresh",
      resource,
      ttlSeconds: MCP_REFRESH_TTL_SECONDS,
    },
    sql,
  ),
  expiresIn: MCP_ACCESS_TTL_SECONDS,
  scope: grant.scope,
});

export type ExchangeFailure = {
  ok: false;
  error: "invalid_grant" | "invalid_client" | "invalid_target";
  description: string;
};

export type ExchangeCodeResult =
  | { ok: true; grant: McpGrantRecord; tokens: TokenPair }
  | ExchangeFailure;

interface CodeRow extends GrantRow {
  token_id: string;
  resource: string;
  expires_at: Date;
  rotated_at: Date | null;
  code_challenge: string | null;
  redirect_uri: string | null;
}

/**
 * Redeem an authorization code exactly once.
 *
 * Everything is checked under the code row's lock, so two simultaneous
 * exchanges cannot both pass. A failed check still spends nothing: the row is
 * only marked rotated after every check succeeds.
 */
export const exchangeAuthorizationCode = async (input: {
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
  resource?: string | null;
}): Promise<ExchangeCodeResult> =>
  db.begin(async (tx) => {
    const rows = (await tx`
      SELECT t.id AS token_id, t.resource, t.expires_at, t.rotated_at,
             t.code_challenge, t.redirect_uri,
             g.id, g.client_id, g.identity_id, g.scope, g.created_at,
             g.last_used_at, g.revoked_at
      FROM cms_mcp_tokens t
      JOIN cms_mcp_grants g ON g.id = t.grant_id
      WHERE t.token_hash = ${computeHMAC(input.code)}
        AND t.kind = 'code'
      FOR UPDATE
    `) as CodeRow[];

    if (rows.length === 0) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "Unknown or expired authorization code.",
      };
    }
    const code = rows[0];
    if (
      code.rotated_at !== null ||
      new Date(code.expires_at).getTime() <= Date.now()
    ) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "Unknown or expired authorization code.",
      };
    }
    if (code.revoked_at !== null) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "This grant has been revoked.",
      };
    }
    if (code.client_id !== input.clientId) {
      return {
        ok: false as const,
        error: "invalid_client" as const,
        description: "The code was issued to a different client.",
      };
    }
    if (code.redirect_uri !== input.redirectUri) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "redirect_uri does not match the authorization request.",
      };
    }
    if (code.resource !== mcpResource()) {
      return {
        ok: false as const,
        error: "invalid_target" as const,
        description: "The code was issued for another resource.",
      };
    }
    if (input.resource && input.resource !== code.resource) {
      return {
        ok: false as const,
        error: "invalid_target" as const,
        description: "resource does not match the authorization request.",
      };
    }
    if (
      !code.code_challenge ||
      !verifyPkce(input.codeVerifier, code.code_challenge)
    ) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "PKCE verification failed.",
      };
    }

    await tx`
      UPDATE cms_mcp_tokens SET rotated_at = CURRENT_TIMESTAMP WHERE id = ${code.token_id}
    `;

    const grant = toGrant(code);
    return {
      ok: true as const,
      grant,
      tokens: await issuePair(grant, code.resource, tx),
    };
  });

export type RefreshResult =
  | { ok: true; grant: McpGrantRecord; tokens: TokenPair }
  | ExchangeFailure;

/**
 * Rotate a refresh token, revoking the grant when a spent one comes back.
 *
 * The reuse branch is intentionally blunt: if a row exists, was rotated, and
 * is presented again, either the client raced itself or someone copied it.
 * Either way the grant is no longer trustworthy.
 */
export const rotateRefreshToken = async (input: {
  refreshToken: string;
  clientId: string;
  resource?: string | null;
}): Promise<RefreshResult> =>
  db.begin(async (tx) => {
    const rows = (await tx`
      SELECT t.id AS token_id, t.resource, t.expires_at, t.rotated_at,
             g.id, g.client_id, g.identity_id, g.scope, g.created_at,
             g.last_used_at, g.revoked_at
      FROM cms_mcp_tokens t
      JOIN cms_mcp_grants g ON g.id = t.grant_id
      WHERE t.token_hash = ${computeHMAC(input.refreshToken)}
        AND t.kind = 'refresh'
      FOR UPDATE
    `) as CodeRow[];

    if (rows.length === 0) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "Unknown refresh token.",
      };
    }
    const token = rows[0];

    if (token.rotated_at !== null) {
      await tx`
        UPDATE cms_mcp_grants SET revoked_at = CURRENT_TIMESTAMP
        WHERE id = ${token.id} AND revoked_at IS NULL
      `;
      await tx`
        UPDATE cms_mcp_tokens SET rotated_at = COALESCE(rotated_at, CURRENT_TIMESTAMP)
        WHERE grant_id = ${token.id}
      `;
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description:
          "Refresh token reuse detected; the connection was revoked.",
      };
    }
    if (new Date(token.expires_at).getTime() <= Date.now()) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "Refresh token expired.",
      };
    }
    if (token.revoked_at !== null) {
      return {
        ok: false as const,
        error: "invalid_grant" as const,
        description: "This grant has been revoked.",
      };
    }
    if (token.client_id !== input.clientId) {
      return {
        ok: false as const,
        error: "invalid_client" as const,
        description: "The refresh token was issued to a different client.",
      };
    }
    if (token.resource !== mcpResource()) {
      return {
        ok: false as const,
        error: "invalid_target" as const,
        description: "The refresh token was issued for another resource.",
      };
    }
    if (input.resource && input.resource !== token.resource) {
      return {
        ok: false as const,
        error: "invalid_target" as const,
        description: "resource does not match the refresh token.",
      };
    }

    await tx`
      UPDATE cms_mcp_tokens SET rotated_at = CURRENT_TIMESTAMP WHERE id = ${token.token_id}
    `;

    const grant = toGrant(token);
    return {
      ok: true as const,
      grant,
      tokens: await issuePair(grant, token.resource, tx),
    };
  });

export interface McpGrantSummary {
  id: string;
  clientId: string;
  clientName: string;
  identityEmail: string | null;
  scope: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
}

interface GrantSummaryRow extends GrantRow {
  client_name: string | null;
  identity_email: string | null;
}

/** Every consent, for the Connected apps page. */
export const listGrants = async (): Promise<McpGrantSummary[]> => {
  const rows = (await db`
    SELECT g.id, g.client_id, g.identity_id, g.scope, g.created_at,
           g.last_used_at, g.revoked_at,
           c.client_name, i.email AS identity_email
    FROM cms_mcp_grants g
    JOIN cms_mcp_clients c ON c.client_id = g.client_id
    LEFT JOIN cms_identities i ON i.id = g.identity_id
    ORDER BY g.created_at DESC, g.id DESC
  `) as GrantSummaryRow[];

  return rows.map((row) => ({
    id: row.id,
    clientId: row.client_id,
    clientName: row.client_name ?? "Unnamed MCP client",
    identityEmail: row.identity_email,
    scope: row.scope,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
  }));
};

/** Delete credentials nothing can use any more. Never touches live grants. */
export const cleanupExpiredMcpCredentials = async (): Promise<void> => {
  await db`DELETE FROM cms_mcp_auth_requests WHERE expires_at <= CURRENT_TIMESTAMP`;
  await db`DELETE FROM cms_mcp_tokens WHERE kind = 'code' AND expires_at <= CURRENT_TIMESTAMP`;
  await db`
    DELETE FROM cms_mcp_tokens
    WHERE kind IN ('access', 'refresh')
      AND expires_at <= CURRENT_TIMESTAMP - INTERVAL '1 day'
  `;
};
