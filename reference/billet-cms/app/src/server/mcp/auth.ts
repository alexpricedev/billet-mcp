/**
 * The MCP bearer gate.
 *
 * Two credentials are accepted during the OAuth build-out:
 *
 * - the development token from `MCP_DEV_TOKEN`, only outside production, so the
 *   spike and the matrix keep working while the connector flow is unfinished;
 * - an OAuth access token minted by `/mcp/token`, verified against
 *   `cms_mcp_tokens`, its grant, its audience and `cms_identities`.
 *
 * Both arrive as `Authorization: Bearer …`. There is no session and no CSRF:
 * the caller is a machine, and the token is the whole credential.
 *
 * The 401 carries the RFC 9728 `resource_metadata` pointer. Claude starts its
 * sign-in from that header and ignores one on a 200, so it is part of the
 * handshake, not decoration.
 */
import { timingSafeEqual } from "node:crypto";
import { TABLES } from "@alexpricedev/billet-cms/contract";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { db } from "../services/database";
import { log } from "../services/logger";
import { mcpDevIdentityEmail, mcpDevToken } from "./config";
import { MCP_SCOPE, mcpResourceMetadataUrl } from "./oauth/config";
import { verifyAccessToken } from "./oauth/tokens";

export interface McpActor {
  id: string;
  email: string;
  role: string;
}

interface ActorRow {
  id: string;
  email: string;
  role: string;
}

/** The raw token out of an `Authorization: Bearer …` header, or `null`. */
export const readBearerToken = (header: string | null): string | null => {
  if (!header) return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1].trim();
  return token === "" ? null : token;
};

/**
 * Constant-time string comparison.
 *
 * `timingSafeEqual` throws when the lengths differ, so compare lengths first
 * and return false. Length is not a secret; the bytes are.
 */
const constantTimeEqual = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

/**
 * Resolve the identity the dev token acts as.
 *
 * The email is configured rather than inferred: guessing "the first admin"
 * would make a write attribute itself to a person nobody chose. A configured
 * email that no longer resolves is logged and treated as no identity, so reads
 * still work while a write has no author.
 */
const resolveDevActor = async (): Promise<McpActor | null> => {
  const email = mcpDevIdentityEmail();
  if (!email) return null;

  const rows = (await db.unsafe(
    `SELECT id, email, role FROM ${TABLES.identities} WHERE lower(email) = $1`,
    [email],
  )) as ActorRow[];

  if (rows.length === 0) {
    log.warn(
      "mcp",
      `MCP_DEV_IDENTITY_EMAIL "${email}" is not in cms_identities; writes will have no author.`,
    );
    return null;
  }

  return rows[0];
};

export type McpAuthResult =
  | { ok: true; authInfo: AuthInfo }
  | { ok: false; response: Response };

/**
 * The 401 every unauthenticated or invalid request gets.
 *
 * `error="invalid_token"` is only for a token that was present and rejected;
 * a missing token gets the bare challenge, which is what starts the client's
 * sign-in rather than ending it in an error state.
 */
const unauthorized = (message: string, invalidToken: boolean): Response => {
  const challenge = [
    `Bearer resource_metadata="${mcpResourceMetadataUrl()}"`,
    `scope="${MCP_SCOPE}"`,
    ...(invalidToken ? ['error="invalid_token"'] : []),
  ].join(", ");

  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32001, message },
    }),
    {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "WWW-Authenticate": challenge,
        "Cache-Control": "no-store",
      },
    },
  );
};

/**
 * Verify the request's bearer token and build the `AuthInfo` the SDK hands to
 * every tool handler.
 *
 * `extra.actor` carries the resolved CMS identity. The SDK's `AuthInfo` has no
 * notion of one, and the tool layer needs it for `created_by` and
 * `get_profile`, so it rides along the field meant for exactly this.
 */
export const authenticateMcpRequest = async (
  req: Request,
): Promise<McpAuthResult> => {
  const token = readBearerToken(req.headers.get("authorization"));
  if (!token) {
    return {
      ok: false,
      response: unauthorized("An access token is required.", false),
    };
  }

  // The development credential, deliberately not accepted in production even if
  // one is configured. `validateEnv` only warns about it there, so this check is
  // the lock.
  const devToken = mcpDevToken();
  if (
    devToken &&
    process.env.NODE_ENV !== "production" &&
    constantTimeEqual(token, devToken)
  ) {
    return {
      ok: true,
      authInfo: {
        token,
        clientId: "dev",
        scopes: [MCP_SCOPE],
        extra: { actor: await resolveDevActor(), grantId: "dev" },
      },
    };
  }

  const context = await verifyAccessToken(token);
  if (!context) {
    return {
      ok: false,
      response: unauthorized("Invalid or expired access token.", true),
    };
  }

  return {
    ok: true,
    authInfo: {
      token,
      clientId: context.grant.clientId,
      scopes: [context.grant.scope],
      expiresAt: context.expiresAt,
      resource: new URL(context.resource),
      extra: { actor: context.actor, grantId: context.grant.id },
    },
  };
};

/** The identity an `AuthInfo` carries, or `null` for an anonymous dev caller. */
export const actorFromAuthInfo = (
  authInfo: AuthInfo | undefined,
): McpActor | null => {
  const actor = authInfo?.extra?.actor;
  if (
    typeof actor === "object" &&
    actor !== null &&
    "id" in actor &&
    "email" in actor
  ) {
    return actor as McpActor;
  }
  return null;
};

/** The grant a verified token names, or `null` when there is none. */
export const grantIdFromAuthInfo = (
  authInfo: AuthInfo | undefined,
): string | null => {
  const grantId = authInfo?.extra?.grantId;
  return typeof grantId === "string" && grantId !== "" ? grantId : null;
};
