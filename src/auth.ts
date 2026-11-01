/**
 * The MCP bearer gate.
 *
 * The only credential is an OAuth access token minted by `/mcp/token`, verified
 * against `mcp_tokens`, its grant, its audience and the app's user. It arrives
 * as `Authorization: Bearer …`. There is no session and no CSRF: the caller is
 * a machine, and the token is the whole credential.
 *
 * The 401 carries the RFC 9728 `resource_metadata` pointer. Claude starts its
 * sign-in from that header and ignores one on a 200, so it is part of the
 * handshake, not decoration.
 */
import type { AuthInfo } from "@modelcontextprotocol/server";
import { MCP_SCOPE, type McpContext } from "./config";
import { verifyAccessToken } from "./oauth/tokens";
import type { McpUser } from "./types";

/** The raw token out of an `Authorization: Bearer …` header, or `null`. */
export const readBearerToken = (header: string | null): string | null => {
  if (!header) return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1].trim();
  return token === "" ? null : token;
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
const unauthorized = (
  ctx: McpContext,
  message: string,
  invalidToken: boolean,
): Response => {
  const challenge = [
    `Bearer resource_metadata="${ctx.resourceMetadataUrl}"`,
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
 * `extra.user` carries the resolved app user. The SDK's `AuthInfo` has no
 * notion of one, and the tool layer needs it, so it rides along the field
 * meant for exactly this.
 */
export const authenticateMcpRequest = async (
  ctx: McpContext,
  req: Request,
): Promise<McpAuthResult> => {
  const token = readBearerToken(req.headers.get("authorization"));
  if (!token) {
    return {
      ok: false,
      response: unauthorized(ctx, "An access token is required.", false),
    };
  }

  const context = await verifyAccessToken(ctx, token);
  if (!context) {
    return {
      ok: false,
      response: unauthorized(ctx, "Invalid or expired access token.", true),
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
      extra: { user: context.actor, grantId: context.grant.id },
    },
  };
};

/** The user an `AuthInfo` carries, or `null`. */
export const userFromAuthInfo = (
  authInfo: AuthInfo | undefined,
): McpUser | null => {
  const user = authInfo?.extra?.user;
  if (
    typeof user === "object" &&
    user !== null &&
    "id" in user &&
    "email" in user
  ) {
    return user as McpUser;
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
