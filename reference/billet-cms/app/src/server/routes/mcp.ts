/**
 * The machine-facing routes: the MCP endpoint and its OAuth discovery surface.
 *
 * These are mounted outside `secureRoutes` (`main.ts`), so they answer JSON and
 * JSON-RPC errors rather than the CMS's HTML pipeline, and nothing buffers a
 * stream. The two browser-facing consent routes are the exception: they render
 * HTML, so they opt back in to `handleGuarded` (security headers, maintenance
 * mode, the styled 500). Every one is gated by `MCP_ENABLED`.
 *
 * Auth is a bearer token: the development token outside production, or an
 * OAuth access token once the connector flow is in use. There is no session and
 * no CSRF, because there is no cookie to forge.
 */
import type { BunRequest } from "bun";
import { authorize } from "../controllers/mcp/authorize";
import { token } from "../controllers/mcp/token";
import { mcpHandler } from "../mcp";
import { auditToolCall, parseToolCall, readRpcBody } from "../mcp/audit";
import { authenticateMcpRequest, grantIdFromAuthInfo } from "../mcp/auth";
import { isMcpEnabled } from "../mcp/config";
import { registerClient } from "../mcp/oauth/clients";
import {
  authorizationServerMetadata,
  protectedResourceMetadata,
} from "../mcp/oauth/discovery";
import { rateLimit, rateLimitByKey } from "../middleware/rate-limit";
import { log } from "../services/logger";
import { createRouteHandler } from "../utils/route-handler";
import { handleGuarded } from "../utils/security-headers";

const JSON_HEADERS = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "X-Robots-Tag": "noindex",
};

const disabled = (): Response =>
  new Response("", { status: 404, headers: { "Cache-Control": "no-store" } });

const methodNotAllowed = (allow: string): Response =>
  new Response("", {
    status: 405,
    headers: { Allow: allow, "Cache-Control": "no-store" },
  });

const oauthError = (
  status: number,
  error: string,
  description: string,
): Response =>
  Response.json(
    { error, error_description: description },
    {
      status,
      headers: { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
    },
  );

const internalError = (message: string): Response =>
  new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32603, message },
    }),
    { status: 500, headers: JSON_HEADERS },
  );

/**
 * JSON-RPC batches are refused outright.
 *
 * The rate limit and the audit both work on a single `tools/call`; the SDK would
 * still run every call in a batch, so one POST could publish repeatedly with
 * neither. MCP dropped batching in the 2025-06-18 revision, so no current client
 * sends one.
 */
const batchRefused = (): Response =>
  new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32600,
        message:
          "JSON-RPC batches are not supported. Send one request per POST.",
      },
    }),
    { status: 400, headers: JSON_HEADERS },
  );

const TOOL_CALLS_PER_MINUTE = 120;
const WRITES_PER_MINUTE = 30;

/**
 * Tools that change content, and so spend the smaller per-grant budget.
 *
 * The delete and media names are reserved for tools that are not registered yet,
 * so the write budget already applies the day one of them lands.
 */
const WRITE_TOOLS = new Set([
  "save_slot",
  "save_page",
  "publish_slot",
  "publish_page",
  "delete_page",
  "upload_media",
  "update_media",
  "delete_media",
]);

/**
 * A JSON-RPC 429 rather than the CMS's error envelope.
 *
 * A model can read "you are being rate limited" and back off; a body shaped for
 * a different API cannot. `Retry-After` is preserved, so a client that honours
 * it stops at the earliest moment a retry can succeed.
 */
const rateLimited = (
  response: Response,
  id: string | number | null,
): Response => {
  const retryAfter = response.headers.get("Retry-After") ?? "1";
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      error: {
        code: -32000,
        message: `Too many requests. Try again in ${retryAfter}s.`,
      },
    }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": retryAfter,
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex",
      },
    },
  );
};

export const handleMcp = async (req: BunRequest): Promise<Response> => {
  if (!isMcpEnabled()) return disabled();

  const auth = await authenticateMcpRequest(req);
  if (!auth.ok) return auth.response;

  // Parse the call before the SDK reads the body: the clone gives us the tool
  // name for the budget and for the audit, without changing what the handler
  // sees.
  const body = await readRpcBody(req);
  if (Array.isArray(body)) return batchRefused();
  const call = parseToolCall(body);
  if (call) {
    const grantId = grantIdFromAuthInfo(auth.authInfo) ?? "unknown";
    const limited = rateLimitByKey(
      `mcp-tool:${grantId}`,
      TOOL_CALLS_PER_MINUTE,
      60_000,
    );
    if (limited) return rateLimited(limited, call.id);

    if (WRITE_TOOLS.has(call.name)) {
      const writeLimited = rateLimitByKey(
        `mcp-write:${grantId}`,
        WRITES_PER_MINUTE,
        60_000,
      );
      if (writeLimited) return rateLimited(writeLimited, call.id);
    }
  }

  try {
    const response = await mcpHandler.fetch(req, {
      authInfo: auth.authInfo,
    });
    if (call) await auditToolCall(call, auth.authInfo, response);
    // The SDK may already set these on a streamed response; only add what is
    // missing so its headers win.
    if (!response.headers.has("Cache-Control")) {
      response.headers.set("Cache-Control", "no-store");
    }
    if (!response.headers.has("X-Robots-Tag")) {
      response.headers.set("X-Robots-Tag", "noindex");
    }
    return response;
  } catch (error) {
    log.error(
      "mcp",
      `Unhandled error on ${req.method} /mcp: ${error instanceof Error ? error.message : String(error)}`,
    );
    return internalError("The CMS could not complete this MCP request.");
  }
};

/**
 * A public discovery document.
 *
 * These are read by the client's backend before any sign-in, so they carry
 * permissive CORS (the MCP Server Card guidance treats public metadata the same
 * way) and a short cache. They contain no credentials and no user data.
 */
const wellKnown =
  (document: () => unknown) =>
  (req: BunRequest): Response => {
    if (!isMcpEnabled()) return disabled();
    if (req.method !== "GET" && req.method !== "HEAD") {
      return methodNotAllowed("GET, HEAD");
    }

    const headers = {
      "Cache-Control": "public, max-age=300",
      "Access-Control-Allow-Origin": "*",
      "X-Robots-Tag": "noindex",
    };

    if (req.method === "HEAD") {
      return new Response(null, { status: 200, headers });
    }
    return Response.json(document(), { headers });
  };

/**
 * Dynamic client registration (RFC 7591), public clients only.
 *
 * The redirect allowlist in `isAllowedRedirectUri` is what makes an open
 * registration endpoint safe: a client cannot register a callback on a host it
 * controls and then use our consent screen to phish a code. The per-IP budget
 * is small because a real connection registers once.
 */
const register = async (req: BunRequest): Promise<Response> => {
  if (!isMcpEnabled()) return disabled();
  if (req.method !== "POST") return methodNotAllowed("POST");

  const limited = rateLimit(req, "mcp-register", 10, 60_000);
  if (limited) return limited;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return oauthError(
      400,
      "invalid_client_metadata",
      "The request body must be JSON.",
    );
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return oauthError(
      400,
      "invalid_client_metadata",
      "The request body must be a JSON object.",
    );
  }

  try {
    const result = await registerClient(body as Record<string, unknown>);
    if (!result.ok) {
      return oauthError(400, result.error, result.description);
    }

    return Response.json(
      {
        client_id: result.client.clientId,
        client_name: result.client.clientName,
        redirect_uris: result.client.redirectUris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      },
      {
        status: 201,
        headers: { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
      },
    );
  } catch (error) {
    log.error(
      "mcp",
      `Client registration failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return oauthError(
      500,
      "server_error",
      "The CMS could not register this client.",
    );
  }
};

/**
 * Gate a browser-facing handler on `MCP_ENABLED`.
 *
 * A disabled deployment answers 404 for the whole surface, discovery included,
 * so a client cannot start a flow against a CMS that will not finish it.
 */
const gated =
  (handler: (req: BunRequest) => Response | Promise<Response>) =>
  async (req: BunRequest): Promise<Response> =>
    isMcpEnabled() ? handler(req) : disabled();

/** `gated`, plus the CMS's header and error pipeline for the HTML consent pages. */
const guarded = (handler: (req: BunRequest) => Response | Promise<Response>) =>
  gated((req) => handleGuarded(req, handler));

export const mcpRoutes = {
  "/mcp": handleMcp,
  "/.well-known/oauth-protected-resource": wellKnown(protectedResourceMetadata),
  "/.well-known/oauth-protected-resource/mcp": wellKnown(
    protectedResourceMetadata,
  ),
  "/.well-known/oauth-authorization-server": wellKnown(
    authorizationServerMetadata,
  ),
  "/mcp/register": register,
  "/mcp/authorize": createRouteHandler({
    GET: guarded(authorize.index),
    POST: guarded(authorize.create),
  }),
  "/mcp/authorize/continue": createRouteHandler({
    GET: guarded(authorize.continue),
  }),
  "/mcp/token": createRouteHandler({
    POST: gated(token.create),
  }),
};
