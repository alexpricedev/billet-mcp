/**
 * The route map: the MCP endpoint and its OAuth surface.
 *
 * Auth on `/mcp` is a bearer token. There is no session and no CSRF, because
 * there is no cookie to forge. The two browser-facing routes render HTML, so
 * they run inside the app's `secureHeaders` wrapper when it supplies one.
 */
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import {
  authenticateMcpRequest,
  grantIdFromAuthInfo,
  userFromAuthInfo,
} from "./auth";
import { auditToolCall, parseToolCall, readRpcBody } from "./audit";
import { createAuthorizeHandlers } from "./authorize";
import { type McpContext, TOOL_CALLS_PER_MINUTE } from "./config";
import {
  JSON_HEADERS,
  limited,
  methodNotAllowed,
  oauthError,
} from "./http";
import { registerClient } from "./oauth/clients";
import {
  authorizationServerMetadata,
  protectedResourceMetadata,
} from "./oauth/discovery";
import { createTokenHandlers } from "./token";
import type { McpHandler, McpRoutes } from "./types";

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
 * still run every call in a batch, so one POST could call a tool repeatedly with
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

/**
 * A JSON-RPC 429 rather than the app's error envelope.
 *
 * A model can read "you are being rate limited" and back off. `Retry-After` is
 * preserved from the app's hook, so a client that honours it stops at the
 * earliest moment a retry can succeed.
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

const createHandleMcp = (ctx: McpContext): McpHandler => {
  const { server: info, registerTools } = ctx.options;

  const mcpHandler = createMcpHandler(
    async ({ authInfo }) => {
      const server = new McpServer(
        { name: info.name, version: info.version },
        info.instructions ? { instructions: info.instructions } : undefined,
      );
      const user = userFromAuthInfo(authInfo);
      if (user) await registerTools(server, user);
      return server;
    },
    { legacy: "stateless" },
  );

  return async (req) => {
    const auth = await authenticateMcpRequest(ctx, req);
    if (!auth.ok) return auth.response;

    // Parse the call before the SDK reads the body: the clone gives us the tool
    // name for the budget and for the audit, without changing what the handler
    // sees.
    const body = await readRpcBody(req);
    if (Array.isArray(body)) return batchRefused();
    const call = parseToolCall(body);
    if (call) {
      const grantId = grantIdFromAuthInfo(auth.authInfo) ?? "unknown";
      const refused = await limited(ctx, req, {
        name: "mcp-tool",
        limit: TOOL_CALLS_PER_MINUTE,
        windowMs: 60_000,
        key: `mcp-tool:${grantId}`,
      });
      if (refused) return rateLimited(refused, call.id);
    }

    try {
      const response = await mcpHandler.fetch(req, {
        authInfo: auth.authInfo,
      });
      if (call) await auditToolCall(ctx, call, auth.authInfo, response);
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
      ctx.log.error(
        "mcp",
        `Unhandled error on ${req.method} /mcp: ${error instanceof Error ? error.message : String(error)}`,
      );
      return internalError("The server could not complete this MCP request.");
    }
  };
};

/**
 * A public discovery document.
 *
 * These are read by the client's backend before any sign-in, so they carry
 * permissive CORS and a short cache. They contain no credentials and no user
 * data.
 */
const wellKnown =
  (document: () => unknown): McpHandler =>
  (req) => {
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
const createRegister =
  (ctx: McpContext): McpHandler =>
  async (req) => {
    if (req.method !== "POST") return methodNotAllowed("POST");

    const refused = await limited(ctx, req, {
      name: "mcp-register",
      limit: 10,
      windowMs: 60_000,
    });
    if (refused) return refused;

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
      const result = await registerClient(
        ctx,
        body as Record<string, unknown>,
      );
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
      ctx.log.error(
        "mcp",
        `Client registration failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return oauthError(
        500,
        "server_error",
        "The server could not register this client.",
      );
    }
  };

/** Dispatch on method, answering 405 with `Allow` for any other. */
const byMethod =
  (handlers: Partial<Record<"GET" | "POST", McpHandler>>): McpHandler =>
  (req) => {
    const handler = handlers[req.method as "GET" | "POST"];
    return handler
      ? handler(req)
      : methodNotAllowed(Object.keys(handlers).join(", "));
  };

export const createRoutes = (ctx: McpContext): McpRoutes => {
  const authorize = createAuthorizeHandlers(ctx);
  const token = createTokenHandlers(ctx);

  // The HTML consent pages run inside the app's header and error pipeline.
  const guarded =
    (handler: McpHandler): McpHandler =>
    (req) =>
      ctx.options.secureHeaders
        ? ctx.options.secureHeaders(req, handler)
        : handler(req);

  const resourceMetadata = wellKnown(() => protectedResourceMetadata(ctx));

  return {
    "/mcp": createHandleMcp(ctx),
    "/.well-known/oauth-protected-resource": resourceMetadata,
    "/.well-known/oauth-protected-resource/mcp": resourceMetadata,
    "/.well-known/oauth-authorization-server": wellKnown(() =>
      authorizationServerMetadata(ctx),
    ),
    "/mcp/register": createRegister(ctx),
    "/mcp/authorize": byMethod({
      GET: guarded(authorize.index),
      POST: guarded(authorize.create),
    }),
    "/mcp/authorize/continue": byMethod({ GET: guarded(authorize.continue) }),
    "/mcp/token": byMethod({ POST: token.create }),
  };
};
