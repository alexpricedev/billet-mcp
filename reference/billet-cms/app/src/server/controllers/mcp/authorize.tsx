/**
 * `/mcp/authorize`: the one browser-facing step of the connector flow.
 *
 * Three jobs, in order:
 *
 * 1. Validate the request. The client must be registered, and its `redirect_uri`
 *    must match one it registered exactly. An unknown client or redirect gets a
 *    page, never a redirect — the redirect is the attack surface. Every later
 *    failure (wrong response type, missing PKCE, wrong resource, unknown scope)
 *    goes back to the client as an OAuth error, with `state` and `iss`.
 * 2. Establish the person. The CMS has no sign-in of its own, so a signed-out
 *    visit stores the request, sets an opaque cookie and sends the browser
 *    through the existing `/sign-in` → site → `/handoff` chain. `/handoff`
 *    notices the cookie and returns here to `/mcp/authorize/continue`.
 * 3. Ask, then issue a code. The consent screen shows the client, the redirect
 *    host and the signed-in identity. An approval creates (or reuses) the grant
 *    and mints a single-use, 60-second code bound to the client, redirect, PKCE
 *    challenge and resource. The token endpoint does the exchange.
 */
import type { BunRequest } from "bun";
import { getClientById, splitClientName } from "../../mcp/oauth/clients";
import {
  MCP_AUTH_COOKIE,
  MCP_CODE_TTL_SECONDS,
  mcpAuthCookieOptions,
  mcpIssuer,
  mcpResource,
  parseScope,
} from "../../mcp/oauth/config";
import {
  createAuthRequest,
  deleteAuthRequest,
  getAuthRequest,
  type McpAuthRequest,
} from "../../mcp/oauth/requests";
import { createOrReuseGrant, mintToken } from "../../mcp/oauth/tokens";
import { getSessionContext } from "../../middleware/auth";
import { csrfProtection } from "../../middleware/csrf";
import { rateLimit } from "../../middleware/rate-limit";
import { recordAudit } from "../../services/audit";
import { createCsrfToken } from "../../services/csrf";
import { db } from "../../services/database";
import { log } from "../../services/logger";
import { siteOrigin } from "../../services/sign-in";
import { CONSENT_PATH, Consent } from "../../templates/mcp/consent";
import { ConsentError } from "../../templates/mcp/consent-error";
import { redirect, render } from "../../utils/response";

// The CSP and `X-Frame-Options` come from `handleGuarded` (routes/mcp.ts): a CSP
// set here would stop the full policy being applied.
const CONSENT_HEADERS = {
  "Cache-Control": "no-store",
  "X-Robots-Tag": "noindex",
};

const page = (
  element: Parameters<typeof render>[0],
  status = 200,
): Response => {
  const response = render(element, CONSENT_HEADERS);
  return new Response(response.body, { status, headers: response.headers });
};

const errorPage = (
  heading: string,
  message: string,
  status: number,
): Response =>
  page(
    <ConsentError heading={heading} message={message} siteUrl={siteOrigin()} />,
    status,
  );

const setAuthCookie = (req: BunRequest, requestId: string): void => {
  req.cookies.set(MCP_AUTH_COOKIE, requestId, mcpAuthCookieOptions());
};

const clearAuthCookie = (req: BunRequest): void => {
  req.cookies.delete(MCP_AUTH_COOKIE);
};

/**
 * Send the browser back to the client with the result.
 *
 * `iss` is added to every response, success or error, because the metadata
 * advertises `authorization_response_iss_parameter_supported`. ChatGPT uses
 * that to keep a stable redirect URI, and both clients reject a response that
 * promised `iss` and then omitted it.
 */
const backToClient = (
  redirectUri: string,
  input: {
    code?: string;
    error?: string;
    description?: string;
    state: string | null;
  },
): Response => {
  const url = new URL(redirectUri);
  if (input.code) url.searchParams.set("code", input.code);
  if (input.error) url.searchParams.set("error", input.error);
  if (input.description) {
    url.searchParams.set("error_description", input.description);
  }
  if (input.state) url.searchParams.set("state", input.state);
  url.searchParams.set("iss", mcpIssuer());
  return redirect(url.href);
};

const renderConsent = async (
  request: McpAuthRequest,
  sessionId: string,
  identityEmail: string,
): Promise<Response> => {
  const client = await getClientById(request.clientId);
  if (!client) {
    return errorPage(
      "This app is no longer registered",
      "Return to the app and start the connection again.",
      400,
    );
  }

  const csrfToken = await createCsrfToken(sessionId, "POST", CONSENT_PATH);
  const display = splitClientName(client.clientName);
  return page(
    <Consent
      clientName={display.appName}
      connectionLabel={display.connectionLabel}
      redirectHost={new URL(request.redirectUri).host}
      identityEmail={identityEmail}
      requestId={request.id}
      csrfToken={csrfToken}
    />,
  );
};

export const authorize = {
  /** Validate, then either render consent or start sign-in. */
  async index(req: BunRequest): Promise<Response> {
    const limited = rateLimit(req, "mcp-authorize", 30, 60_000);
    if (limited) return limited;

    const query = new URL(req.url).searchParams;
    const clientId = query.get("client_id");
    const redirectUri = query.get("redirect_uri");
    const state = query.get("state");

    if (!clientId || !redirectUri) {
      return errorPage(
        "This connection request is incomplete",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const client = await getClientById(clientId);
    if (!client) {
      return errorPage(
        "This app isn't registered",
        "Return to the app and start the connection again.",
        400,
      );
    }
    if (!client.redirectUris.includes(redirectUri)) {
      return errorPage(
        "This app's return address isn't registered",
        "Return to the app and start the connection again.",
        400,
      );
    }

    if (query.get("response_type") !== "code") {
      return backToClient(redirectUri, {
        error: "unsupported_response_type",
        description: "Only the authorization code flow is supported.",
        state,
      });
    }

    const challenge = query.get("code_challenge");
    if (!challenge || query.get("code_challenge_method") !== "S256") {
      return backToClient(redirectUri, {
        error: "invalid_request",
        description: "PKCE with S256 is required.",
        state,
      });
    }

    // RFC 8707: the client names the resource it wants a token for. Missing is
    // tolerated (both clients send it) by treating it as this endpoint; a
    // different value is refused rather than silently narrowed.
    const resource = query.get("resource") ?? mcpResource();
    if (resource !== mcpResource()) {
      return backToClient(redirectUri, {
        error: "invalid_target",
        description: "This server cannot issue a token for that resource.",
        state,
      });
    }

    const scope = parseScope(query.get("scope"));
    if (!scope) {
      return backToClient(redirectUri, {
        error: "invalid_scope",
        description: "Only the content scope is supported.",
        state,
      });
    }

    const request = await createAuthRequest({
      clientId: client.clientId,
      redirectUri,
      state,
      codeChallenge: challenge,
      resource,
      scope,
    });

    const ctx = await getSessionContext(req);
    if (!ctx.isAuthenticated || !ctx.user || !ctx.sessionId) {
      setAuthCookie(req, request.id);
      return redirect("/sign-in");
    }

    return renderConsent(request, ctx.sessionId, ctx.user.email);
  },

  /** Approve or deny the visible consent form. */
  async create(req: BunRequest): Promise<Response> {
    const limited = rateLimit(req, "mcp-authorize", 30, 60_000);
    if (limited) return limited;

    const csrfFailure = await csrfProtection(req, {
      method: "POST",
      path: CONSENT_PATH,
    });
    if (csrfFailure) return csrfFailure;

    const form = await req.formData();
    const requestId = form.get("request");
    const decision = form.get("decision");

    if (typeof requestId !== "string" || requestId === "") {
      return errorPage(
        "This connection request is incomplete",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const request = await getAuthRequest(requestId);
    if (!request) {
      clearAuthCookie(req);
      return errorPage(
        "This connection request expired",
        "Return to the app and start the connection again.",
        410,
      );
    }

    const ctx = await getSessionContext(req);
    if (!ctx.isAuthenticated || !ctx.user || !ctx.sessionId) {
      setAuthCookie(req, request.id);
      return redirect("/sign-in");
    }

    if (decision === "deny") {
      await deleteAuthRequest(request.id);
      clearAuthCookie(req);
      return backToClient(request.redirectUri, {
        error: "access_denied",
        description: "The connection was denied.",
        state: request.state,
      });
    }

    if (decision !== "approve") {
      return errorPage(
        "That choice wasn't recognised",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const client = await getClientById(request.clientId);
    if (!client) {
      clearAuthCookie(req);
      return errorPage(
        "This app is no longer registered",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const user = ctx.user;
    try {
      // One transaction: the grant, the code and the deletion of the pending
      // request either all happen or none do. A code that outlived its request
      // row, or a grant left behind by a failed mint, would be state nobody
      // can explain later.
      const { grant, code } = await db.begin(async (tx) => {
        const created = await createOrReuseGrant(
          {
            clientId: request.clientId,
            identityId: user.id,
            scope: request.scope,
          },
          tx,
        );
        const minted = await mintToken(
          {
            grantId: created.id,
            kind: "code",
            resource: request.resource,
            ttlSeconds: MCP_CODE_TTL_SECONDS,
            codeChallenge: request.codeChallenge,
            redirectUri: request.redirectUri,
          },
          tx,
        );
        await deleteAuthRequest(request.id, tx);
        return { grant: created, code: minted };
      });

      clearAuthCookie(req);
      await recordAudit({
        action: "mcp_grant.approved",
        actorId: user.id,
        subjectType: "mcp_grant",
        subjectId: grant.id,
        detail: { clientId: request.clientId, clientName: client.clientName },
      });

      return backToClient(request.redirectUri, {
        code,
        state: request.state,
      });
    } catch (error) {
      log.error(
        "mcp",
        `Consent approval failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return errorPage(
        "The connection couldn't be completed",
        "Return to the app and try again.",
        500,
      );
    }
  },

  /** The handoff return path: render consent from the pending cookie. */
  async continue(req: BunRequest): Promise<Response> {
    const limited = rateLimit(req, "mcp-authorize", 30, 60_000);
    if (limited) return limited;

    const requestId = req.cookies.get(MCP_AUTH_COOKIE);
    if (!requestId) {
      // A normal CMS sign-in, not an OAuth flow.
      return redirect("/cms");
    }

    const request = await getAuthRequest(requestId);
    if (!request) {
      clearAuthCookie(req);
      return errorPage(
        "This connection request expired",
        "Return to the app and start the connection again.",
        410,
      );
    }

    const ctx = await getSessionContext(req);
    if (!ctx.isAuthenticated || !ctx.user || !ctx.sessionId) {
      setAuthCookie(req, request.id);
      return redirect("/sign-in");
    }

    return renderConsent(request, ctx.sessionId, ctx.user.email);
  },
};
