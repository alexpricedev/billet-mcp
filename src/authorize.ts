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
 * 2. Establish the person. A signed-out visit stores the request, sets an
 *    opaque cookie and sends the browser to the app's sign-in. The app sends it
 *    back to `/mcp/authorize/continue` when sign-in is done.
 * 3. Ask, then issue a code. The consent screen shows the client, the redirect
 *    host and the signed-in user. An approval creates (or reuses) the grant
 *    and mints a single-use, 60-second code bound to the client, redirect, PKCE
 *    challenge and resource. The token endpoint does the exchange.
 */
import { randomBytes } from "node:crypto";
import {
  clearCookieHeader,
  cookieHeader,
  MCP_AUTH_COOKIE,
  MCP_AUTH_COOKIE_MAX_AGE,
  MCP_CODE_TTL_SECONDS,
  MCP_CSRF_COOKIE,
  type McpContext,
  parseCookies,
  parseScope,
} from "./config";
import {
  CONSENT_PATH,
  consentPage,
  errorPage as errorPageContent,
  renderPage,
} from "./consent";
import {
  constantTimeEqual,
  limited,
  redirect,
  type RequestForm,
} from "./http";
import { getClientById, splitClientName } from "./oauth/clients";
import {
  createAuthRequest,
  deleteAuthRequest,
  getAuthRequest,
  type McpAuthRequest,
} from "./oauth/requests";
import { createOrReuseGrant, mintToken } from "./oauth/tokens";
import { recordAudit } from "./record-audit";
import type { ConsentPage, McpUser } from "./types";

const PAGE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Robots-Tag": "noindex",
  // The Allow button must not be clickjackable, whatever the app wraps.
  "X-Frame-Options": "DENY",
};

const RULE = { name: "mcp-authorize", limit: 30, windowMs: 60_000 };

// The app's `secureHeaders` wrapper supplies the CSP. Without one, the page
// still refuses to be framed: a CSP set here would stop the app's full policy
// being applied, so it is only added when there is no wrapper.
const page = (
  ctx: McpContext,
  content: ConsentPage,
  status = 200,
  cookies: string[] = [],
): Response => {
  const headers = new Headers(PAGE_HEADERS);
  if (!ctx.options.secureHeaders) {
    headers.set("Content-Security-Policy", "frame-ancestors 'none'");
  }
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(renderPage(ctx.options, content), { status, headers });
};

const errorPage = (
  ctx: McpContext,
  heading: string,
  message: string,
  status: number,
  cookies: string[] = [],
): Response =>
  page(
    ctx,
    errorPageContent(ctx.options.server.name, heading, message, ctx.issuer),
    status,
    cookies,
  );

const authCookie = (ctx: McpContext, requestId: string): string =>
  cookieHeader(ctx, MCP_AUTH_COOKIE, requestId, {
    path: "/",
    maxAge: MCP_AUTH_COOKIE_MAX_AGE,
  });

const clearAuthCookie = (ctx: McpContext): string =>
  clearCookieHeader(ctx, MCP_AUTH_COOKIE, "/");

const signInRedirect = (
  ctx: McpContext,
  req: Request,
  requestId: string,
): Response => {
  const target =
    typeof ctx.options.signInUrl === "function"
      ? ctx.options.signInUrl(req)
      : ctx.options.signInUrl;
  return redirect(target, [authCookie(ctx, requestId)]);
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
  ctx: McpContext,
  redirectUri: string,
  input: {
    code?: string;
    error?: string;
    description?: string;
    state: string | null;
  },
  cookies: string[] = [],
): Response => {
  const url = new URL(redirectUri);
  if (input.code) url.searchParams.set("code", input.code);
  if (input.error) url.searchParams.set("error", input.error);
  if (input.description) {
    url.searchParams.set("error_description", input.description);
  }
  if (input.state) url.searchParams.set("state", input.state);
  url.searchParams.set("iss", ctx.issuer);
  return redirect(url.href, cookies);
};

const renderConsent = async (
  ctx: McpContext,
  request: McpAuthRequest,
  user: McpUser,
): Promise<Response> => {
  const client = await getClientById(ctx, request.clientId);
  if (!client) {
    return errorPage(
      ctx,
      "This app is no longer registered",
      "Return to the app and start the connection again.",
      400,
    );
  }

  // Double-submit: the token is in the form and in an HttpOnly cookie, and the
  // POST must carry both. A cross-site form can do neither.
  const csrfToken = randomBytes(24).toString("base64url");
  const display = splitClientName(client.clientName);
  return page(
    ctx,
    consentPage({
      serverName: ctx.options.server.name,
      clientName: display.appName,
      connectionLabel: display.connectionLabel,
      redirectHost: new URL(request.redirectUri).host,
      identityEmail: user.email,
      requestId: request.id,
      csrfToken,
    }),
    200,
    [
      cookieHeader(ctx, MCP_CSRF_COOKIE, csrfToken, {
        path: CONSENT_PATH,
        maxAge: MCP_AUTH_COOKIE_MAX_AGE,
      }),
    ],
  );
};

/** The POST is same-origin and carries the token its cookie was set with. */
const csrfFailure = (
  ctx: McpContext,
  req: Request,
  form: RequestForm,
): Response | null => {
  const origin = req.headers.get("origin");
  const cookie = parseCookies(req).get(MCP_CSRF_COOKIE);
  const field = form.get("csrf");
  // Browsers send Origin on every POST, so its absence is refused too.
  const originOk = origin === ctx.issuer;
  const tokenOk =
    typeof field === "string" &&
    field !== "" &&
    cookie !== undefined &&
    constantTimeEqual(field, cookie);
  if (originOk && tokenOk) return null;
  return errorPage(
    ctx,
    "We couldn't verify this request",
    "Check that cookies are enabled, then return to the app and start the connection again.",
    403,
  );
};

export const createAuthorizeHandlers = (ctx: McpContext) => ({
  /** Validate, then either render consent or start sign-in. */
  async index(req: Request): Promise<Response> {
    const refused = await limited(ctx, req, RULE);
    if (refused) return refused;

    const query = new URL(req.url).searchParams;
    const clientId = query.get("client_id");
    const redirectUri = query.get("redirect_uri");
    const state = query.get("state");

    if (!clientId || !redirectUri) {
      return errorPage(
        ctx,
        "This connection request is incomplete",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const client = await getClientById(ctx, clientId);
    if (!client) {
      return errorPage(
        ctx,
        "This app isn't registered",
        "Return to the app and start the connection again.",
        400,
      );
    }
    if (!client.redirectUris.includes(redirectUri)) {
      return errorPage(
        ctx,
        "This app's return address isn't registered",
        "Return to the app and start the connection again.",
        400,
      );
    }

    if (query.get("response_type") !== "code") {
      return backToClient(ctx, redirectUri, {
        error: "unsupported_response_type",
        description: "Only the authorization code flow is supported.",
        state,
      });
    }

    const challenge = query.get("code_challenge");
    if (!challenge || query.get("code_challenge_method") !== "S256") {
      return backToClient(ctx, redirectUri, {
        error: "invalid_request",
        description: "PKCE with S256 is required.",
        state,
      });
    }

    // RFC 8707: the client names the resource it wants a token for. Missing is
    // tolerated (both clients send it) by treating it as this endpoint; a
    // different value is refused rather than silently narrowed.
    const resource = query.get("resource") ?? ctx.resource;
    if (resource !== ctx.resource) {
      return backToClient(ctx, redirectUri, {
        error: "invalid_target",
        description: "This server cannot issue a token for that resource.",
        state,
      });
    }

    const scope = parseScope(query.get("scope"));
    if (!scope) {
      return backToClient(ctx, redirectUri, {
        error: "invalid_scope",
        description: "Only the content scope is supported.",
        state,
      });
    }

    const request = await createAuthRequest(ctx, {
      clientId: client.clientId,
      redirectUri,
      state,
      codeChallenge: challenge,
      resource,
      scope,
    });

    const user = await ctx.options.getUser(req);
    if (!user) return signInRedirect(ctx, req, request.id);

    return renderConsent(ctx, request, user);
  },

  /** Approve or deny the visible consent form. */
  async create(req: Request): Promise<Response> {
    const refused = await limited(ctx, req, RULE);
    if (refused) return refused;

    let form: RequestForm;
    try {
      form = await req.formData();
    } catch {
      return errorPage(
        ctx,
        "This connection request is incomplete",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const failure = csrfFailure(ctx, req, form);
    if (failure) return failure;

    const requestId = form.get("request");
    const decision = form.get("decision");

    if (typeof requestId !== "string" || requestId === "") {
      return errorPage(
        ctx,
        "This connection request is incomplete",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const request = await getAuthRequest(ctx, requestId);
    if (!request) {
      return errorPage(
        ctx,
        "This connection request expired",
        "Return to the app and start the connection again.",
        410,
        [clearAuthCookie(ctx)],
      );
    }

    const user = await ctx.options.getUser(req);
    if (!user) return signInRedirect(ctx, req, request.id);

    if (decision === "deny") {
      await deleteAuthRequest(ctx, request.id);
      return backToClient(
        ctx,
        request.redirectUri,
        {
          error: "access_denied",
          description: "The connection was denied.",
          state: request.state,
        },
        [clearAuthCookie(ctx)],
      );
    }

    if (decision !== "approve") {
      return errorPage(
        ctx,
        "That choice wasn't recognised",
        "Return to the app and start the connection again.",
        400,
      );
    }

    const client = await getClientById(ctx, request.clientId);
    if (!client) {
      return errorPage(
        ctx,
        "This app is no longer registered",
        "Return to the app and start the connection again.",
        400,
        [clearAuthCookie(ctx)],
      );
    }

    try {
      // One transaction: the grant, the code and the deletion of the pending
      // request either all happen or none do. A code that outlived its request
      // row, or a grant left behind by a failed mint, would be state nobody
      // can explain later.
      const { grant, code } = await ctx.sql.begin(async (tx) => {
        const created = await createOrReuseGrant(
          ctx,
          {
            clientId: request.clientId,
            identityId: user.id,
            scope: request.scope,
          },
          tx,
        );
        const minted = await mintToken(
          ctx,
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
        await deleteAuthRequest(ctx, request.id, tx);
        return { grant: created, code: minted };
      });

      await recordAudit(ctx, {
        action: "mcp_grant.approved",
        actorId: user.id,
        subjectType: "mcp_grant",
        subjectId: grant.id,
        detail: { clientId: request.clientId, clientName: client.clientName },
      });

      return backToClient(
        ctx,
        request.redirectUri,
        { code, state: request.state },
        [clearAuthCookie(ctx)],
      );
    } catch (error) {
      ctx.log.error(
        "mcp",
        `Consent approval failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return errorPage(
        ctx,
        "The connection couldn't be completed",
        "Return to the app and try again.",
        500,
      );
    }
  },

  /** The sign-in return path: render consent from the pending cookie. */
  async continue(req: Request): Promise<Response> {
    const refused = await limited(ctx, req, RULE);
    if (refused) return refused;

    const requestId = parseCookies(req).get(MCP_AUTH_COOKIE);
    if (!requestId) {
      // A normal sign-in, not an OAuth flow.
      return redirect("/");
    }

    const request = await getAuthRequest(ctx, requestId);
    if (!request) {
      return errorPage(
        ctx,
        "This connection request expired",
        "Return to the app and start the connection again.",
        410,
        [clearAuthCookie(ctx)],
      );
    }

    const user = await ctx.options.getUser(req);
    if (!user) return signInRedirect(ctx, req, request.id);

    return renderConsent(ctx, request, user);
  },
});
