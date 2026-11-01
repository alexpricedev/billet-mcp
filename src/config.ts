/**
 * The OAuth surface's fixed values, and the per-app context built from the
 * options the app supplies.
 *
 * The app is both the resource server (`/mcp`) and the authorization server.
 * The issuer and resource identifiers are derived from `appUrl`, so a
 * deployment cannot advertise one URL and answer on another.
 *
 * There is one scope. The consent screen is where authority is made explicit,
 * not a scope list.
 */
import type { McpOptions } from "./types";

/** The one scope an access token can carry. */
export const MCP_SCOPE = "content";

/** The cookie holding a pending authorize request across the app's sign-in. */
export const MCP_AUTH_COOKIE = "mcp_auth";

/** The cookie binding the consent form to the browser that rendered it. */
export const MCP_CSRF_COOKIE = "mcp_consent_csrf";

/** How long each credential lives. */
export const MCP_CODE_TTL_SECONDS = 60;
export const MCP_ACCESS_TTL_SECONDS = 60 * 60;
export const MCP_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MCP_AUTH_REQUEST_TTL_SECONDS = 10 * 60;

/** The cookie's lifetime: the same ten minutes as the request row. */
export const MCP_AUTH_COOKIE_MAX_AGE = MCP_AUTH_REQUEST_TTL_SECONDS;

/** Where the app sends the browser back to once it has signed in. */
export const MCP_CONTINUE_PATH = "/mcp/authorize/continue";

export const TOOL_CALLS_PER_MINUTE = 120;

export interface McpContext {
  options: McpOptions;
  sql: McpOptions["sql"];
  log: McpOptions["log"];
  /** The canonical issuer: the app origin, without a trailing slash. */
  issuer: string;
  /** The canonical resource identifier: the MCP endpoint itself. */
  resource: string;
  /** The RFC 9728 document the 401 challenge points at. */
  resourceMetadataUrl: string;
  secureCookies: boolean;
}

export const createContext = (options: McpOptions): McpContext => {
  const url = new URL(options.appUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("billet-mcp: appUrl must be an http(s) URL.");
  }
  // `.origin` drops a path, so a stray `/app` in configuration cannot make the
  // issuer disagree with the metadata URL a client fetches.
  const issuer = url.origin;
  return {
    options,
    sql: options.sql,
    log: options.log,
    issuer,
    resource: `${issuer}/mcp`,
    resourceMetadataUrl: `${issuer}/.well-known/oauth-protected-resource/mcp`,
    secureCookies: url.protocol === "https:",
  };
};

export const endpoint = (ctx: McpContext, path: string): string =>
  `${ctx.issuer}${path}`;

/**
 * The scope set a request asks for, or `null` when it asks for one this server
 * does not issue.
 *
 * An absent scope means the default. A space-delimited list is what OAuth
 * sends; only `content` is recognised, so anything else is refused rather than
 * silently narrowed.
 */
export const parseScope = (raw: string | null): string | null => {
  if (raw === null || raw.trim() === "") return MCP_SCOPE;
  const requested = raw
    .split(" ")
    .map((part) => part.trim())
    .filter((part) => part !== "");
  if (requested.length === 0) return MCP_SCOPE;
  return requested.every((scope) => scope === MCP_SCOPE) ? MCP_SCOPE : null;
};

export const parseCookies = (req: Request): Map<string, string> => {
  const cookies = new Map<string, string>();
  for (const part of (req.headers.get("cookie") ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    if (!cookies.has(name)) cookies.set(name, part.slice(index + 1).trim());
  }
  return cookies;
};

/**
 * A `Set-Cookie` value. `Path=/` for the pending-request cookie on purpose: the
 * app's post-sign-in step has to read it, and that path is not under `/mcp`.
 * It is HttpOnly, SameSite=Lax and short-lived, and carries only an opaque id.
 */
export const cookieHeader = (
  ctx: McpContext,
  name: string,
  value: string,
  options: { path: string; maxAge: number },
): string =>
  [
    `${name}=${value}`,
    `Path=${options.path}`,
    `Max-Age=${options.maxAge}`,
    "HttpOnly",
    "SameSite=Lax",
    ...(ctx.secureCookies ? ["Secure"] : []),
  ].join("; ");

export const clearCookieHeader = (
  ctx: McpContext,
  name: string,
  path: string,
): string => cookieHeader(ctx, name, "", { path, maxAge: 0 });
