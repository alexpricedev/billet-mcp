/**
 * The OAuth surface's fixed values.
 *
 * The CMS is both the resource server (`/mcp`) and the authorization server,
 * because a per-site CMS has one origin and one small credential surface. The
 * issuer and resource identifiers are derived from `APP_URL` so a deployment
 * cannot advertise one URL and answer on another.
 *
 * There is one scope. Publishing and deleting are part of it, because the
 * people who connect an AI editor are the people who want those actions; the
 * consent screen is where that is made explicit, not a scope list.
 */

/** The one scope an access token can carry. */
export const MCP_SCOPE = "content";

/** The cookie holding a pending authorize request across site sign-in. */
export const MCP_AUTH_COOKIE = "cms_mcp_auth";

/** How long each credential lives. */
export const MCP_CODE_TTL_SECONDS = 60;
export const MCP_ACCESS_TTL_SECONDS = 60 * 60;
export const MCP_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MCP_AUTH_REQUEST_TTL_SECONDS = 10 * 60;

/** The cookie's lifetime: the same ten minutes as the request row. */
export const MCP_AUTH_COOKIE_MAX_AGE = MCP_AUTH_REQUEST_TTL_SECONDS;

/**
 * Where the pending authorize request id lives.
 *
 * `Path=/` rather than `/mcp` on purpose: `/handoff` has to read it after the
 * site sends the browser back, and that path is not under `/mcp`. The cookie is
 * HttpOnly, SameSite=Lax and short-lived, and carries only an opaque row id.
 */
export const mcpAuthCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
  maxAge: MCP_AUTH_COOKIE_MAX_AGE,
});

/**
 * The canonical issuer: the CMS origin, without a trailing slash.
 *
 * `APP_URL` is validated at boot as an http(s) URL. `.origin` drops a path, so
 * a stray `/cms` in configuration cannot make the issuer disagree with the
 * metadata URL a client fetches.
 */
export const mcpIssuer = (): string =>
  new URL(process.env.APP_URL as string).origin;

/** The canonical resource identifier: the MCP endpoint itself. */
export const mcpResource = (): string => `${mcpIssuer()}/mcp`;

export const mcpEndpoint = (path: string): string => `${mcpIssuer()}${path}`;

/** The RFC 9728 document the 401 challenge points at. */
export const mcpResourceMetadataUrl = (): string =>
  `${mcpIssuer()}/.well-known/oauth-protected-resource/mcp`;

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
