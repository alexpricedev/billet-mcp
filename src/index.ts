/**
 * @alexpricedev/billet-mcp: a remote MCP endpoint with an OAuth 2.1 sign-in.
 *
 * `createMcp(options)` returns the route map to mount, plus the few functions
 * an app needs around it. See the README for the seams `options` takes.
 */
import { createContext, MCP_AUTH_COOKIE, parseCookies } from "./config";
import { getAuthRequest } from "./oauth/requests";
import {
  cleanupExpiredMcpCredentials,
  listGrants,
  revokeGrant,
} from "./oauth/tokens";
import { createRoutes } from "./routes";
import type { McpOptions, McpRoutes } from "./types";

export interface Mcp {
  /** Mount these on the app's router. */
  routes: McpRoutes;
  /**
   * True when the request carries a pending authorize request that has not
   * expired. Call it after
   * sign-in: if it is true, send the browser to `MCP_CONTINUE_PATH`.
   */
  hasPendingAuthorize(req: Request): Promise<boolean>;
  /** Revoke a grant; every token it issued stops verifying immediately. */
  revokeGrant(grantId: string, actorId: string | null): Promise<boolean>;
  /** Every consent, newest first, for a connected-apps page. */
  listGrants: () => ReturnType<typeof listGrants>;
  /** Delete credentials nothing can use any more. Run it now and then. */
  cleanupExpired(): Promise<void>;
}

export const createMcp = (options: McpOptions): Mcp => {
  const ctx = createContext(options);
  return {
    routes: createRoutes(ctx),
    hasPendingAuthorize: async (req) => {
      const id = parseCookies(req).get(MCP_AUTH_COOKIE);
      return id !== undefined && (await getAuthRequest(ctx, id)) !== null;
    },
    revokeGrant: (grantId, actorId) => revokeGrant(ctx, grantId, actorId),
    listGrants: () => listGrants(ctx),
    cleanupExpired: () => cleanupExpiredMcpCredentials(ctx),
  };
};

export { down, up } from "./migration";
export { MCP_CONTINUE_PATH, MCP_SCOPE } from "./config";
export type {
  ConsentPage,
  McpHandler,
  McpLogger,
  McpOptions,
  McpRoutes,
  McpUser,
  RateLimitRule,
} from "./types";
export type { McpGrantRecord, McpGrantSummary } from "./oauth/tokens";
