import type { SQL } from "bun";
import type { McpServer } from "@modelcontextprotocol/server";

/** The person a request acts as. `id` must be stable: grants are keyed on it. */
export interface McpUser {
  id: string;
  email: string;
}

export interface McpLogger {
  info?(scope: string, message: string): void;
  warn(scope: string, message: string): void;
  error(scope: string, message: string): void;
}

/** A request handler, as Bun's `routes` object takes it. */
export type McpHandler = (req: Request) => Response | Promise<Response>;

export type McpRoutes = Record<string, McpHandler>;

export interface RateLimitRule {
  /** The bucket's name, e.g. `mcp-register`. */
  name: string;
  limit: number;
  windowMs: number;
  /**
   * Set when the budget belongs to something other than the caller's address
   * (the tool-call budget is per grant). Absent means key it by client IP.
   */
  key?: string;
}

export interface ConsentPage {
  title: string;
  heading: string;
  subtitle: string;
  /** Trusted, already-escaped HTML for the page body. */
  bodyHtml: string;
  /** Trusted, already-escaped HTML for the footer, or null. */
  footerHtml: string | null;
}

export interface McpOptions {
  /** The app's Postgres connection. The `mcp_` tables must already exist. */
  sql: SQL;
  /** The app's public URL. Only its origin is used, as issuer and resource base. */
  appUrl: string;
  log: McpLogger;
  server: {
    name: string;
    version: string;
    instructions?: string;
  };
  /** The signed-in user for a browser request, or null when signed out. */
  getUser(req: Request): Promise<McpUser | null> | McpUser | null;
  /**
   * The user behind a stored grant, or null if the app no longer has them. It
   * runs on every `/mcp` request, so removing a person ends their tokens.
   */
  findUser(id: string): Promise<McpUser | null> | McpUser | null;
  /**
   * Where a signed-out browser goes to sign in. After sign-in the app must send
   * the browser to `/mcp/authorize/continue` (see `hasPendingAuthorize`).
   */
  signInUrl: string | ((req: Request) => string);
  /** Register the app's tools on the per-request server, acting as `user`. */
  registerTools(server: McpServer, user: McpUser): void | Promise<void>;
  /** Return a Response (usually a 429) to refuse the request, or null to allow it. */
  rateLimit?(
    req: Request,
    rule: RateLimitRule,
  ): Response | null | Promise<Response | null>;
  /** Wraps the HTML consent routes, for the app's security headers. */
  secureHeaders?(
    req: Request,
    handler: McpHandler,
  ): Response | Promise<Response>;
  /** Replaces the package's plain page chrome. */
  renderPage?(page: ConsentPage): string;
  /** Tool argument names kept in the audit row. Content is never recorded. */
  auditTargetKeys?: readonly string[];
}
