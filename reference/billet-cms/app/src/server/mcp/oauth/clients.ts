/**
 * OAuth client registration, and the redirect-URI allowlist that makes open
 * dynamic registration safe.
 *
 * The endpoint is public by design: a hosted client registers itself and then
 * sends the person through the consent screen. The risk in open DCR is a client
 * registering a redirect to a host it controls and using our consent screen to
 * phish an authorization code, so registration accepts only the redirect URIs
 * of the clients this CMS is built for — Claude, ChatGPT, and a loopback client
 * for local testing. A new client means one deliberate line here, not a new
 * security posture.
 */
import { randomBytes } from "node:crypto";
import type { SQL } from "bun";
import { db } from "../../services/database";
import { jsonbValue, textArrayLiteral } from "../../utils/sql";

/** The clients' documented callbacks. Keep these exact. */
const CLAUDE_CALLBACK_PATH = "/api/mcp/auth_callback";
const CHATGPT_STABLE_PATH = "/connector_platform_oauth_redirect";
const CHATGPT_CALLBACK_PATH = /^\/connector\/oauth\/[A-Za-z0-9_-]+$/;

const MAX_REDIRECT_URIS = 10;
const MAX_CLIENT_NAME_LENGTH = 200;

/**
 * True when a redirect URI is one this CMS will send an authorization code to.
 *
 * https is required except for a loopback redirect, which RFC 8252 allows over
 * http on an ephemeral port. Query strings and fragments are refused: neither
 * registered client uses one, and accepting them turns exact-match validation
 * into an exercise in normalisation.
 */
export const isAllowedRedirectUri = (value: string): boolean => {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }

  if (url.username || url.password || url.search || url.hash) return false;

  const host = url.hostname.toLowerCase();

  if (url.protocol === "https:") {
    if (url.port !== "" && url.port !== "443") return false;
    if (host === "claude.ai") return url.pathname === CLAUDE_CALLBACK_PATH;
    if (host === "chatgpt.com") {
      return (
        url.pathname === CHATGPT_STABLE_PATH ||
        CHATGPT_CALLBACK_PATH.test(url.pathname)
      );
    }
    return false;
  }

  if (url.protocol === "http:") {
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  }

  return false;
};

export interface McpClientRecord {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  createdAt: Date;
}

interface ClientRow {
  client_id: string;
  client_name: string | null;
  redirect_uris: string[];
  created_at: Date;
}

const toClient = (row: ClientRow): McpClientRecord => ({
  clientId: row.client_id,
  clientName: row.client_name ?? "Unnamed MCP client",
  redirectUris: row.redirect_uris,
  createdAt: row.created_at,
});

export type RegisterClientResult =
  | { ok: true; client: McpClientRecord }
  | {
      ok: false;
      error: "invalid_redirect_uri" | "invalid_client_metadata";
      description: string;
    };

const stringArray = (value: unknown): string[] | null => {
  if (!Array.isArray(value) || value.length === 0) return null;
  if (!value.every((item) => typeof item === "string" && item.trim() !== "")) {
    return null;
  }
  return value.map((item) => (item as string).trim());
};

/** Strip control characters and bound a client-supplied display name. */
const displayName = (value: unknown): string => {
  if (typeof value !== "string") return "Unnamed MCP client";
  const cleaned = value
    .replace(/\p{Cc}/gu, " ")
    .trim()
    .slice(0, MAX_CLIENT_NAME_LENGTH);
  return cleaned === "" ? "Unnamed MCP client" : cleaned;
};

export interface SplitClientName {
  /** The app's own name, with any trailing connection label removed. */
  appName: string;
  /** The label in parentheses, e.g. the MCP server name the person chose. */
  connectionLabel: string | null;
}

/**
 * Split a client's self-declared name into app and connection.
 *
 * Hosted clients register names like `Claude Code (northwind)`: the app, then
 * the connection the person named. The consent heading should say which app is
 * asking, with the connection on its own line, rather than putting the local
 * slug in the headline. Only a trailing parenthetical is treated as a label; a
 * name without one is returned whole.
 */
export const splitClientName = (clientName: string): SplitClientName => {
  const match = clientName.match(/^(.*?)\s*\(([^()]+)\)\s*$/);
  if (!match) return { appName: clientName.trim(), connectionLabel: null };

  const appName = match[1].trim();
  const connectionLabel = match[2].trim();
  if (appName === "" || connectionLabel === "") {
    return { appName: clientName.trim(), connectionLabel: null };
  }
  return { appName, connectionLabel };
};

/**
 * Validate and store one dynamic client registration.
 *
 * Only public clients are accepted: both hosted clients use PKCE and `none` at
 * the token endpoint, and a `client_secret` would be a credential the CMS has
 * no way to bind to a person.
 */
export const registerClient = async (
  input: Record<string, unknown>,
): Promise<RegisterClientResult> => {
  const redirectUris = stringArray(input.redirect_uris);
  if (
    redirectUris === null ||
    redirectUris.length > MAX_REDIRECT_URIS ||
    !redirectUris.every(isAllowedRedirectUri)
  ) {
    return {
      ok: false,
      error: "invalid_redirect_uri",
      description:
        "redirect_uris must contain one or more HTTPS Claude or ChatGPT callbacks, or a loopback http://localhost redirect.",
    };
  }

  const authMethod = input.token_endpoint_auth_method;
  if (authMethod !== undefined && authMethod !== "none") {
    return {
      ok: false,
      error: "invalid_client_metadata",
      description:
        "Only public clients are supported: token_endpoint_auth_method must be none.",
    };
  }

  const grantTypes = input.grant_types ?? [
    "authorization_code",
    "refresh_token",
  ];
  if (
    !Array.isArray(grantTypes) ||
    !grantTypes.includes("authorization_code") ||
    !grantTypes.every(
      (value) => value === "authorization_code" || value === "refresh_token",
    )
  ) {
    return {
      ok: false,
      error: "invalid_client_metadata",
      description:
        "grant_types must be authorization_code, optionally with refresh_token.",
    };
  }

  const responseTypes = input.response_types ?? ["code"];
  if (
    !Array.isArray(responseTypes) ||
    responseTypes.length !== 1 ||
    responseTypes[0] !== "code"
  ) {
    return {
      ok: false,
      error: "invalid_client_metadata",
      description: 'response_types must be ["code"].',
    };
  }

  const clientName = displayName(input.client_name);
  const clientId = `bcmcp_client_${randomBytes(18).toString("base64url")}`;
  const metadata = {
    client_name: clientName,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: "none",
    grant_types: grantTypes,
    response_types: ["code"],
  };

  const rows = (await db`
    INSERT INTO cms_mcp_clients (client_id, client_name, redirect_uris, metadata)
    VALUES (
      ${clientId},
      ${clientName},
      ${textArrayLiteral(redirectUris)}::text[],
      ${jsonbValue(metadata)}
    )
    RETURNING client_id, client_name, redirect_uris, created_at
  `) as ClientRow[];

  return { ok: true, client: toClient(rows[0]) };
};

export const getClientById = async (
  clientId: string,
  sql: SQL = db,
): Promise<McpClientRecord | null> => {
  const rows = (await sql`
    SELECT client_id, client_name, redirect_uris, created_at
    FROM cms_mcp_clients
    WHERE client_id = ${clientId}
  `) as ClientRow[];
  return rows.length > 0 ? toClient(rows[0]) : null;
};
