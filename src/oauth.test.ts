import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createContext, MCP_SCOPE, parseScope } from "./config";
import { isAllowedRedirectUri, getClientById, registerClient, splitClientName } from "./oauth/clients";
import {
  createOrReuseGrant,
  exchangeAuthorizationCode,
  mintToken,
  rotateRefreshToken,
  verifyAccessToken,
  verifyPkce,
} from "./oauth/tokens";
import { connect, EDITOR, resetDatabase } from "./test-helpers";

const sql = connect();
const ctx = createContext({
  sql,
  appUrl: "https://app.example.com",
  log: { warn() {}, error() {} },
  server: { name: "t", version: "1" },
  getUser: () => null,
  findUser: (id: string) => (id === EDITOR.id ? EDITOR : null),
  signInUrl: "/sign-in",
  registerTools() {},
});

const challengeFor = (verifier: string): string =>
  createHash("sha256").update(verifier).digest("base64url");

beforeAll(async () => {
  await resetDatabase(sql);
});

afterAll(async () => {
  await sql.close();
});

describe("the redirect allowlist", () => {
  test("accepts the two hosted callbacks", () => {
    expect(isAllowedRedirectUri("https://claude.ai/api/mcp/auth_callback")).toBe(true);
    expect(isAllowedRedirectUri("https://chatgpt.com/connector_platform_oauth_redirect")).toBe(true);
    expect(isAllowedRedirectUri("https://chatgpt.com/connector/oauth/abc123")).toBe(true);
  });

  test("accepts a loopback redirect on any port", () => {
    expect(isAllowedRedirectUri("http://localhost:3118/callback")).toBe(true);
    expect(isAllowedRedirectUri("http://127.0.0.1:8976/callback")).toBe(true);
    expect(isAllowedRedirectUri("http://[::1]:4321/callback")).toBe(true);
  });

  test("refuses anything that is not an allowlisted client", () => {
    for (const value of [
      "https://evil.example/callback",
      "https://claude.ai.evil.example/api/mcp/auth_callback",
      "http://claude.ai/api/mcp/auth_callback",
      "https://claude.ai/api/mcp/other",
      "https://claude.ai/api/mcp/auth_callback?x=1",
      "https://claude.ai/api/mcp/auth_callback#frag",
      "https://chatgpt.com/elsewhere",
      "http://localhost.evil.example/callback",
      "javascript:alert(1)",
      "not a url",
    ]) {
      expect(isAllowedRedirectUri(value)).toBe(false);
    }
  });
});

describe("client display names", () => {
  test("splits a trailing connection label from the app name", () => {
    expect(splitClientName("Claude Code (billet-oauth)")).toEqual({
      appName: "Claude Code",
      connectionLabel: "billet-oauth",
    });
    expect(splitClientName("Claude Code")).toEqual({
      appName: "Claude Code",
      connectionLabel: null,
    });
    expect(splitClientName("App (a) (b)")).toEqual({
      appName: "App (a)",
      connectionLabel: "b",
    });
    expect(splitClientName("App ()")).toEqual({
      appName: "App ()",
      connectionLabel: null,
    });
  });
});

describe("PKCE", () => {
  const verifier = "a".repeat(64);

  test("accepts the S256 challenge for a verifier", () => {
    expect(verifyPkce(verifier, challengeFor(verifier))).toBe(true);
  });

  test("refuses another verifier and a malformed one", () => {
    expect(verifyPkce("b".repeat(64), challengeFor(verifier))).toBe(false);
    expect(verifyPkce("too-short", challengeFor(verifier))).toBe(false);
  });
});

describe("scopes", () => {
  test("defaults to the one scope and refuses anything else", () => {
    expect(parseScope(null)).toBe(MCP_SCOPE);
    expect(parseScope("")).toBe(MCP_SCOPE);
    expect(parseScope("content")).toBe(MCP_SCOPE);
    expect(parseScope("content content")).toBe(MCP_SCOPE);
    expect(parseScope("openid")).toBeNull();
    expect(parseScope("content openid")).toBeNull();
  });
});

describe("dynamic client registration", () => {
  const claude = ["https://claude.ai/api/mcp/auth_callback"];

  test("stores a public client and reads it back", async () => {
    const result = await registerClient(ctx, {
      client_name: "Claude",
      redirect_uris: claude,
      token_endpoint_auth_method: "none",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.clientId).toStartWith("bmcp_client_");
    const stored = await getClientById(ctx, result.client.clientId);
    expect(stored?.clientName).toBe("Claude");
    expect(stored?.redirectUris).toEqual(claude);
  });

  test("refuses a redirect on a host we do not trust", async () => {
    const result = await registerClient(ctx, {
      client_name: "Phish",
      redirect_uris: ["https://evil.example/callback"],
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_redirect_uri");
  });

  test("refuses a confidential client", async () => {
    const result = await registerClient(ctx, {
      client_name: "Old client",
      redirect_uris: claude,
      token_endpoint_auth_method: "client_secret_basic",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_client_metadata");
  });

  test("cleans control characters out of the display name", async () => {
    const result = await registerClient(ctx, {
      client_name: "Claude\nDesktop\u0007",
      redirect_uris: claude,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.clientName).toBe("Claude Desktop");
  });
});

describe("tokens", () => {
  const REDIRECT = "http://localhost:9999/callback";
  const VERIFIER = "a".repeat(64);
  const CHALLENGE = challengeFor(VERIFIER);
  let clientId: string;

  beforeEach(async () => {
    await sql`DELETE FROM mcp_clients`;
    const client = await registerClient(ctx, {
      client_name: "Test client",
      redirect_uris: [REDIRECT],
    });
    if (!client.ok) throw new Error(client.description);
    clientId = client.client.clientId;
  });

  const grant = () =>
    createOrReuseGrant(ctx, { clientId, identityId: EDITOR.id, scope: "content" });

  const mintCode = (grantId: string, resource = ctx.resource) =>
    mintToken(ctx, {
      grantId,
      kind: "code",
      resource,
      ttlSeconds: 60,
      codeChallenge: CHALLENGE,
      redirectUri: REDIRECT,
    });

  const redeem = (code: string, codeVerifier = VERIFIER) =>
    exchangeAuthorizationCode(ctx, { code, clientId, redirectUri: REDIRECT, codeVerifier });

  test("the token pair resolves the user, and only hashes are stored", async () => {
    const code = await mintCode((await grant()).id);
    const result = await redeem(code);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.tokens.accessToken).toStartWith("bmcp_at_");
    expect(result.tokens.refreshToken).toStartWith("bmcp_rt_");

    const context = await verifyAccessToken(ctx, result.tokens.accessToken);
    expect(context?.actor.email).toBe(EDITOR.email);
    expect(context?.grant.clientId).toBe(clientId);

    const stored = await sql`SELECT token_hash FROM mcp_tokens`;
    for (const row of stored) {
      expect(row.token_hash).not.toContain("bmcp_");
      expect(row.token_hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test("lifetimes match billet-cms", async () => {
    const created = await grant();
    await mintCode(created.id);
    const result = await redeem(await mintCode(created.id));
    if (!result.ok) throw new Error("exchange failed");
    const seconds = async (kind: string) =>
      (await sql`
        SELECT EXTRACT(EPOCH FROM expires_at - created_at)::int AS s
        FROM mcp_tokens WHERE kind = ${kind} ORDER BY created_at DESC LIMIT 1`)[0].s;
    expect(await seconds("code")).toBe(60);
    expect(await seconds("access")).toBe(3600);
    expect(await seconds("refresh")).toBe(30 * 24 * 3600);
    expect(result.tokens.expiresIn).toBe(3600);
  });

  test("refuses a code minted for another resource", async () => {
    const code = await mintCode((await grant()).id, "https://elsewhere.example/mcp");
    const result = await redeem(code);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_target");
  });

  test("a mismatched resource parameter is refused", async () => {
    const code = await mintCode((await grant()).id);
    const result = await exchangeAuthorizationCode(ctx, {
      code,
      clientId,
      redirectUri: REDIRECT,
      codeVerifier: VERIFIER,
      resource: "https://elsewhere.example/mcp",
    });
    expect(result.ok).toBe(false);
  });

  test("two simultaneous exchanges cannot both spend a code", async () => {
    const code = await mintCode((await grant()).id);
    const results = await Promise.all([redeem(code), redeem(code)]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
  });

  test("rotates a refresh token, then revokes the grant on reuse", async () => {
    const first = await redeem(await mintCode((await grant()).id));
    if (!first.ok) throw new Error("exchange failed");

    const rotated = await rotateRefreshToken(ctx, {
      refreshToken: first.tokens.refreshToken,
      clientId,
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;

    const reused = await rotateRefreshToken(ctx, {
      refreshToken: first.tokens.refreshToken,
      clientId,
    });
    expect(reused.ok).toBe(false);
    expect(await verifyAccessToken(ctx, rotated.tokens.accessToken)).toBeNull();
  });

  test("an expired refresh token is refused", async () => {
    const first = await redeem(await mintCode((await grant()).id));
    if (!first.ok) throw new Error("exchange failed");
    await sql`UPDATE mcp_tokens SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE kind = 'refresh'`;
    const result = await rotateRefreshToken(ctx, {
      refreshToken: first.tokens.refreshToken,
      clientId,
    });
    expect(result.ok).toBe(false);
  });
});
