import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import {
  APP_URL,
  CLAUDE_REDIRECT,
  connect,
  EDITOR,
  readJson,
  type Harness,
  harness,
  pkcePair,
  resetDatabase,
} from "./test-helpers";

const sql = connect();
let h: Harness;

beforeAll(async () => {
  await resetDatabase(sql);
});

beforeEach(async () => {
  await sql`DELETE FROM mcp_clients`;
  await sql`DELETE FROM mcp_auth_requests`;
  await sql`DELETE FROM mcp_audit`;
  h = harness(sql);
});

afterAll(async () => {
  await sql.close();
});

const register = async (): Promise<string> => {
  const response = await h.call("/mcp/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Claude (test)",
      redirect_uris: [CLAUDE_REDIRECT],
    }),
  });
  expect(response.status).toBe(201);
  return (await readJson(response)).client_id;
};

const cookieJar = (response: Response): string =>
  response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(";")[0])
    .filter((cookie) => !cookie.endsWith("="))
    .join("; ");

const authorizeUrl = (clientId: string, challenge: string, extra = {}) => {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: CLAUDE_REDIRECT,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "xyz",
    resource: `${APP_URL}/mcp`,
    ...extra,
  });
  return `/mcp/authorize?${params}`;
};

/** Register, authorize, approve: returns what a client has after the redirect. */
const approve = async (challenge: string) => {
  const clientId = await register();
  const url = authorizeUrl(clientId, challenge);
  const consent = await h.mcp.routes["/mcp/authorize"](
    new Request(`${APP_URL}${url}`),
  );
  expect(consent.status).toBe(200);
  const html = await consent.text();
  const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
  const requestId = html.match(/name="request" value="([^"]+)"/)?.[1];
  expect(csrf).toBeTruthy();

  const decision = await h.mcp.routes["/mcp/authorize"](
    new Request(`${APP_URL}/mcp/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: cookieJar(consent),
        Origin: APP_URL,
      },
      body: new URLSearchParams({
        csrf: csrf as string,
        request: requestId as string,
        decision: "approve",
      }),
    }),
  );
  expect(decision.status).toBe(302);
  const location = new URL(decision.headers.get("location") as string);
  return { clientId, location };
};

const tokenRequest = (fields: Record<string, string>) =>
  h.call("/mcp/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });

const exchange = async (
  clientId: string,
  code: string,
  verifier: string,
) =>
  tokenRequest({
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: CLAUDE_REDIRECT,
    code_verifier: verifier,
  });

const redeem = async (
  clientId: string,
  location: URL,
  verifier: string,
) =>
  readJson(
    await exchange(clientId, location.searchParams.get("code") as string, verifier),
  );

const callTool = (accessToken: string, id = 1) =>
  h.call("/mcp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: "whoami", arguments: { id: "abc", content: "secret" } },
    }),
  });

describe("the OAuth flow end to end", () => {
  test("register, authorize with PKCE, exchange, call /mcp, refresh", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);

    expect(location.origin + location.pathname).toBe(CLAUDE_REDIRECT);
    expect(location.searchParams.get("state")).toBe("xyz");
    expect(location.searchParams.get("iss")).toBe(APP_URL);
    const code = location.searchParams.get("code") as string;
    expect(code).toStartWith("bmcp_code_");

    const issued = await exchange(clientId, code, verifier);
    expect(issued.status).toBe(200);
    expect(issued.headers.get("cache-control")).toBe("no-store");
    const tokens = await readJson(issued);
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.expires_in).toBe(3600);
    expect(tokens.scope).toBe("content");
    expect(tokens.access_token).toStartWith("bmcp_at_");

    const called = await callTool(tokens.access_token);
    expect(called.status).toBe(200);
    expect(await called.text()).toContain(EDITOR.email);

    // The audit row names the tool and the target, never the arguments.
    const audit = await sql`SELECT * FROM mcp_audit WHERE action = 'mcp.tool'`;
    expect(audit).toHaveLength(1);
    expect(audit[0].actor_id).toBe(EDITOR.id);
    expect(audit[0].detail.tool).toBe("whoami");
    expect(audit[0].detail.id).toBe("abc");
    expect(JSON.stringify(audit[0].detail)).not.toContain("secret");
    const approved = await sql`SELECT * FROM mcp_audit WHERE action = 'mcp_grant.approved'`;
    expect(approved).toHaveLength(1);

    const refreshed = await tokenRequest({
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token: tokens.refresh_token,
    });
    expect(refreshed.status).toBe(200);
    const next = await readJson(refreshed);
    expect(next.access_token).not.toBe(tokens.access_token);
    expect((await callTool(next.access_token)).status).toBe(200);

    // Presenting the spent refresh token revokes the whole grant.
    const reused = await tokenRequest({
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token: tokens.refresh_token,
    });
    expect(reused.status).toBe(400);
    expect((await readJson(reused)).error).toBe("invalid_grant");
    expect((await callTool(next.access_token)).status).toBe(401);
  });

  test("refuses a wrong verifier, and the code is then still usable", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const code = location.searchParams.get("code") as string;

    const wrong = await exchange(clientId, code, pkcePair().verifier);
    expect(wrong.status).toBe(400);
    expect((await readJson(wrong)).error).toBe("invalid_grant");

    expect((await exchange(clientId, code, verifier)).status).toBe(200);
  });

  test("refuses a reused code", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const code = location.searchParams.get("code") as string;

    expect((await exchange(clientId, code, verifier)).status).toBe(200);
    const again = await exchange(clientId, code, verifier);
    expect(again.status).toBe(400);
    expect((await readJson(again)).error).toBe("invalid_grant");
  });

  test("refuses an expired code", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    await sql`UPDATE mcp_tokens SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE kind = 'code'`;
    const response = await exchange(
      clientId,
      location.searchParams.get("code") as string,
      verifier,
    );
    expect(response.status).toBe(400);
  });

  test("refuses a code presented by another client or redirect", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const code = location.searchParams.get("code") as string;

    const other = await register();
    const wrongClient = await exchange(other, code, verifier);
    expect(wrongClient.status).toBe(401);
    expect((await readJson(wrongClient)).error).toBe("invalid_client");

    const wrongRedirect = await tokenRequest({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: "http://localhost:1/cb",
      code_verifier: verifier,
    });
    expect(wrongRedirect.status).toBe(400);
  });

  test("refuses an expired access token", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const tokens = await redeem(clientId, location, verifier);
    expect((await callTool(tokens.access_token)).status).toBe(200);

    await sql`UPDATE mcp_tokens SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE kind = 'access'`;
    const response = await callTool(tokens.access_token);
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain(
      'error="invalid_token"',
    );
  });

  test("refuses a token issued for another audience", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const tokens = await redeem(clientId, location, verifier);

    await sql`UPDATE mcp_tokens SET resource = 'https://elsewhere.example/mcp' WHERE kind = 'access'`;
    expect((await callTool(tokens.access_token)).status).toBe(401);
  });

  test("a token stops working once the app no longer has the user", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const tokens = await redeem(clientId, location, verifier);

    h.users.delete(EDITOR.id);
    expect((await callTool(tokens.access_token)).status).toBe(401);
  });

  test("revoking a grant ends its tokens", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const tokens = await redeem(clientId, location, verifier);

    const [grant] = await h.mcp.listGrants();
    expect(grant.identityId).toBe(EDITOR.id);
    expect(await h.mcp.revokeGrant(grant.id, EDITOR.id)).toBe(true);
    expect((await callTool(tokens.access_token)).status).toBe(401);
    const revoked = await sql`SELECT * FROM mcp_audit WHERE action = 'mcp_grant.revoked'`;
    expect(revoked).toHaveLength(1);
  });
});

describe("the bearer gate", () => {
  test("a 401 carries the resource_metadata pointer", async () => {
    const response = await h.call("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(401);
    const challenge = response.headers.get("www-authenticate") as string;
    expect(challenge).toContain(
      `resource_metadata="${APP_URL}/.well-known/oauth-protected-resource/mcp"`,
    );
    expect(challenge).not.toContain("invalid_token");
  });

  test("a garbage token is an invalid_token 401", async () => {
    const response = await h.call("/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer nonsense" },
      body: "{}",
    });
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain(
      'error="invalid_token"',
    );
  });

  test("a JSON-RPC batch is refused", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const tokens = await redeem(clientId, location, verifier);

    const response = await h.call("/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify([
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { jsonrpc: "2.0", id: 2, method: "tools/list" },
      ]),
    });
    expect(response.status).toBe(400);
    expect((await readJson(response)).error.code).toBe(-32600);
  });

  test("the rate-limit hook can refuse a tool call", async () => {
    const limiter = harness(sql, {
      rateLimit: (_req, rule) =>
        rule.name === "mcp-tool"
          ? new Response("", { status: 429, headers: { "Retry-After": "7" } })
          : null,
    });
    h = limiter;
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const tokens = await redeem(clientId, location, verifier);

    const response = await callTool(tokens.access_token, 5);
    expect(response.status).toBe(429);
    const body = await readJson(response);
    expect(body.id).toBe(5);
    expect(body.error.message).toContain("7s");
  });

  test("tools/list shows the app's tools and server info", async () => {
    const { verifier, challenge } = pkcePair();
    const { clientId, location } = await approve(challenge);
    const tokens = await redeem(clientId, location, verifier);

    const response = await h.call("/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("whoami");
  });
});

describe("the token endpoint", () => {
  test("refuses a JSON body and an unknown grant type", async () => {
    const json = await h.call("/mcp/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(json.status).toBe(400);

    const unknown = await tokenRequest({
      grant_type: "password",
      client_id: "x",
    });
    expect(unknown.status).toBe(400);
    expect((await readJson(unknown)).error).toBe("unsupported_grant_type");
  });

  test("answers 405 to a GET", async () => {
    expect((await h.call("/mcp/token")).status).toBe(405);
  });
});

describe("registration", () => {
  test("refuses a redirect to a host the server does not trust", async () => {
    const response = await h.call("/mcp/register", {
      method: "POST",
      body: JSON.stringify({ redirect_uris: ["https://evil.example/cb"] }),
    });
    expect(response.status).toBe(400);
    expect((await readJson(response)).error).toBe("invalid_redirect_uri");
  });
});
