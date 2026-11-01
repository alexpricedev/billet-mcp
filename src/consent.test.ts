import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import {
  APP_URL,
  CLAUDE_REDIRECT,
  connect,
  type Harness,
  harness,
  pkcePair,
  readJson,
  resetDatabase,
} from "./test-helpers";

const sql = connect();
let h: Harness;
let clientId: string;

beforeAll(async () => {
  await resetDatabase(sql);
});

beforeEach(async () => {
  await sql`DELETE FROM mcp_clients`;
  await sql`DELETE FROM mcp_auth_requests`;
  h = harness(sql);
  const response = await h.call("/mcp/register", {
    method: "POST",
    body: JSON.stringify({
      client_name: "Claude <b>Code</b> (my-app)",
      redirect_uris: [CLAUDE_REDIRECT, "http://localhost:3118/callback"],
    }),
  });
  clientId = (await readJson(response)).client_id;
});

afterAll(async () => {
  await sql.close();
});

const authorize = (overrides: Record<string, string> = {}, redirect = CLAUDE_REDIRECT) => {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirect,
    code_challenge: pkcePair().challenge,
    code_challenge_method: "S256",
    state: "s1",
    ...overrides,
  });
  return h.call(`/mcp/authorize?${params}`);
};

describe("the consent screen", () => {
  test("renders for a signed-in user, escaped, with a CSRF cookie", async () => {
    const response = await authorize();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("content-security-policy")).toBe(
      "frame-ancestors 'none'",
    );
    const html = await response.text();

    expect(html).toContain("Connect Claude &lt;b&gt;Code&lt;/b&gt;?");
    expect(html).not.toContain("<b>Code</b>");
    expect(html).toContain("Connection: <strong>my-app</strong>");
    expect(html).toContain("editor@example.com");
    expect(html).toContain("<strong>claude.ai</strong>");
    expect(html).toContain("Allow access");
    expect(html).toContain("Deny");
    expect(html).toContain("Test app");

    const cookie = response.headers.getSetCookie().join("\n");
    expect(cookie).toContain("mcp_consent_csrf=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
  });

  test("warns when the app returns to a program on this computer", async () => {
    const html = await (
      await authorize({}, "http://localhost:3118/callback")
    ).text();
    expect(html).toContain("program on this computer");
  });

  test("redirects a signed-out browser to sign in, holding the request in a cookie", async () => {
    h.session.userId = null;
    const response = await authorize();
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/sign-in");

    const cookie = response.headers.getSetCookie().join("\n");
    expect(cookie).toMatch(/^mcp_auth=[0-9a-f-]{36}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure/);

    const [row] = await sql`SELECT * FROM mcp_auth_requests`;
    expect(row.client_id).toBe(clientId);
    expect(row.scope).toBe("content");

    // After sign-in the app notices the cookie and returns to /continue.
    const returning = new Request(`${APP_URL}/mcp/authorize/continue`, {
      headers: { Cookie: `mcp_auth=${row.id}` },
    });
    expect(await h.mcp.hasPendingAuthorize(returning)).toBe(true);
    expect(await h.mcp.hasPendingAuthorize(new Request(APP_URL))).toBe(false);

    // Once the request has expired the cookie no longer counts.
    await sql`UPDATE mcp_auth_requests SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'`;
    expect(await h.mcp.hasPendingAuthorize(returning)).toBe(false);
    await sql`UPDATE mcp_auth_requests SET expires_at = CURRENT_TIMESTAMP + INTERVAL '5 minutes'`;

    h.session.userId = "user-1";
    const consent = await h.mcp.routes["/mcp/authorize/continue"](returning);
    expect(consent.status).toBe(200);
    expect(await consent.text()).toContain("Allow access");
  });

  test("signInUrl can be a function of the request", async () => {
    h = harness(sql, { signInUrl: () => "/login?next=/mcp/authorize/continue" });
    h.session.userId = null;
    const response = await authorize();
    expect(response.headers.get("location")).toBe(
      "/login?next=/mcp/authorize/continue",
    );
  });

  test("continue without the cookie is not an OAuth flow", async () => {
    const response = await h.call("/mcp/authorize/continue");
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/");
  });

  test("continue with an expired request says so", async () => {
    const [row] = await sql`
      INSERT INTO mcp_auth_requests (client_id, redirect_uri, code_challenge, resource, expires_at)
      VALUES (${clientId}, ${CLAUDE_REDIRECT}, 'c', ${`${APP_URL}/mcp`}, CURRENT_TIMESTAMP - INTERVAL '1 second')
      RETURNING id`;
    const response = await h.call("/mcp/authorize/continue", {
      headers: { Cookie: `mcp_auth=${row.id}` },
    });
    expect(response.status).toBe(410);
  });
});

describe("authorize validation", () => {
  test("an unknown client or unregistered redirect gets a page, not a redirect", async () => {
    const unknown = await authorize({ client_id: "nope" });
    expect(unknown.status).toBe(400);
    expect(unknown.headers.get("location")).toBeNull();

    const other = await authorize({}, "https://claude.ai/api/mcp/other");
    expect(other.status).toBe(400);
    expect(other.headers.get("location")).toBeNull();

    const missing = await h.call("/mcp/authorize");
    expect(missing.status).toBe(400);
  });

  test("later failures go back to the client with state and iss", async () => {
    const cases: [Record<string, string>, string][] = [
      [{ response_type: "token" }, "unsupported_response_type"],
      [{ code_challenge_method: "plain" }, "invalid_request"],
      [{ resource: "https://elsewhere.example/mcp" }, "invalid_target"],
      [{ scope: "openid" }, "invalid_scope"],
    ];
    for (const [overrides, error] of cases) {
      const response = await authorize(overrides);
      expect(response.status).toBe(302);
      const location = new URL(response.headers.get("location") as string);
      expect(location.searchParams.get("error")).toBe(error);
      expect(location.searchParams.get("state")).toBe("s1");
      expect(location.searchParams.get("iss")).toBe(APP_URL);
    }
  });
});

describe("the consent decision", () => {
  const decide = async (fields: Record<string, string>, headers: Record<string, string> = {}) =>
    h.call("/mcp/authorize", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: APP_URL,
        ...headers,
      },
      body: new URLSearchParams(fields),
    });

  const prepare = async () => {
    const consent = await authorize();
    const html = await consent.text();
    return {
      csrf: html.match(/name="csrf" value="([^"]+)"/)?.[1] as string,
      request: html.match(/name="request" value="([^"]+)"/)?.[1] as string,
      cookie: `mcp_consent_csrf=${html.match(/name="csrf" value="([^"]+)"/)?.[1]}`,
    };
  };

  test("a POST without the matching CSRF cookie is refused", async () => {
    const { csrf, request } = await prepare();
    const noCookie = await decide({ csrf, request, decision: "approve" });
    expect(noCookie.status).toBe(403);

    const wrong = await decide(
      { csrf, request, decision: "approve" },
      { Cookie: "mcp_consent_csrf=other" },
    );
    expect(wrong.status).toBe(403);

    const noOrigin = await h.call("/mcp/authorize", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: `mcp_consent_csrf=${csrf}`,
      },
      body: new URLSearchParams({ csrf, request, decision: "approve" }),
    });
    expect(noOrigin.status).toBe(403);

    const crossSite = await decide(
      { csrf, request, decision: "approve" },
      { Cookie: `mcp_consent_csrf=${csrf}`, Origin: "https://evil.example" },
    );
    expect(crossSite.status).toBe(403);
    expect(await sql`SELECT 1 FROM mcp_grants`).toHaveLength(0);
  });

  test("deny returns access_denied and forgets the request", async () => {
    const { csrf, request, cookie } = await prepare();
    const response = await decide({ csrf, request, decision: "deny" }, { Cookie: cookie });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") as string);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("s1");
    expect(location.searchParams.get("iss")).toBe(APP_URL);
    expect(await sql`SELECT 1 FROM mcp_auth_requests`).toHaveLength(0);
    expect(await sql`SELECT 1 FROM mcp_grants`).toHaveLength(0);
  });

  test("approving while signed out sends the browser to sign in", async () => {
    const { csrf, request, cookie } = await prepare();
    h.session.userId = null;
    const response = await decide({ csrf, request, decision: "approve" }, { Cookie: cookie });
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/sign-in");
    expect(await sql`SELECT 1 FROM mcp_grants`).toHaveLength(0);
  });

  test("approving twice reuses the one live grant", async () => {
    for (let i = 0; i < 2; i++) {
      const { csrf, request, cookie } = await prepare();
      const response = await decide({ csrf, request, decision: "approve" }, { Cookie: cookie });
      expect(response.status).toBe(302);
      expect(new URL(response.headers.get("location") as string).searchParams.get("code")).toBeTruthy();
    }
    expect(await sql`SELECT 1 FROM mcp_grants WHERE revoked_at IS NULL`).toHaveLength(1);
  });

  test("an unrecognised decision and an unknown request are refused", async () => {
    const { csrf, request, cookie } = await prepare();
    const bad = await decide({ csrf, request, decision: "maybe" }, { Cookie: cookie });
    expect(bad.status).toBe(400);

    const gone = await decide(
      { csrf, request: "00000000-0000-4000-8000-000000000000", decision: "approve" },
      { Cookie: cookie },
    );
    expect(gone.status).toBe(410);
    const junk = await decide({ csrf, request: "not-a-uuid", decision: "approve" }, { Cookie: cookie });
    expect(junk.status).toBe(410);
  });
});

describe("the app's wrappers", () => {
  test("secureHeaders wraps the consent routes and nothing else", async () => {
    h = harness(sql, {
      secureHeaders: async (_req, handler) => {
        const response = await handler(_req);
        response.headers.set("Content-Security-Policy", "default-src 'self'");
        return response;
      },
    });
    const page = await authorize();
    expect(page.headers.get("content-security-policy")).toBe("default-src 'self'");
    const doc = await h.call("/.well-known/oauth-authorization-server");
    expect(doc.headers.get("content-security-policy")).toBeNull();
  });

  test("renderPage replaces the page chrome", async () => {
    h = harness(sql, {
      renderPage: (page) => `<custom>${page.heading}|${page.bodyHtml}</custom>`,
    });
    const html = await (await authorize()).text();
    expect(html).toStartWith("<custom>Connect ");
    expect(html).toContain("Allow access");
  });
});
