import { afterAll, describe, expect, test } from "bun:test";
import { APP_URL, connect, harness, readJson } from "./test-helpers";

const sql = connect();
afterAll(async () => {
  await sql.close();
});

const fetchDoc = async (h: ReturnType<typeof harness>, path: string) => {
  const response = await h.call(path);
  expect(response.status).toBe(200);
  expect(response.headers.get("access-control-allow-origin")).toBe("*");
  return readJson(response);
};

describe("discovery documents", () => {
  test("describe this deployment and its endpoints", async () => {
    const h = harness(sql);

    for (const path of [
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-protected-resource/mcp",
    ]) {
      expect(await fetchDoc(h, path)).toEqual({
        resource: `${APP_URL}/mcp`,
        authorization_servers: [APP_URL],
        scopes_supported: ["content"],
        bearer_methods_supported: ["header"],
      });
    }

    const metadata = await fetchDoc(h, "/.well-known/oauth-authorization-server");
    expect(metadata.issuer).toBe(APP_URL);
    expect(metadata.authorization_endpoint).toBe(`${APP_URL}/mcp/authorize`);
    expect(metadata.token_endpoint).toBe(`${APP_URL}/mcp/token`);
    expect(metadata.registration_endpoint).toBe(`${APP_URL}/mcp/register`);
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
    expect(metadata.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true);
  });

  test("follow the app URL, and drop any path on it", async () => {
    const h = harness(sql, { appUrl: "https://other.example.org/some/path" });
    const resource = await fetchDoc(h, "/.well-known/oauth-protected-resource/mcp");
    expect(resource.resource).toBe("https://other.example.org/mcp");
    const metadata = await fetchDoc(h, "/.well-known/oauth-authorization-server");
    expect(metadata.issuer).toBe("https://other.example.org");
    expect(metadata.token_endpoint).toBe("https://other.example.org/mcp/token");
  });

  test("a 401 points at the same metadata URL", async () => {
    const h = harness(sql, { appUrl: "https://other.example.org" });
    const response = await h.call("/mcp", { method: "POST", body: "{}" });
    expect(response.headers.get("www-authenticate")).toContain(
      'resource_metadata="https://other.example.org/.well-known/oauth-protected-resource/mcp"',
    );
  });

  test("answer HEAD and refuse other methods", async () => {
    const h = harness(sql);
    const head = await h.call("/.well-known/oauth-authorization-server", {
      method: "HEAD",
    });
    expect(head.status).toBe(200);
    const post = await h.call("/.well-known/oauth-authorization-server", {
      method: "POST",
    });
    expect(post.status).toBe(405);
  });

  test("an appUrl that is not http(s) is refused", () => {
    expect(() => harness(sql, { appUrl: "ftp://example.com" })).toThrow();
  });
});
