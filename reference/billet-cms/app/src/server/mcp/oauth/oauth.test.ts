import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { isAllowedRedirectUri, splitClientName } from "./clients";
import { MCP_SCOPE, parseScope } from "./config";
import {
  authorizationServerMetadata,
  protectedResourceMetadata,
} from "./discovery";
import { verifyPkce } from "./tokens";

const challengeFor = (verifier: string): string =>
  createHash("sha256").update(verifier).digest("base64url");

describe("the redirect allowlist", () => {
  test("accepts the two hosted callbacks", () => {
    expect(
      isAllowedRedirectUri("https://claude.ai/api/mcp/auth_callback"),
    ).toBe(true);
    expect(
      isAllowedRedirectUri(
        "https://chatgpt.com/connector_platform_oauth_redirect",
      ),
    ).toBe(true);
    expect(
      isAllowedRedirectUri("https://chatgpt.com/connector/oauth/abc123"),
    ).toBe(true);
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

describe("discovery documents", () => {
  const original = process.env.APP_URL;

  test("describe this deployment and its endpoints", () => {
    process.env.APP_URL = "https://cms.example.com";
    try {
      expect(protectedResourceMetadata()).toEqual({
        resource: "https://cms.example.com/mcp",
        authorization_servers: ["https://cms.example.com"],
        scopes_supported: ["content"],
        bearer_methods_supported: ["header"],
      });

      const metadata = authorizationServerMetadata();
      expect(metadata.issuer).toBe("https://cms.example.com");
      expect(metadata.authorization_endpoint).toBe(
        "https://cms.example.com/mcp/authorize",
      );
      expect(metadata.token_endpoint).toBe("https://cms.example.com/mcp/token");
      expect(metadata.registration_endpoint).toBe(
        "https://cms.example.com/mcp/register",
      );
      expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
      expect(metadata.token_endpoint_auth_methods_supported).toEqual(["none"]);
      expect(metadata.authorization_response_iss_parameter_supported).toBe(
        true,
      );
    } finally {
      process.env.APP_URL = original;
    }
  });
});
