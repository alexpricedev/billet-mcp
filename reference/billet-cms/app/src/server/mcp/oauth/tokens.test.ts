import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";
import { createHash } from "node:crypto";
import { testDatabase } from "../../test-utils/database";
import { cleanupTestData, seedIdentity } from "../../test-utils/helpers";

const connection = testDatabase();

mock.module("../../services/database", () => ({
  get db() {
    return connection;
  },
  closeDatabase: async () => {},
}));

import { db } from "../../services/database";
import { registerClient } from "./clients";
import { mcpResource } from "./config";
import {
  createOrReuseGrant,
  exchangeAuthorizationCode,
  mintToken,
  revokeGrant,
  rotateRefreshToken,
  verifyAccessToken,
} from "./tokens";

const REDIRECT = "http://localhost:9999/callback";
const VERIFIER = "a".repeat(64);
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");

let clientId: string;
let identityId: string;

beforeEach(async () => {
  await cleanupTestData(db);
  identityId = (await seedIdentity(db, "editor@example.com")).id;

  const client = await registerClient({
    client_name: "Test client",
    redirect_uris: [REDIRECT],
  });
  if (!client.ok) throw new Error(client.description);
  clientId = client.client.clientId;
});

afterAll(async () => {
  await connection.end();
});

const grant = async () =>
  createOrReuseGrant({ clientId, identityId, scope: "content" });

const mintCode = async (grantId: string, resource = mcpResource()) =>
  mintToken({
    grantId,
    kind: "code",
    resource,
    ttlSeconds: 60,
    codeChallenge: CHALLENGE,
    redirectUri: REDIRECT,
  });

describe("authorization code exchange", () => {
  test("issues a token pair and the access token resolves the identity", async () => {
    const created = await grant();
    const code = await mintCode(created.id);

    const result = await exchangeAuthorizationCode({
      code,
      clientId,
      redirectUri: REDIRECT,
      codeVerifier: VERIFIER,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.tokens.accessToken).toStartWith("bcmcp_at_");
    expect(result.tokens.refreshToken).toStartWith("bcmcp_rt_");

    const context = await verifyAccessToken(result.tokens.accessToken);
    expect(context?.actor.email).toBe("editor@example.com");
    expect(context?.grant.clientId).toBe(clientId);
  });

  test("refuses the wrong verifier and burns nothing before the check", async () => {
    const created = await grant();
    const code = await mintCode(created.id);

    const result = await exchangeAuthorizationCode({
      code,
      clientId,
      redirectUri: REDIRECT,
      codeVerifier: "b".repeat(64),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_grant");
  });

  test("refuses a code minted for another resource", async () => {
    const created = await grant();
    const code = await mintCode(created.id, "https://elsewhere.example/mcp");

    const result = await exchangeAuthorizationCode({
      code,
      clientId,
      redirectUri: REDIRECT,
      codeVerifier: VERIFIER,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_target");
  });
});

describe("refresh rotation", () => {
  test("rotates, then revokes the grant when the old token is reused", async () => {
    const created = await grant();
    const code = await mintCode(created.id);
    const first = await exchangeAuthorizationCode({
      code,
      clientId,
      redirectUri: REDIRECT,
      codeVerifier: VERIFIER,
    });
    if (!first.ok) throw new Error("code exchange failed");

    const rotated = await rotateRefreshToken({
      refreshToken: first.tokens.refreshToken,
      clientId,
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;
    expect(rotated.tokens.accessToken).not.toBe(first.tokens.accessToken);

    const reused = await rotateRefreshToken({
      refreshToken: first.tokens.refreshToken,
      clientId,
    });
    expect(reused.ok).toBe(false);
    if (reused.ok) return;
    expect(reused.error).toBe("invalid_grant");

    // The grant is now revoked, so even the rotated access token is dead.
    expect(await verifyAccessToken(rotated.tokens.accessToken)).toBeNull();
  });

  test("revoking a grant kills an access token immediately", async () => {
    const created = await grant();
    const code = await mintCode(created.id);
    const first = await exchangeAuthorizationCode({
      code,
      clientId,
      redirectUri: REDIRECT,
      codeVerifier: VERIFIER,
    });
    if (!first.ok) throw new Error("code exchange failed");

    expect(await verifyAccessToken(first.tokens.accessToken)).not.toBeNull();
    expect(await revokeGrant(created.id, identityId)).toBe(true);
    expect(await verifyAccessToken(first.tokens.accessToken)).toBeNull();
  });
});
