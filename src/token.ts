/**
 * `/mcp/token`: exchange an authorization code, or rotate a refresh token.
 *
 * Public clients only, so there is no client secret and no `Authorization`
 * header — the `client_id` is a parameter, and possession of the code is proved
 * by the PKCE verifier. The body is form-encoded, which is what both clients
 * send; a JSON body is refused rather than guessed at. Every response is
 * uncached, and errors use RFC 6749's codes because a refresh that returns a
 * custom code is a refresh a client cannot act on.
 */
import {
  exchangeAuthorizationCode,
  rotateRefreshToken,
  type TokenPair,
} from "./oauth/tokens";
import type { McpContext } from "./config";
import { limited, type RequestForm } from "./http";

const TOKEN_HEADERS = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
  "X-Robots-Tag": "noindex",
};

const oauthError = (
  status: number,
  error: string,
  description: string,
): Response =>
  Response.json(
    { error, error_description: description },
    { status, headers: TOKEN_HEADERS },
  );

const tokensResponse = (tokens: TokenPair): Response =>
  Response.json(
    {
      access_token: tokens.accessToken,
      token_type: "Bearer",
      expires_in: tokens.expiresIn,
      refresh_token: tokens.refreshToken,
      scope: tokens.scope,
    },
    { headers: TOKEN_HEADERS },
  );

const field = (form: RequestForm, name: string): string | null => {
  const value = form.get(name);
  return typeof value === "string" && value !== "" ? value : null;
};

export const createTokenHandlers = (ctx: McpContext) => ({
  async create(req: Request): Promise<Response> {
    const refused = await limited(ctx, req, {
      name: "mcp-token",
      limit: 30,
      windowMs: 60_000,
    });
    if (refused) return refused;

    const mediaType = (req.headers.get("content-type") ?? "")
      .split(";")[0]
      .trim()
      .toLowerCase();
    if (mediaType !== "application/x-www-form-urlencoded") {
      return oauthError(
        400,
        "invalid_request",
        "The token endpoint accepts application/x-www-form-urlencoded.",
      );
    }

    let form: RequestForm;
    try {
      form = await req.formData();
    } catch {
      return oauthError(
        400,
        "invalid_request",
        "The request body could not be parsed.",
      );
    }

    const grantType = field(form, "grant_type");
    const clientId = field(form, "client_id");
    const resource = field(form, "resource");

    if (!clientId) {
      return oauthError(400, "invalid_request", "client_id is required.");
    }

    try {
      if (grantType === "authorization_code") {
        const code = field(form, "code");
        const redirectUri = field(form, "redirect_uri");
        const codeVerifier = field(form, "code_verifier");

        if (!code || !redirectUri || !codeVerifier) {
          return oauthError(
            400,
            "invalid_request",
            "code, redirect_uri and code_verifier are required.",
          );
        }

        const result = await exchangeAuthorizationCode(ctx, {
          code,
          clientId,
          redirectUri,
          codeVerifier,
          resource,
        });

        if (!result.ok) {
          return oauthError(
            result.error === "invalid_client" ? 401 : 400,
            result.error,
            result.description,
          );
        }
        return tokensResponse(result.tokens);
      }

      if (grantType === "refresh_token") {
        const refreshToken = field(form, "refresh_token");
        if (!refreshToken) {
          return oauthError(
            400,
            "invalid_request",
            "refresh_token is required.",
          );
        }

        const result = await rotateRefreshToken(ctx, {
          refreshToken,
          clientId,
          resource,
        });
        if (!result.ok) {
          return oauthError(
            result.error === "invalid_client" ? 401 : 400,
            result.error,
            result.description,
          );
        }
        return tokensResponse(result.tokens);
      }

      return oauthError(
        400,
        "unsupported_grant_type",
        "grant_type must be authorization_code or refresh_token.",
      );
    } catch (error) {
      ctx.log.error(
        "mcp",
        `Token request failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return oauthError(
        500,
        "server_error",
        "The server could not complete the token request.",
      );
    }
  },
});
