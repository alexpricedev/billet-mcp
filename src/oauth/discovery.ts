/**
 * The two discovery documents, built from the app URL.
 *
 * Claude and ChatGPT both find the authorization server through the protected
 * resource metadata (`resource` must equal the MCP URL exactly, and the first
 * `authorization_servers` entry is the one Claude uses), then read the RFC 8414
 * document for the endpoints. `authorization_response_iss_parameter_supported`
 * makes ChatGPT use its stable redirect URI and protects both clients against
 * mix-up, so the authorize endpoint must actually return `iss` on every
 * response, including errors.
 */
import { endpoint, MCP_SCOPE, type McpContext } from "../config";

export const protectedResourceMetadata = (ctx: McpContext) => ({
  resource: ctx.resource,
  authorization_servers: [ctx.issuer],
  scopes_supported: [MCP_SCOPE],
  bearer_methods_supported: ["header"],
});

export const authorizationServerMetadata = (ctx: McpContext) => ({
  issuer: ctx.issuer,
  authorization_endpoint: endpoint(ctx, "/mcp/authorize"),
  token_endpoint: endpoint(ctx, "/mcp/token"),
  registration_endpoint: endpoint(ctx, "/mcp/register"),
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: [MCP_SCOPE],
  authorization_response_iss_parameter_supported: true,
});
