/**
 * The two discovery documents, built from `APP_URL`.
 *
 * Claude and ChatGPT both find the authorization server through the protected
 * resource metadata (`resource` must equal the MCP URL exactly, and the first
 * `authorization_servers` entry is the one Claude uses), then read the RFC 8414
 * document for the endpoints. `authorization_response_iss_parameter_supported`
 * makes ChatGPT use its stable redirect URI and protects both clients against
 * mix-up, so the authorize endpoint must actually return `iss` on every
 * response, including errors.
 */
import { MCP_SCOPE, mcpEndpoint, mcpIssuer, mcpResource } from "./config";

export const protectedResourceMetadata = () => ({
  resource: mcpResource(),
  authorization_servers: [mcpIssuer()],
  scopes_supported: [MCP_SCOPE],
  bearer_methods_supported: ["header"],
});

export const authorizationServerMetadata = () => ({
  issuer: mcpIssuer(),
  authorization_endpoint: mcpEndpoint("/mcp/authorize"),
  token_endpoint: mcpEndpoint("/mcp/token"),
  registration_endpoint: mcpEndpoint("/mcp/register"),
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: [MCP_SCOPE],
  authorization_response_iss_parameter_supported: true,
});
