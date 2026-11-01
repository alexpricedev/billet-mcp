# billet-mcp

A remote [MCP](https://modelcontextprotocol.io) endpoint with an OAuth 2.1 sign-in, for [Billet](https://github.com/alexpricedev) apps. Claude connectors (and ChatGPT) can register themselves, send a person through a consent screen, and then call the app's tools as that person.

It owns the generic surface and nothing else:

- OAuth 2.1 server: dynamic client registration (RFC 7591), authorize with PKCE (S256 only), authorization codes, rotating refresh tokens, revocation of a grant.
- Discovery: RFC 9728 protected-resource metadata and RFC 8414 authorization-server metadata.
- The consent screen.
- A bearer gate whose 401 carries the RFC 9728 `resource_metadata` pointer.
- A stateless `/mcp` endpoint and tool-call auditing.

The app supplies the database, its URL, a logger, its users, its sign-in page and its tools. The package imports nothing Billet-specific and keeps its data in its own `mcp_` tables.

## Install

```sh
bun add @alexpricedev/billet-mcp
```

Requires Bun (it uses `Bun.SQL`) and Postgres.

## Add the migration

The package ships `up` and `down` functions. Wrap them in one migration file of your app's:

```ts
// migrations/0xx_add_mcp.ts
import { down as mcpDown, up as mcpUp } from "@alexpricedev/billet-mcp";
import type { SQL } from "bun";

export const up = (db: SQL) => mcpUp(db);
export const down = (db: SQL) => mcpDown(db);
```

It creates `mcp_clients`, `mcp_grants`, `mcp_tokens`, `mcp_auth_requests` and `mcp_audit`. Every constraint and index is named with the `mcp_` prefix. `identity_id` is `TEXT` with no foreign key, so your user ids can be UUIDs, integers or anything else stable.

## Mount the routes

```ts
import { createMcp, MCP_CONTINUE_PATH } from "@alexpricedev/billet-mcp";

export const mcp = createMcp({
  sql: db,                                  // a Bun SQL instance
  appUrl: process.env.APP_URL!,             // e.g. https://app.example.com
  log,                                      // { warn, error, info? }(scope, message)
  server: {
    name: "My app",
    version: "1.0.0",
    instructions: "What the model should know about this server.",
  },
  getUser: async (req) => {                 // the signed-in user, or null
    const session = await sessionFrom(req);
    return session ? { id: session.user.id, email: session.user.email } : null;
  },
  findUser: async (id) => lookupUser(id),   // fresh read by id, or null
  signInUrl: "/sign-in",                    // string, or (req) => string
  registerTools: (server, user) => {
    server.registerTool("whoami", { description: "Who am I?" }, async () => ({
      content: [{ type: "text", text: user.email }],
    }));
  },
});

Bun.serve({
  routes: {
    ...mcp.routes,
    // ...your own routes
  },
});
```

`mcp.routes` is a plain object of `(req: Request) => Response | Promise<Response>`:

| Route | What |
| --- | --- |
| `/mcp` | the stateless MCP endpoint (bearer token) |
| `/.well-known/oauth-protected-resource` and `/mcp` | RFC 9728 metadata |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `/mcp/register` | dynamic client registration |
| `/mcp/authorize` | the consent screen (GET) and its decision (POST) |
| `/mcp/authorize/continue` | where sign-in returns to |
| `/mcp/token` | code exchange and refresh |

The discovery documents must be reachable at the root of your origin, so mount them there.

### The seams

| Option | Purpose |
| --- | --- |
| `sql` | Bun `SQL` connection. Grants and tokens use `sql.begin` transactions. |
| `appUrl` | Your public URL. Only its origin is used: it is the OAuth issuer and `<origin>/mcp` is the resource. Cookies are `Secure` when it is `https`. |
| `log` | `warn`/`error` (and optional `info`) taking `(scope, message)`. |
| `server` | Name, version and instructions the MCP server reports. |
| `getUser(req)` | The signed-in user for a browser request: `{ id, email }` with a stable `id`, or `null`. |
| `findUser(id)` | The user behind a stored grant, or `null` if they are gone. It runs on every `/mcp` request, so removing a person from your app ends every token they approved. |
| `signInUrl` | Where a signed-out browser goes to sign in. |
| `registerTools(server, user)` | Register your tools on the per-request `McpServer`. `user` is who the token acts as. |
| `rateLimit?(req, rule)` | Return a `Response` (usually a 429) to refuse, or `null`. Called for `mcp-register`, `mcp-authorize`, `mcp-token` (all per IP) and `mcp-tool` (`rule.key` is per grant, 120 a minute). |
| `secureHeaders?(req, handler)` | Wraps the two HTML routes so your CSP and friends apply. |
| `renderPage?(page)` | Replaces the package's plain page chrome. `page.bodyHtml` is already escaped. |
| `auditTargetKeys?` | Tool argument names kept in the audit row (default `slot`, `handle`, `id`, `url`, `revisionId`, `target`). Other arguments are never recorded. |

The package's own page uses an inline `<style>`. If your CSP forbids that, pass `renderPage`.

### Sign-in and coming back

A signed-out visit to `/mcp/authorize` stores the pending request, sets the HttpOnly `mcp_auth` cookie (`Path=/`, ten minutes) and redirects to `signInUrl`. After your sign-in completes, send the browser on to `MCP_CONTINUE_PATH` (`/mcp/authorize/continue`) when a request is pending:

```ts
if (mcp.hasPendingAuthorize(req)) return Response.redirect(MCP_CONTINUE_PATH);
```

`/mcp/authorize/continue` shows the consent screen, or redirects to `/` when there is no pending request.

## Connect Claude

1. Deploy the app with the routes mounted and `appUrl` set to its public URL.
2. In Claude, add a custom connector and enter `https://your-app.example.com/mcp`.
3. Claude gets a 401 with `resource_metadata`, discovers the server, registers itself, and opens `/mcp/authorize` in your browser.
4. Sign in if you are not, then choose **Allow access** on the consent screen.

For Claude Code: `claude mcp add --transport http my-app https://your-app.example.com/mcp`, then `/mcp` inside Claude Code to sign in.

## Behaviour

- One scope, `content`. Anything else is refused, not narrowed.
- Public clients only (`token_endpoint_auth_method: none`). Registration accepts only Claude's and ChatGPT's callbacks and loopback redirects (`http://localhost`, `127.0.0.1`, `[::1]`).
- Lifetimes: authorization code 60 seconds, access token 1 hour, refresh token 30 days, pending authorize request 10 minutes.
- Codes are single use. Refresh tokens rotate, and presenting a spent one revokes the whole grant.
- Tokens are 256 random bits, stored only as a SHA-256. An access token is also checked against its grant, its audience (`<origin>/mcp`) and `findUser`.
- The consent form is protected by a double-submit token in an HttpOnly cookie plus an `Origin` check.
- JSON-RPC batches are refused, so the rate limit and the audit see every call.
- There is no development token: OAuth is the only way in.
- Every tool call writes one `mcp_audit` row (tool, grant, outcome, target arguments), and so do grant approvals and revocations.

Also exported from `createMcp`: `revokeGrant(grantId, actorId)`, `listGrants()` for a connected-apps page, and `cleanupExpired()` to delete spent credentials (run it now and then).

## Development

```sh
bun install
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/billet_mcp_test bun run check
bun run build
```

The tests run the OAuth flow against Postgres and drop and recreate the `mcp_` tables, so point `DATABASE_URL` at a throwaway database.
