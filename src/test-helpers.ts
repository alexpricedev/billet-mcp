import { SQL } from "bun";
import { createHash, randomBytes } from "node:crypto";
import { createMcp, down, type McpOptions, type McpUser, up } from "./index";

export const APP_URL = "https://app.example.com";

export const testDatabaseUrl = (): string =>
  process.env.DATABASE_URL ??
  "postgresql://postgres:postgres@localhost:5432/billet_mcp_test";

/** Drops and recreates the `mcp_` tables, so each test file starts clean. */
export const resetDatabase = async (sql: SQL): Promise<void> => {
  await down(sql);
  await up(sql);
};

export const pkcePair = () => {
  const verifier = randomBytes(48).toString("base64url");
  return {
    verifier,
    challenge: createHash("sha256").update(verifier).digest("base64url"),
  };
};

export const CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

export const EDITOR: McpUser = { id: "user-1", email: "editor@example.com" };

export interface Harness {
  sql: SQL;
  mcp: ReturnType<typeof createMcp>;
  users: Map<string, McpUser>;
  /** The id of the signed-in user, or null. Tests flip this. */
  session: { userId: string | null };
  warnings: string[];
  call: (
    path: string,
    init?: RequestInit,
  ) => Response | Promise<Response>;
}

export const harness = (
  sql: SQL,
  overrides: Partial<McpOptions> = {},
): Harness => {
  const users = new Map<string, McpUser>([[EDITOR.id, EDITOR]]);
  const session = { userId: EDITOR.id as string | null };
  const warnings: string[] = [];
  const mcp = createMcp({
    sql,
    appUrl: APP_URL,
    log: {
      warn: (_scope, message) => void warnings.push(message),
      error: (_scope, message) => void warnings.push(message),
    },
    server: { name: "Test app", version: "1.2.3", instructions: "Be kind." },
    getUser: () => (session.userId ? (users.get(session.userId) ?? null) : null),
    findUser: (id) => users.get(id) ?? null,
    signInUrl: "/sign-in",
    registerTools: (server, user) => {
      server.registerTool(
        "whoami",
        { description: "The signed-in user's email." },
        async () => ({
          content: [{ type: "text" as const, text: user.email }],
          structuredContent: { email: user.email },
        }),
      );
    },
    ...overrides,
  });
  return {
    sql,
    mcp,
    users,
    session,
    warnings,
    call: (path, init) => {
      const handler = mcp.routes[path.split("?")[0]];
      if (!handler) throw new Error(`no route ${path}`);
      return handler(new Request(`${APP_URL}${path}`, init));
    },
  };
};

export const connect = () => new SQL(testDatabaseUrl());

/** Test responses are untyped JSON. */
export const readJson = async (response: Response): Promise<any> =>
  response.json();
