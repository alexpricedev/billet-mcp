/**
 * The two shapes every tool returns.
 *
 * A successful call carries a short human summary in `content` and the same
 * data in `structuredContent`, so a client that understands structured output
 * gets types and one that does not still gets usable JSON. A refused call sets
 * `isError` — it is an expected outcome the model should read and correct, not
 * a protocol failure.
 */
import type { CallToolResult } from "@modelcontextprotocol/server";
import { log } from "../services/logger";

export interface ToolFieldIssue {
  path: string;
  message: string;
}

export const okResult = (value: Record<string, unknown>): CallToolResult => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
  structuredContent: value,
});

export const errorResult = (
  summary: string,
  detail: Record<string, unknown> = {},
): CallToolResult => ({
  isError: true,
  content: [{ type: "text", text: summary }],
  structuredContent: { ok: false, ...detail },
});

export const issuesResult = (
  summary: string,
  reason: "invalid" | "conflict" | "stale" | "no-draft" | "not-found",
  detail: Record<string, unknown> = {},
): CallToolResult =>
  errorResult(summary, {
    reason,
    ...detail,
  });

/** Cap a list and report the uncapped total, so a caller can page. */
export const paginate = <T>(
  items: readonly T[],
  limit: number,
  offset: number,
): { items: T[]; total: number } => ({
  items: items.slice(offset, offset + limit),
  total: items.length,
});

export const iso = (date: Date | null | undefined): string | null =>
  date ? date.toISOString() : null;

export const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Run a tool body, turning any uncaught throw into a tool error.
 *
 * A service throwing means the caller's target vanished or a publish raced a
 * deploy; the model can act on that as a message. Letting it escape becomes a
 * JSON-RPC internal error with no context, which it cannot.
 */
export const guard = async (
  name: string,
  fn: () => Promise<CallToolResult>,
): Promise<CallToolResult> => {
  try {
    return await fn();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log.error("mcp", `${name} failed: ${message}`);
    return errorResult(`The CMS could not complete ${name}: ${message}`, {
      reason: "error",
    });
  }
};
