/**
 * Auditing every tool call, without touching each tool's body.
 *
 * The route clones the request body before the SDK reads it, remembers the tool
 * name and a small target, and after the handler answers, clones the response
 * and records one `cms_audit` row. That keeps the audit honest for tools added
 * later and keeps content out of the log: only the tool name, its target fields
 * and the outcome are recorded, never the arguments or the result.
 *
 * The response is cloned rather than consumed, so a streaming answer still
 * reaches the client exactly as the SDK produced it.
 */
import type { AuthInfo } from "@modelcontextprotocol/server";
import { recordAudit } from "../services/audit";
import { log } from "../services/logger";
import { actorFromAuthInfo, grantIdFromAuthInfo } from "./auth";

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
  id: string | number | null;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The tool call in a JSON-RPC body, or `null` for anything else.
 *
 * `initialize`, `tools/list` and notifications are not audited: the first two
 * are session plumbing, and a notification has no id to correlate.
 */
export const parseToolCall = (body: unknown): ToolCall | null => {
  if (!isRecord(body) || body.method !== "tools/call") return null;
  const params = isRecord(body.params) ? body.params : null;
  if (!params || typeof params.name !== "string" || params.name === "") {
    return null;
  }
  const id =
    typeof body.id === "string" || typeof body.id === "number" ? body.id : null;
  return {
    name: params.name,
    arguments: isRecord(params.arguments) ? params.arguments : {},
    id,
  };
};

/** Parse the JSON-RPC body without consuming the SDK's copy; `null` if unparseable. */
export const readRpcBody = async (req: Request): Promise<unknown> => {
  try {
    return await req.clone().json();
  } catch {
    return null;
  }
};

const TARGET_KEYS = [
  "slot",
  "handle",
  "id",
  "url",
  "revisionId",
  "target",
] as const;

/**
 * The small, non-content fields that identify a target.
 *
 * Deliberately an allowlist: `content` and `blocks` are the bulk of a write and
 * may contain anything an editor typed, which has no place in an audit row.
 */
export const targetOf = (
  args: Record<string, unknown>,
): Record<string, string | number> => {
  const target: Record<string, string | number> = {};
  for (const key of TARGET_KEYS) {
    const value = args[key];
    if (typeof value === "string" || typeof value === "number") {
      target[key] = value;
    }
  }
  return target;
};

export interface ToolOutcome {
  ok: boolean;
  reason: string | null;
}

const outcomeOf = (
  message: unknown,
  id: ToolCall["id"],
): ToolOutcome | null => {
  if (!isRecord(message)) return null;
  if (id !== null && message.id !== id) return null;

  if (isRecord(message.error)) {
    return { ok: false, reason: "protocol_error" };
  }

  const result = isRecord(message.result) ? message.result : null;
  if (!result) return null;

  const structured = isRecord(result.structuredContent)
    ? result.structuredContent
    : {};
  return {
    ok: result.isError !== true,
    reason: typeof structured.reason === "string" ? structured.reason : null,
  };
};

/**
 * The outcome in a tool response.
 *
 * Modern hosts answer with one JSON object; the 2025-era stateless path answers
 * with an SSE stream. Both carry the same JSON-RPC result, so both are read and
 * matched by request id.
 */
export const parseToolResult = (
  text: string,
  contentType: string,
  id: ToolCall["id"],
): ToolOutcome | null => {
  const type = contentType.split(";")[0].trim().toLowerCase();

  if (type === "application/json") {
    try {
      return outcomeOf(JSON.parse(text), id);
    } catch {
      return null;
    }
  }

  if (type === "text/event-stream") {
    for (const line of text.split(/\r?\n/)) {
      if (!line.startsWith("data:")) continue;
      const raw = line.slice(5).trim();
      if (raw === "") continue;
      try {
        const outcome = outcomeOf(JSON.parse(raw), id);
        if (outcome) return outcome;
      } catch {
        // A comment or partial frame; the next line may be the result.
      }
    }
  }

  return null;
};

/** Record one audit row for a completed tool call, best-effort. */
export const auditToolCall = async (
  call: ToolCall,
  authInfo: AuthInfo | undefined,
  response: Response,
): Promise<void> => {
  try {
    const contentType = response.headers.get("content-type") ?? "";
    const outcome = parseToolResult(
      await response.clone().text(),
      contentType,
      call.id,
    ) ?? {
      ok: false,
      reason: "unreadable_result",
    };

    await recordAudit({
      action: "mcp.tool",
      actorId: actorFromAuthInfo(authInfo)?.id ?? null,
      subjectType: "mcp_tool",
      detail: {
        tool: call.name,
        grantId: grantIdFromAuthInfo(authInfo),
        ok: outcome.ok,
        ...(outcome.reason ? { reason: outcome.reason } : {}),
        ...targetOf(call.arguments),
      },
    });
  } catch (error) {
    // The tool already ran; a logging problem must not change its answer.
    log.warn(
      "mcp",
      `Could not audit ${call.name}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};
