import type { McpContext } from "./config";

export interface AuditEntry {
  action: string;
  actorId: string | null;
  subjectType: string;
  subjectId?: string | null;
  detail?: Record<string, unknown>;
}

/**
 * Record one `mcp_audit` row, best-effort.
 *
 * The action it describes has already happened; a logging problem must not
 * change the answer to the caller.
 */
export const recordAudit = async (
  ctx: McpContext,
  entry: AuditEntry,
): Promise<void> => {
  try {
    await ctx.sql`
      INSERT INTO mcp_audit (action, actor_id, subject_type, subject_id, detail)
      VALUES (
        ${entry.action},
        ${entry.actorId},
        ${entry.subjectType},
        ${entry.subjectId ?? null},
        ${JSON.stringify(entry.detail ?? {})}::text::jsonb
      )
    `;
  } catch (error) {
    ctx.log.warn(
      "mcp",
      `Could not record audit ${entry.action}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};
