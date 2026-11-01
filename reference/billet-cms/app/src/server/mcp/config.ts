/**
 * The MCP endpoint's environment.
 *
 * `MCP_ENABLED` switches the whole surface on. OAuth is the credential in every
 * environment; `MCP_DEV_TOKEN` is an optional local seam that `mcp/auth.ts`
 * ignores in production, where `validateEnv` only warns if one is set.
 *
 * Read at call time rather than module load: tests set these on the process.
 */

/** Whether `/mcp` answers at all. Off unless explicitly `true`. */
export const isMcpEnabled = (): boolean => process.env.MCP_ENABLED === "true";

/** The development bearer token, accepted outside production. `null` when unset. */
export const mcpDevToken = (): string | null => {
  const value = process.env.MCP_DEV_TOKEN?.trim();
  return value ? value : null;
};

/**
 * The `cms_identities` email the dev token acts as.
 *
 * Optional: without it the spike can still read, but a write has no `created_by`
 * and `get_profile` has no identity to report. Set it to a fixture admin (for
 * example `priya@example.com`) to exercise history and attribution.
 */
export const mcpDevIdentityEmail = (): string | null => {
  const value = process.env.MCP_DEV_IDENTITY_EMAIL?.trim();
  return value ? value.toLowerCase() : null;
};
