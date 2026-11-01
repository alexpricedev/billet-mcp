import { timingSafeEqual } from "node:crypto";
import type { McpContext } from "./config";
import type { RateLimitRule } from "./types";

export const JSON_HEADERS = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "X-Robots-Tag": "noindex",
};

export const methodNotAllowed = (allow: string): Response =>
  new Response("", {
    status: 405,
    headers: { Allow: allow, "Cache-Control": "no-store" },
  });

export const oauthError = (
  status: number,
  error: string,
  description: string,
  headers: Record<string, string> = {
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex",
  },
): Response =>
  Response.json(
    { error, error_description: description },
    { status, headers },
  );

/** Run the app's rate-limit hook, if it supplied one. */
export const limited = async (
  ctx: McpContext,
  req: Request,
  rule: RateLimitRule,
): Promise<Response | null> =>
  (await ctx.options.rateLimit?.(req, rule)) ?? null;

export const constantTimeEqual = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

export const redirect = (
  location: string,
  cookies: string[] = [],
  status = 302,
): Response => {
  const headers = new Headers({ Location: location, "Cache-Control": "no-store" });
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(null, { status, headers });
};
export type RequestForm = Awaited<ReturnType<Request["formData"]>>;
