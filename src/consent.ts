/**
 * The consent screen and the dead-end page, as escaped template strings.
 *
 * Every dynamic value goes through `escapeHtml`: a registered client name or a
 * redirect host is rendered as text, so it cannot inject markup into the page
 * that asks for consent.
 */
import type { ConsentPage, McpOptions } from "./types";

/** The path the consent form posts to. */
export const CONSENT_PATH = "/mcp/authorize";

export const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const STYLES = `
  body{font-family:system-ui,sans-serif;background:#f6f6f4;color:#1c1c1a;margin:0;padding:1rem}
  main{max-width:28rem;margin:3rem auto;background:#fff;border:1px solid #ddd;border-radius:.5rem;padding:1.5rem}
  h1{font-size:1.4rem;margin:0 0 .5rem}
  p.subtitle{margin:0 0 1rem;color:#555}
  ul{padding-left:1.2rem;line-height:1.5}
  .actions{display:flex;gap:.75rem;margin-top:1.25rem}
  button{font:inherit;padding:.6rem 1rem;border-radius:.35rem;border:1px solid #1c1c1a;cursor:pointer}
  button.primary{background:#1c1c1a;color:#fff}
  button.ghost{background:#fff;color:#1c1c1a}
  .error{border:1px solid #b3261e;color:#b3261e;border-radius:.35rem;padding:.6rem .8rem}
  footer{margin-top:1.25rem;font-size:.9rem}
`;

const defaultPage = (page: ConsentPage): string => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(page.title)}</title>
<style>${STYLES}</style>
</head>
<body>
<main>
<h1>${escapeHtml(page.heading)}</h1>
<p class="subtitle">${escapeHtml(page.subtitle)}</p>
${page.bodyHtml}
${page.footerHtml ? `<footer>${page.footerHtml}</footer>` : ""}
</main>
</body>
</html>`;

export const renderPage = (options: McpOptions, page: ConsentPage): string =>
  (options.renderPage ?? defaultPage)(page);

const LOOPBACK_HOST = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

export interface ConsentInput {
  serverName: string;
  clientName: string;
  /** The connection label the client registered, shown apart from the app name. */
  connectionLabel: string | null;
  /** The host the authorization code will be sent to, shown to the person. */
  redirectHost: string;
  identityEmail: string;
  requestId: string;
  csrfToken: string;
}

/**
 * The one screen where a person grants an AI client authority over the app.
 *
 * It is deliberately plain: who is asking, who they will act as, where they
 * will return, and the single permission this server issues.
 */
export const consentPage = (input: ConsentInput): ConsentPage => {
  const e = escapeHtml;
  const items = [
    input.connectionLabel
      ? `<li>Connection: <strong>${e(input.connectionLabel)}</strong></li>`
      : "",
    `<li>It can use <strong>every tool this server offers</strong>, as you.</li>`,
    `<li>You are signed in as <strong>${e(input.identityEmail)}</strong>.</li>`,
    `<li>After you decide, you will return to <strong>${e(input.redirectHost)}</strong>.</li>`,
    LOOPBACK_HOST.test(input.redirectHost)
      ? "<li>This app will return to a program on this computer. Only continue if you started it.</li>"
      : "",
  ].join("\n");

  return {
    title: `Connect an app - ${input.serverName}`,
    heading: `Connect ${input.clientName}?`,
    subtitle: `It will act as you in ${input.serverName}.`,
    bodyHtml: `<ul class="consent-details">
${items}
</ul>
<form method="POST" action="${CONSENT_PATH}" class="actions">
<input type="hidden" name="csrf" value="${e(input.csrfToken)}">
<input type="hidden" name="request" value="${e(input.requestId)}">
<button type="submit" name="decision" value="approve" class="primary">Allow access</button>
<button type="submit" name="decision" value="deny" class="ghost">Deny</button>
</form>`,
    footerHtml: null,
  };
};

/**
 * A dead end in the OAuth flow, rendered instead of redirecting.
 *
 * An unknown client or an unregistered redirect URI must never be sent
 * anywhere: the redirect is the attack surface.
 */
export const errorPage = (
  serverName: string,
  heading: string,
  message: string,
  siteUrl: string,
): ConsentPage => ({
  title: `${heading} - ${serverName}`,
  heading,
  subtitle: message,
  bodyHtml: "",
  footerHtml: `<a href="${escapeHtml(siteUrl)}">Back to the site</a>`,
});
