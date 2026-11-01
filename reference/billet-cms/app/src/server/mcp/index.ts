/**
 * The MCP server factory.
 *
 * One server instance per HTTP request; the factory receives the verified
 * `AuthInfo` and hands the resolved CMS identity to every tool. Nothing here
 * touches the database directly — the tools call `services/content` and
 * `services/media`, the same functions the CMS's forms call.
 */
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { SITE_NAME } from "../services/seo";
import { actorFromAuthInfo } from "./auth";
import { registerReadTools } from "./tools/read";
import { registerWriteTools } from "./tools/write";

const INSTRUCTIONS = `${SITE_NAME} holds two kinds of content:
- slots: fixed places in the site's templates (for example home.hero), each filled by one block type.
- pages: documents an editor creates against a page type, served at a URL.

Start with get_context, then read the exact target with get_slot or get_page.
Every save needs the baseRevisionId that read returned; a stale one is refused
instead of overwriting someone else's work.

save_slot and save_page create DRAFTS. They do not change the public site.
publish_slot and publish_page make a revision live within about a second — only
do that when the person asked for it. get_preview_url gives a link to the draft
on the real site, which is usually the better way to show a change.

Content is validated against schemas the site publishes on deploy. validate_slot
and validate_page check without writing. Block types, page types and slots are
read-only: they come from the site's code, not from the CMS.

Image fields take {mediaId, alt?}; get ids from list_media. A rich text field
takes a stored document; read the field tree first, and prefer keeping the
existing document's shape when editing a part of it.`;

export const mcpHandler = createMcpHandler(
  ({ authInfo }) => {
    const server = new McpServer(
      { name: SITE_NAME, version: "0.1.0" },
      { instructions: INSTRUCTIONS },
    );

    const actor = actorFromAuthInfo(authInfo);
    registerReadTools(server, actor);
    registerWriteTools(server, actor);

    return server;
  },
  { legacy: "stateless" },
);
