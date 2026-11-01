import { describe, expect, test } from "bun:test";
import { parseToolCall, parseToolResult, targetOf } from "./audit";

describe("the tool-call audit parser", () => {
  test("reads a tools/call and ignores other methods", () => {
    expect(
      parseToolCall({
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "get_slot", arguments: { slot: "home.hero" } },
      }),
    ).toEqual({
      name: "get_slot",
      arguments: { slot: "home.hero" },
      id: 7,
    });

    expect(
      parseToolCall({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    ).toBeNull();
    expect(parseToolCall(null)).toBeNull();
    expect(parseToolCall({ method: "tools/call", params: {} })).toBeNull();
  });

  test("keeps target fields and never content", () => {
    expect(
      targetOf({
        slot: "home.hero",
        id: "abc",
        revisionId: 3,
        content: { heading: "secret copy" },
        blocks: [{ type: "hero" }],
      }),
    ).toEqual({ slot: "home.hero", id: "abc", revisionId: 3 });
  });

  test("reads a JSON result's outcome", () => {
    expect(
      parseToolResult(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: { isError: true, structuredContent: { reason: "invalid" } },
        }),
        "application/json",
        1,
      ),
    ).toEqual({ ok: false, reason: "invalid" });
  });

  test("reads an SSE result and matches the request id", () => {
    const text = [
      "event: message",
      `data: ${JSON.stringify({ jsonrpc: "2.0", id: 2, result: {} })}`,
      "",
    ].join("\n");

    expect(parseToolResult(text, "text/event-stream", 2)).toEqual({
      ok: true,
      reason: null,
    });
    expect(parseToolResult(text, "text/event-stream", 99)).toBeNull();
  });

  test("treats a JSON-RPC error as a failed call", () => {
    expect(
      parseToolResult(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          error: { code: -32601, message: "Unknown tool" },
        }),
        "application/json",
        3,
      ),
    ).toEqual({ ok: false, reason: "protocol_error" });
  });
});
