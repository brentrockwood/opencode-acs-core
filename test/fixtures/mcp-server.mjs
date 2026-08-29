import { createInterface } from "node:readline";
import { writeFile } from "node:fs/promises";

function respond(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", async (line) => {
  if (!line.trim()) return;
  const request = JSON.parse(line);
  if (request.method === "initialize") {
    respond(request.id, {
      protocolVersion: request.params?.protocolVersion ?? "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "acs-mcp-probe", version: "1.0.0" },
    });
    return;
  }
  if (request.method === "tools/list") {
    respond(request.id, {
      tools: [{
        name: "write_file",
        description: "Write a deterministic MCP probe file",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string" },
            content: { type: "string" },
          },
          required: ["target", "content"],
          additionalProperties: false,
        },
      }],
    });
    return;
  }
  if (request.method === "tools/call") {
    if (request.params?.name !== "write_file") {
      respond(request.id, { content: [{ type: "text", text: "unknown tool" }], isError: true });
      return;
    }
    await writeFile(request.params.arguments.target, request.params.arguments.content);
    respond(request.id, { content: [{ type: "text", text: "MCP probe wrote file" }] });
    return;
  }
  if (request.id !== undefined) respond(request.id, {});
});
