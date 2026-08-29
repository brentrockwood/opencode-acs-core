import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { AcsClient } from "../src/client.js";
import { parseConfig } from "../src/config.js";
import { newSessionState, toolCallPayload } from "../src/mapper.js";
import { PROTECTED_TOOL } from "../src/protected.js";
import type { AcsRequestEnvelope, JsonObject } from "../src/types.js";
import { OPENCODE_VERSION } from "../src/types.js";
import { createGuardian, TEST_KEY, TEST_KEY_ID } from "./guardian-helper.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pluginModule = resolve(packageRoot, "src/index.ts");
const openCodePluginModule = resolve(packageRoot, "node_modules/@opencode-ai/plugin/dist/index.js");
const mcpServerModule = resolve(packageRoot, "test/fixtures/mcp-server.mjs");
const openCodeCli = process.env.OPENCODE_E2E_BIN ?? "opencode";

interface ListeningServer {
  server: Server;
  url: string;
}

interface OpenCodeRun {
  stdout: string;
  stderr: string;
  audit: JsonObject[];
}

async function installedOpenCodeVersion(): Promise<string> {
  const child = spawn(openCodeCli, ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (value: string) => { stdout += value; });
  child.stderr.setEncoding("utf8").on("data", (value: string) => { stderr += value; });
  const exitCode = await new Promise<number | null>((resolveExit, reject) => {
    child.once("error", reject);
    child.once("close", resolveExit);
  });
  if (exitCode !== 0) throw new Error(`OpenCode --version exited with ${exitCode}: ${stderr}`);
  return stdout.trim();
}

async function bodyOf(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

async function listen(server: Server): Promise<ListeningServer> {
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolveListen();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind a TCP port");
  return { server, url: `http://127.0.0.1:${address.port}` };
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
}

async function reservePort(): Promise<number> {
  const temporary = await listen(createServer());
  const port = Number(new URL(temporary.url).port);
  await close(temporary.server);
  return port;
}

function argument(request: AcsRequestEnvelope, name: string): unknown {
  const item = (request.params.payload.arguments as JsonObject | undefined)?.[name];
  return typeof item === "object" && item !== null && !Array.isArray(item) ? (item as JsonObject).value : undefined;
}

function chunk(delta: JsonObject, finishReason: string | null): string {
  return JSON.stringify({
    id: "chatcmpl-opencode-acs-e2e",
    object: "chat.completion.chunk",
    created: 1,
    model: "acs-e2e-model",
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  });
}

function promptText(messages: unknown): string {
  if (!Array.isArray(messages)) return "";
  const user = [...messages].reverse().find((item) => typeof item === "object" && item !== null && (item as JsonObject).role === "user") as JsonObject | undefined;
  const content = user?.content;
  if (typeof content === "string") return normalizePrompt(content);
  if (!Array.isArray(content)) return "";
  return normalizePrompt(content.map((part) => typeof part === "object" && part !== null && !Array.isArray(part) && typeof (part as JsonObject).text === "string"
    ? String((part as JsonObject).text)
    : "").join(""));
}

function normalizePrompt(value: string): string {
  if (value.startsWith("\"") && value.endsWith("\"")) {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (typeof parsed === "string") return parsed;
    } catch {
      // Preserve the original fixture input when it is not a JSON string.
    }
  }
  return value;
}

function hasToolResult(messages: unknown): boolean {
  return Array.isArray(messages) && messages.some((item) => typeof item === "object" && item !== null && (item as JsonObject).role === "tool");
}

interface FixtureToolCall {
  tool: string;
  args: Record<string, unknown>;
  callID?: string;
}

function fixtureToolCalls(prompt: string): FixtureToolCall[] {
  const parallelPrefix = "ACS_PARALLEL_B64:";
  if (prompt.startsWith(parallelPrefix)) {
    return JSON.parse(Buffer.from(prompt.slice(parallelPrefix.length), "base64url").toString("utf8")) as FixtureToolCall[];
  }
  const prefix = "ACS_TOOL_B64:";
  if (prompt.startsWith(prefix)) {
    return [JSON.parse(Buffer.from(prompt.slice(prefix.length), "base64url").toString("utf8")) as FixtureToolCall];
  }
  return [{ tool: "bash", args: { command: prompt, description: "ACS deterministic fixture" } }];
}

function toolPrompt(tool: string, args: Record<string, unknown>): string {
  return `ACS_TOOL_B64:${Buffer.from(JSON.stringify({ tool, args }), "utf8").toString("base64url")}`;
}

function parallelPrompt(calls: FixtureToolCall[]): string {
  return `ACS_PARALLEL_B64:${Buffer.from(JSON.stringify(calls), "utf8").toString("base64url")}`;
}

function sendModelResponse(response: ServerResponse, calls: FixtureToolCall[] | undefined): void {
  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  if (calls) {
    response.write(`data: ${chunk({
      role: "assistant",
      tool_calls: calls.map((call, index) => ({
        index,
        id: call.callID ?? `call-opencode-acs-e2e-${index}`,
        type: "function",
        function: { name: call.tool, arguments: JSON.stringify(call.args) },
      })),
    }, null)}\n\n`);
    response.write(`data: ${chunk({}, "tool_calls")}\n\n`);
  } else {
    response.write(`data: ${chunk({ role: "assistant", content: "fixture complete" }, null)}\n\n`);
    response.write(`data: ${chunk({}, "stop")}\n\n`);
  }
  response.end("data: [DONE]\n\n");
}

async function createWorkspace(
  base: string,
  guardianUrl: string,
  modelUrl: string,
  enableModify = false,
  customTool = false,
  mcpTool = false,
  protectedResourceUrl?: string,
  hmacKeyId = TEST_KEY_ID,
): Promise<{ directory: string; auditPath: string }> {
  const directory = join(base, "workspace");
  const pluginDirectory = join(directory, ".opencode", "plugins");
  const auditPath = join(base, "audit.jsonl");
  await mkdir(pluginDirectory, { recursive: true });
  await writeFile(join(pluginDirectory, "acs.ts"), `export { AcsPlugin } from ${JSON.stringify(pathToFileURL(pluginModule).href)};\n`);
  if (customTool) {
    await writeFile(join(pluginDirectory, "custom-probe.ts"), `
import { writeFile } from "node:fs/promises";
import { tool } from ${JSON.stringify(pathToFileURL(openCodePluginModule).href)};

export const CustomProbe = async () => ({
  tool: {
    custom_probe: tool({
      description: "Deterministic ACS custom tool probe",
      args: { target: tool.schema.string(), content: tool.schema.string() },
      async execute(args) {
        await writeFile(args.target, args.content);
        return "custom probe wrote file";
      },
    }),
  },
});
`);
  }
  const openCodeConfig: Record<string, unknown> = {
    model: "acs-e2e/acs-e2e-model",
    provider: {
      "acs-e2e": {
        npm: "@ai-sdk/openai-compatible",
        name: "ACS E2E fixture",
        options: { baseURL: `${modelUrl}/v1`, apiKey: "local-e2e-only" },
        models: { "acs-e2e-model": { name: "ACS E2E fixture model" } },
      },
    },
    permission: "allow",
  };
  if (mcpTool) {
    openCodeConfig.mcp = {
      probe: { type: "local", command: [process.execPath, mcpServerModule], enabled: true },
    };
  }
  await writeFile(join(directory, "opencode.json"), JSON.stringify(openCodeConfig));
  await writeFile(join(base, "acs.json"), JSON.stringify({
    mode: "enforce",
    startupPosture: "refuse",
    enableModify,
    guardian: {
      url: `${guardianUrl}/`,
      connectTimeoutMs: 2_000,
      hmacKeyEnv: "OPENCODE_ACS_E2E_KEY",
      keyId: hmacKeyId,
    },
    audit: { path: auditPath, includePayloads: false },
    ...(protectedResourceUrl ? { protectedResource: { url: protectedResourceUrl, timeoutMs: 5_000 } } : {}),
  }));
  return { directory, auditPath };
}

async function runOpenCode(
  base: string,
  guardianUrl: string,
  modelUrl: string,
  prompt: string,
  enableModify = false,
  customTool = false,
  mcpTool = false,
  protectedResourceUrl?: string,
  hmacKey = TEST_KEY,
  hmacKeyId = TEST_KEY_ID,
): Promise<OpenCodeRun> {
  const { directory, auditPath } = await createWorkspace(
    base,
    guardianUrl,
    modelUrl,
    enableModify,
    customTool,
    mcpTool,
    protectedResourceUrl,
    hmacKeyId,
  );
  const child = spawn(openCodeCli, [
    "run",
    "--format", "json",
    "--model", "acs-e2e/acs-e2e-model",
    "--dir", directory,
    prompt,
  ], {
    cwd: directory,
    env: {
      ...process.env,
      OPENCODE_ACS_CONFIG: join(base, "acs.json"),
      OPENCODE_ACS_E2E_KEY: hmacKey,
      XDG_DATA_HOME: join(base, "xdg-data"),
      XDG_CONFIG_HOME: join(base, "xdg-config"),
      XDG_CACHE_HOME: join(base, "xdg-cache"),
      OPENCODE_DISABLE_LSP_DOWNLOAD: "true",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (value: string) => { stdout += value; });
  child.stderr.setEncoding("utf8").on("data", (value: string) => { stderr += value; });
  const exitCode = await new Promise<number | null>((resolveExit, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`OpenCode timed out. stderr:\n${stderr}`));
    }, 25_000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      resolveExit(code);
    });
  });
  if (exitCode !== 0) throw new Error(`OpenCode exited with ${exitCode}.\nstdout:\n${stdout}\nstderr:\n${stderr}`);
  const audit = (await readFile(auditPath, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as JsonObject);
  return { stdout, stderr, audit };
}

async function runDirectServerShell(
  base: string,
  guardianUrl: string,
  modelUrl: string,
  command: string,
): Promise<{ response: string; stdout: string; stderr: string }> {
  const { directory } = await createWorkspace(base, guardianUrl, modelUrl);
  const port = await reservePort();
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(openCodeCli, ["serve", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: directory,
    env: {
      ...process.env,
      OPENCODE_ACS_CONFIG: join(base, "acs.json"),
      OPENCODE_ACS_E2E_KEY: TEST_KEY,
      XDG_DATA_HOME: join(base, "xdg-data"),
      XDG_CONFIG_HOME: join(base, "xdg-config"),
      XDG_CACHE_HOME: join(base, "xdg-cache"),
      OPENCODE_DISABLE_LSP_DOWNLOAD: "true",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (value: string) => { stdout += value; });
  child.stderr.setEncoding("utf8").on("data", (value: string) => { stderr += value; });
  try {
    const deadline = Date.now() + 10_000;
    while (true) {
      try {
        const health = await fetch(`${url}/global/health`);
        if (health.ok) break;
      } catch {
        // The server has not bound yet.
      }
      if (Date.now() > deadline) throw new Error(`OpenCode server did not start\nstdout:\n${stdout}\nstderr:\n${stderr}`);
      await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    }
    const sessionResponse = await fetch(`${url}/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: "ACS direct shell probe" }),
    });
    if (!sessionResponse.ok) throw new Error(`session creation failed: ${sessionResponse.status} ${await sessionResponse.text()}`);
    const session = await sessionResponse.json() as JsonObject;
    if (typeof session.id !== "string") throw new Error(`session response has no id: ${JSON.stringify(session)}`);
    const shellResponse = await fetch(`${url}/session/${session.id}/shell`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agent: "build",
        model: { providerID: "acs-e2e", modelID: "acs-e2e-model" },
        command,
      }),
    });
    const response = await shellResponse.text();
    if (!shellResponse.ok) throw new Error(`direct shell failed: ${shellResponse.status} ${response}`);
    return { response, stdout, stderr };
  } finally {
    child.kill("SIGTERM");
    await new Promise<void>((resolveExit) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        resolveExit();
      }, 2_000);
      child.once("close", () => {
        clearTimeout(timer);
        resolveExit();
      });
    });
  }
}

describe("real OpenCode 1.18.20 runtime enforcement", () => {
  let guardianServer: ListeningServer | undefined;
  let modelServer: ListeningServer | undefined;
  const directories = new Set<string>();
  const guardian = createGuardian((request) => {
    if (request.method !== "steps/toolCallRequest") return {};
    const command = argument(request, "command");
    if (JSON.stringify(request.params.payload.arguments).includes("acs-deny")) {
      return { result: { decision: "deny", reasoning: "blocked by deterministic Guardian" } };
    }
    if (JSON.stringify(request.params.payload.arguments).includes("acs-malformed")) {
      return { raw: "not-json" };
    }
    if (JSON.stringify(request.params.payload.arguments).includes("acs-ask")) {
      return {
        result: {
          decision: "ask",
          reasoning: "remote approval required",
          ask_details: {
            approver: { type: "human", id: "remote-operator" },
            question: "Approve this action?",
            timeout_seconds: 5,
          },
        },
      };
    }
    if (JSON.stringify(request.params.payload.arguments).includes("acs-defer")) {
      return {
        result: {
          decision: "defer",
          reasoning: "dependency pending",
          defer_details: {
            reason: "pending_dependency",
            resolution_method: "timeout",
            resolution_timeout_ms: 100,
            timeout_decision: "deny",
          },
        },
      };
    }
    if (typeof command === "string" && command.includes("acs-rewrite")) {
      return {
        result: {
          decision: "modify",
          reasoning: "rewritten by deterministic Guardian",
          modifications: {
            parameter_overrides: { command: command.replace("original", "modified").replace(" # acs-rewrite", "") },
          },
        },
      };
    }
    return {};
  });

  beforeAll(async () => {
    expect(await installedOpenCodeVersion()).toBe(OPENCODE_VERSION);
    guardianServer = await listen(createServer(async (request, response) => {
      const result = await guardian.fetch("http://guardian.invalid/", { method: "POST", body: await bodyOf(request) });
      response.writeHead(result.status, Object.fromEntries(result.headers.entries()));
      response.end(Buffer.from(await result.arrayBuffer()));
    }));
    modelServer = await listen(createServer(async (request, response) => {
      const body = JSON.parse(await bodyOf(request)) as JsonObject;
      const prompt = promptText(body.messages);
      sendModelResponse(response, hasToolResult(body.messages) ? undefined : fixtureToolCalls(prompt));
    }));
  });

  afterAll(async () => {
    await Promise.all([
      ...(guardianServer ? [close(guardianServer.server)] : []),
      ...(modelServer ? [close(modelServer.server)] : []),
    ]);
  });

  afterEach(async () => {
    await Promise.all([...directories].map((directory) => rm(directory, { recursive: true, force: true })));
    directories.clear();
  });

  async function temporary(prefix: string): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), prefix));
    directories.add(directory);
    return directory;
  }

  it("loads the plugin and allows an actual Bash side effect", async () => {
    const base = await temporary("opencode-acs-allow-");
    const target = join(base, "allowed.txt");
    const result = await runOpenCode(base, guardianServer!.url, modelServer!.url, `printf 'allowed' > ${JSON.stringify(target)}`);
    try {
      await access(target);
    } catch {
      throw new Error(`allowed side effect missing\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\naudit:\n${JSON.stringify(result.audit, null, 2)}`);
    }
    expect(await readFile(target, "utf8")).toBe("allowed");
    expect(result.audit.some((event) => event.event === "acs_decision" && event.method === "steps/toolCallRequest")).toBe(true);
  });

  it("denies an actual Bash side effect before execution", async () => {
    const base = await temporary("opencode-acs-deny-");
    const target = join(base, "denied.txt");
    const offset = guardian.requests.length;
    const result = await runOpenCode(base, guardianServer!.url, modelServer!.url, `printf 'denied' > ${JSON.stringify(target)} # acs-deny`);
    await expect(access(target)).rejects.toMatchObject({ code: "ENOENT" });
    const observed = guardian.requests.slice(offset).some((request) => request.method === "steps/toolCallRequest" && String(argument(request, "command")).includes("acs-deny"));
    if (!observed) {
      throw new Error(`Guardian did not observe denied tool request\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\naudit:\n${JSON.stringify(result.audit, null, 2)}`);
    }
  });

  it("executes Guardian-modified Bash arguments on OpenCode 1.18.20", async () => {
    const base = await temporary("opencode-acs-modify-");
    const target = join(base, "modified.txt");
    const result = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      `printf 'original' > ${JSON.stringify(target)} # acs-rewrite`,
      true,
    );
    try {
      expect(await readFile(target, "utf8")).toBe("modified");
    } catch (error) {
      throw new Error(`OpenCode did not execute modified arguments: ${String(error)}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\naudit:\n${JSON.stringify(result.audit, null, 2)}`);
    }
  });

  it("allows write and observes its real result", async () => {
    const base = await temporary("opencode-acs-write-");
    const target = join(base, "written.txt");
    const result = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      toolPrompt("write", { filePath: target, content: "written" }),
    );
    expect(await readFile(target, "utf8")).toBe("written");
    expect(result.audit.some((event) => event.method === "steps/toolCallResult")).toBe(true);
  });

  it("denies read before file content reaches the model", async () => {
    const base = await temporary("opencode-acs-read-deny-");
    const target = join(base, "secret-acs-deny.txt");
    await writeFile(target, "fixture-secret-value");
    const result = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      toolPrompt("read", { filePath: target }),
    );
    expect(result.stdout).not.toContain("fixture-secret-value");
    expect(result.stdout).toContain("ACS denied read");
  });

  it("denies edit before it changes a file", async () => {
    const base = await temporary("opencode-acs-edit-deny-");
    const target = join(base, "edit.txt");
    await writeFile(target, "original");
    await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      toolPrompt("edit", { filePath: target, oldString: "original", newString: "acs-deny" }),
    );
    expect(await readFile(target, "utf8")).toBe("original");
  });

  it("denies apply_patch before it creates a file", async () => {
    const base = await temporary("opencode-acs-patch-deny-");
    const target = join(base, "workspace", "acs-deny-created.txt");
    await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      toolPrompt("apply_patch", { patchText: "*** Begin Patch\n*** Add File: acs-deny-created.txt\n+blocked\n*** End Patch" }),
    );
    await expect(access(target)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("keeps parallel tool calls and results distinctly correlated", async () => {
    const base = await temporary("opencode-acs-parallel-");
    const first = join(base, "first.txt");
    const second = join(base, "second.txt");
    const offset = guardian.requests.length;
    await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      parallelPrompt([
        { tool: "bash", callID: "call-parallel-first", args: { command: `printf first > ${JSON.stringify(first)}`, description: "first" } },
        { tool: "bash", callID: "call-parallel-second", args: { command: `printf second > ${JSON.stringify(second)}`, description: "second" } },
      ]),
    );
    expect(await readFile(first, "utf8")).toBe("first");
    expect(await readFile(second, "utf8")).toBe("second");
    const requests = guardian.requests.slice(offset);
    const calls = requests.filter((request) => request.method === "steps/toolCallRequest");
    const results = requests.filter((request) => request.method === "steps/toolCallResult");
    expect(calls).toHaveLength(2);
    expect(results).toHaveLength(2);
    expect(new Set(results.map((request) => request.params.payload.request_id_ref))).toEqual(
      new Set(calls.map((request) => request.params.request_id)),
    );
  });

  it("denies a task launch without claiming child-session coverage", async () => {
    const base = await temporary("opencode-acs-task-deny-");
    const offset = guardian.requests.length;
    const result = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      toolPrompt("task", {
        description: "deterministic task probe",
        prompt: "acs-deny: do not launch this child",
        subagent_type: "general",
      }),
    );
    const taskRequest = guardian.requests.slice(offset).find((request) =>
      request.method === "steps/toolCallRequest" && request.params.payload.tool
        && (request.params.payload.tool as JsonObject).name === "task");
    expect(taskRequest).toBeDefined();
    expect(result.stdout).toContain("ACS denied task");
  });

  it("records that the direct server shell bypasses the model-tool hook", async () => {
    const base = await temporary("opencode-acs-direct-shell-");
    const target = join(base, "direct-shell.txt");
    const offset = guardian.requests.length;
    const run = await runDirectServerShell(
      base,
      guardianServer!.url,
      modelServer!.url,
      `printf direct > ${JSON.stringify(target)} # acs-deny`,
    );
    const toolRequests = guardian.requests.slice(offset).filter((request) => request.method === "steps/toolCallRequest");
    expect(await readFile(target, "utf8"), `server response: ${run.response}\nstderr: ${run.stderr}`).toBe("direct");
    expect(toolRequests).toHaveLength(0);
  });

  it("intercepts and denies a plugin-defined custom tool with complete arguments", async () => {
    const base = await temporary("opencode-acs-custom-deny-");
    const target = join(base, "custom-acs-deny.txt");
    const offset = guardian.requests.length;
    const run = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      toolPrompt("custom_probe", { target, content: "must not be written" }),
      false,
      true,
    );
    await expect(access(target)).rejects.toMatchObject({ code: "ENOENT" });
    const request = guardian.requests.slice(offset).find((item) =>
      item.method === "steps/toolCallRequest" && (item.params.payload.tool as JsonObject | undefined)?.name === "custom_probe");
    expect(argument(request!, "target")).toBe(target);
    expect(run.stdout).toContain("ACS denied custom_probe");
  });

  it("intercepts and denies an MCP tool with complete arguments", async () => {
    const base = await temporary("opencode-acs-mcp-deny-");
    const target = join(base, "mcp-acs-deny.txt");
    const offset = guardian.requests.length;
    const run = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      toolPrompt("probe_write_file", { target, content: "must not be written" }),
      false,
      false,
      true,
    );
    await expect(access(target)).rejects.toMatchObject({ code: "ENOENT" });
    const request = guardian.requests.slice(offset).find((item) =>
      item.method === "steps/toolCallRequest" && (item.params.payload.tool as JsonObject | undefined)?.name === "probe_write_file");
    if (!request) throw new Error(`MCP tool did not reach ACS hook\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`);
    expect(argument(request, "target")).toBe(target);
    expect(run.stdout).toContain("ACS denied probe_write_file");
  });

  it("fails closed on malformed Guardian output", async () => {
    const base = await temporary("opencode-acs-malformed-");
    const target = join(base, "malformed.txt");
    const run = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      `printf malformed > ${JSON.stringify(target)} # acs-malformed`,
    );
    await expect(access(target)).rejects.toMatchObject({ code: "ENOENT" });
    expect(run.stdout).toContain("ACS decision failure");
  });

  it.each(["acs-ask", "acs-defer"])("fails closed on unsupported %s escalation", async (marker) => {
    const base = await temporary(`opencode-${marker}-`);
    const target = join(base, `${marker}.txt`);
    const run = await runOpenCode(
      base,
      guardianServer!.url,
      modelServer!.url,
      `printf blocked > ${JSON.stringify(target)} # ${marker}`,
    );
    await expect(access(target)).rejects.toMatchObject({ code: "ENOENT" });
    expect(run.stdout).toContain(`unsupported ${marker.slice(4).toUpperCase()}`);
  });

  it("refuses tool execution when the Guardian is unavailable at startup", async () => {
    const base = await temporary("opencode-acs-unavailable-");
    const target = join(base, "unavailable.txt");
    const run = await runOpenCode(
      base,
      "http://127.0.0.1:1",
      modelServer!.url,
      `printf unavailable > ${JSON.stringify(target)}`,
    );
    await expect(access(target)).rejects.toMatchObject({ code: "ENOENT" });
    expect(run.audit.some((event) => event.event === "acs_startup_refused")).toBe(true);
  });

  const remoteBaseUrl = process.env.ACS_REMOTE_TEST_URL;
  const remoteKey = process.env.ACS_GUARDIAN_HMAC_KEY;
  const remoteKeyId = process.env.ACS_GUARDIAN_KEY_ID;
  it.skipIf(!remoteBaseUrl || !remoteKey || !remoteKeyId)("uses a remotely issued capability at the protected resource", async () => {
    const base = await temporary("opencode-acs-remote-protected-");
    const value = `allowed-${randomUUID()}`;
    const allowRun = await runOpenCode(
      base,
      `${remoteBaseUrl}/acs`,
      modelServer!.url,
      toolPrompt(PROTECTED_TOOL, { value }),
      false,
      false,
      false,
      `${remoteBaseUrl}/protected`,
      remoteKey!,
      remoteKeyId!,
    );
    expect(allowRun.stdout).toContain("Protected append accepted:");
    expect(allowRun.audit.some((event) => event.event === "acs_tool_completed" && event.tool === PROTECTED_TOOL)).toBe(true);

    const deniedBase = await temporary("opencode-acs-remote-denied-");
    const deniedRun = await runOpenCode(
      deniedBase,
      `${remoteBaseUrl}/acs`,
      modelServer!.url,
      toolPrompt(PROTECTED_TOOL, { value: `deny-${randomUUID()}` }),
      false,
      false,
      false,
      `${remoteBaseUrl}/protected`,
      remoteKey!,
      remoteKeyId!,
    );
    expect(deniedRun.stdout).toContain(`ACS denied ${PROTECTED_TOOL}`);

    const noCapability = await fetch(`${remoteBaseUrl}/protected`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: `direct-${randomUUID()}` }),
    });
    expect(noCapability.status).toBe(401);

    const keyEnvironment = "ACS_REMOTE_PROTOCOL_TEST_KEY";
    process.env[keyEnvironment] = remoteKey!;
    try {
      const directClient = new AcsClient(parseConfig({
        mode: "enforce",
        startupPosture: "refuse",
        guardian: {
          url: `${remoteBaseUrl}/acs`,
          hmacKeyEnv: keyEnvironment,
          keyId: remoteKeyId,
          connectTimeoutMs: 5_000,
        },
      }, base));
      const state = newSessionState(`remote-protocol-${randomUUID()}`);
      state.handshake = await directClient.handshake(state);
      state.guarded = true;
      await directClient.request(state, "steps/sessionStart", {});
      const replayValue = `replay-${randomUUID()}`;
      const decision = await directClient.request(
        state,
        "steps/toolCallRequest",
        toolCallPayload(PROTECTED_TOOL, { value: replayValue }),
      );
      const capability = decision.payload?.capability;
      expect(typeof capability).toBe("string");
      const first = await fetch(`${remoteBaseUrl}/protected`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ capability, value: replayValue }),
      });
      expect(first.status).toBe(201);
      const replay = await fetch(`${remoteBaseUrl}/protected`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ capability, value: replayValue }),
      });
      expect(replay.status).toBe(409);
    } finally {
      delete process.env[keyEnvironment];
    }
  }, 40_000);
});
