import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AcsPlugin } from "../src/index.js";
import { createGuardian, TEST_KEY } from "./guardian-helper.js";

const temporaryDirectories = new Set<string>();

afterEach(async () => {
  delete process.env.OPENCODE_ACS_CONFIG;
  delete process.env.OPENCODE_ACS_PLUGIN_TEST_KEY;
  vi.unstubAllGlobals();
  await Promise.all([...temporaryDirectories].map((directory) => rm(directory, { recursive: true, force: true })));
  temporaryDirectories.clear();
});

describe("OpenCode plugin lifecycle", () => {
  it("sends a schema-valid sessionEnd and reinitializes a deleted host session", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    await writeFile(configPath, JSON.stringify({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: {
        url: "http://127.0.0.1:8787/",
        hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY",
        keyId: "test-key",
      },
    }));
    process.env.OPENCODE_ACS_CONFIG = configPath;
    process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);

    const hooks = await AcsPlugin({
      directory,
      client: { app: { log: vi.fn(async () => undefined) } },
    } as never);
    if (!hooks.event) throw new Error("plugin did not register an event hook");

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_host" } } },
    } as never);
    await hooks.event({
      event: { type: "session.deleted", properties: { info: { id: "ses_host" } } },
    } as never);
    const ended = guardian.requests.find((request) => request.method === "steps/sessionEnd");
    expect(ended?.params.payload).toEqual({ reason: "abandoned" });

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_host" } } },
    } as never);
    expect(guardian.requests.filter((request) => request.method === "handshake/hello")).toHaveLength(2);
  });

  it("gates a fresh task as subagentStart and binds the created child session", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-subagent-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    await writeFile(configPath, JSON.stringify({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: {
        url: "http://127.0.0.1:8787/",
        hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY",
        keyId: "test-key",
      },
    }));
    process.env.OPENCODE_ACS_CONFIG = configPath;
    process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);

    const hooks = await AcsPlugin({
      directory,
      client: { app: { log: vi.fn(async () => undefined) } },
    } as never);
    if (!hooks.event || !hooks["tool.execute.before"] || !hooks["tool.execute.after"]) {
      throw new Error("plugin did not register the required lifecycle hooks");
    }

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_parent", title: "parent" } } },
    } as never);
    const args = {
      description: "deterministic child",
      prompt: "inspect the repository",
      subagent_type: "general",
    };
    await hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_parent", callID: "call_task" },
      { args },
    );
    await expect(hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_parent", callID: "call_parallel" },
      { args: { ...args, description: "ambiguous child" } },
    )).rejects.toThrow("cannot be correlated to a unique OpenCode child session");

    const start = guardian.requests.find((request) => request.method === "steps/subagentStart");
    expect(start).toBeDefined();
    expect(start?.params.payload.parent_step_id).toBe(start?.params.request_id);
    const childAcsID = start?.params.payload.subagent_session_id;
    expect(childAcsID).toMatch(/^[0-9a-f-]{36}$/);

    await hooks.event({
      event: {
        type: "session.created",
        properties: {
          info: {
            id: "ses_child",
            parentID: "ses_parent",
            title: "deterministic child (@general subagent)",
          },
        },
      },
    } as never);
    const childStart = guardian.requests.find((request) =>
      request.method === "steps/sessionStart" && request.params.metadata.session_id === childAcsID);
    expect(childStart).toBeDefined();

    await hooks["tool.execute.after"](
      { tool: "task", sessionID: "ses_parent", callID: "call_task" },
      {
        title: "deterministic child",
        output: "done",
        metadata: { parentSessionId: "ses_parent", sessionId: "ses_child" },
      },
    );
    const stop = guardian.requests.find((request) => request.method === "steps/subagentStop");
    expect(stop?.params.payload).toEqual({ subagent_session_id: childAcsID, outcome: "completed" });
    expect(guardian.requests.some((request) =>
      request.method === "steps/toolCallRequest"
      && (request.params.payload.tool as Record<string, unknown> | undefined)?.name === "task")).toBe(false);
  });

  it("governs skill loading as a generic tool call without fabricating skill lifecycle evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-skill-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    await writeFile(configPath, JSON.stringify({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: {
        url: "http://127.0.0.1:8787/",
        hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY",
        keyId: "test-key",
      },
    }));
    process.env.OPENCODE_ACS_CONFIG = configPath;
    process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);

    const hooks = await AcsPlugin({
      directory,
      client: { app: { log: vi.fn(async () => undefined) } },
    } as never);
    if (!hooks.event || !hooks["tool.execute.before"] || !hooks["tool.execute.after"]) {
      throw new Error("plugin did not register the required lifecycle hooks");
    }

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_skill" } } },
    } as never);
    await hooks["tool.execute.before"](
      { tool: "skill", sessionID: "ses_skill", callID: "call_skill" },
      { args: { name: "release-notes" } },
    );
    await hooks["tool.execute.after"](
      { tool: "skill", sessionID: "ses_skill", callID: "call_skill" },
      {
        title: "Loaded skill: release-notes",
        output: "<skill_content name=\"release-notes\">instructions</skill_content>",
        metadata: { name: "release-notes", dir: "/example/skills/release-notes" },
      },
    );

    const request = guardian.requests.find((candidate) =>
      candidate.method === "steps/toolCallRequest"
      && (candidate.params.payload.tool as Record<string, unknown> | undefined)?.name === "skill");
    expect(request?.params.payload.arguments).toEqual({ name: { value: "release-notes" } });
    expect(guardian.requests.some((candidate) => candidate.method === "steps/toolCallResult"
      && candidate.params.payload.request_id_ref === request?.params.request_id)).toBe(true);
    expect(guardian.requests.some((candidate) => [
      "steps/skillRegister",
      "steps/skillLoad",
      "steps/skillUnload",
    ].includes(candidate.method))).toBe(false);
  });
});
