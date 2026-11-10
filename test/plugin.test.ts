import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

async function configuredPlugin(
  prefix: string,
  startupPosture: "proceed" | "refuse",
  mode: "observe" | "enforce" = "enforce",
): Promise<{ directory: string; auditPath: string; hooks: Awaited<ReturnType<typeof AcsPlugin>> }> {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.add(directory);
  const configPath = join(directory, "acs.json");
  const auditPath = join(directory, "audit.jsonl");
  await writeFile(configPath, JSON.stringify({
    mode,
    startupPosture,
    guardian: { url: "http://127.0.0.1:8787/", hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY", keyId: "test-key" },
    audit: { path: auditPath },
  }));
  process.env.OPENCODE_ACS_CONFIG = configPath;
  process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
  const hooks = await AcsPlugin({ directory, client: { app: { log: vi.fn(async () => undefined) } } } as never);
  return { directory, auditPath, hooks };
}

async function auditRecords(auditPath: string): Promise<Array<Record<string, unknown>>> {
  return (await readFile(auditPath, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("refusal, outage and integrity separation", () => {
  it.each([
    { name: "a signed SESSION_REFUSED error", reply: { error: { code: -32000, message: "session refused by policy" } }, disposition: "refusal", code: -32000 },
    { name: "a signed UNSUPPORTED_VERSION error", reply: { error: { code: -32001, message: "no common version" } }, disposition: "refusal", code: -32001 },
    { name: "an HTTP 401 without a body", reply: { status: 401, raw: "" }, disposition: "refusal" },
    { name: "an unverifiable ServerHello", reply: { unsignedHello: true }, disposition: "integrity" },
    { name: "malformed handshake JSON", reply: { raw: "{broken" }, disposition: "integrity" },
  ])("refuses the whole session on $name even when startup posture is proceed", async ({ reply, disposition, code }) => {
    const guardian = createGuardian((request) => request.method === "handshake/hello" ? reply : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const { auditPath, hooks } = await configuredPlugin("opencode-acs-refused-", "proceed");
    await hooks.event!({ event: { type: "session.created", properties: { info: { id: "ses_refused" } } } } as never);
    await expect(hooks["tool.execute.before"]!(
      { tool: "bash", sessionID: "ses_refused", callID: "one" }, { args: { command: "anything" } },
    )).rejects.toThrow(/refused the session|failed verification/);
    await expect(hooks["tool.execute.before"]!(
      { tool: "task", sessionID: "ses_refused", callID: "two" }, { args: { description: "child", prompt: "x", subagent_type: "general" } },
    )).rejects.toThrow(/refused the session|failed verification/);
    expect(guardian.requests.filter((request) => request.method !== "handshake/hello")).toHaveLength(0);
    const audit = await auditRecords(auditPath);
    const refused = audit.filter((record) => record.event === "acs_startup_refused");
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ disposition, ...(code ? { error_code: code } : {}) });
    expect(audit.some((record) => record.event === "acs_session_unguarded")).toBe(false);
    expect(audit.filter((record) => record.event === "acs_tool_blocked")).toHaveLength(2);
  });

  it.each([
    { name: "a refused connection", reply: undefined, failureKind: "transport" },
    { name: "an HTTP 503 without a body", reply: { status: 503, raw: "unavailable" }, failureKind: "http" },
    { name: "a signed internal error", reply: { error: { code: -32603, message: "internal" } }, failureKind: "guardian_error" },
  ])("starts unguarded on $name only because startup posture is proceed", async ({ reply, failureKind }) => {
    const guardian = createGuardian((request) => request.method === "handshake/hello" && reply ? reply : {});
    vi.stubGlobal("fetch", reply ? guardian.fetch : async () => { throw new TypeError("connect ECONNREFUSED"); });
    const { auditPath, hooks } = await configuredPlugin("opencode-acs-unguarded-", "proceed");
    await expect(hooks["tool.execute.before"]!(
      { tool: "bash", sessionID: "ses_unguarded", callID: "one" }, { args: { command: "anything" } },
    )).resolves.toBeUndefined();
    const audit = await auditRecords(auditPath);
    expect(audit.filter((record) => record.event === "acs_session_unguarded")).toEqual([
      expect.objectContaining({ disposition: "availability", failure_kind: failureKind }),
    ]);
    expect(audit.some((record) => record.event === "acs_startup_refused")).toBe(false);
  });

  it("still follows refuse for an outage at startup", async () => {
    vi.stubGlobal("fetch", async () => { throw new TypeError("connect ECONNREFUSED"); });
    const { hooks } = await configuredPlugin("opencode-acs-refuse-outage-", "refuse");
    await expect(hooks["tool.execute.before"]!(
      { tool: "bash", sessionID: "ses_outage", callID: "one" }, { args: { command: "anything" } },
    )).rejects.toThrow("startup posture is refuse");
  });

  it("blocks refusals and integrity failures under a negotiated proceed posture, and fails open only on outages", async () => {
    let failure = "none";
    const guardian = createGuardian((request) => {
      if (request.method === "handshake/hello") return { onDecisionFailure: "proceed" };
      if (request.method !== "steps/toolCallRequest" && request.method !== "steps/subagentStart") return {};
      switch (failure) {
        case "refused": return { error: { code: -32000, message: "refused" } };
        case "refused-on-403": return { status: 403, error: { code: -32000, message: "refused" } };
        case "http-403": return { status: 403, raw: "" };
        case "malformed": return { raw: "{" };
        case "internal": return { error: { code: -32603, message: "internal" } };
        case "http-503": return { status: 503, raw: "unavailable" };
        case "timeout": return { delayMs: 1_200 };
        default: return {};
      }
    });
    const signedFetch = guardian.fetch;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      if (failure === "offline") throw new TypeError("offline");
      const response = await signedFetch(input, init);
      const request = JSON.parse(String(init?.body)) as { method?: string };
      if (request.method !== "steps/toolCallRequest") return response;
      if (!["signature", "key", "id", "request_id", "allow-shape"].includes(failure)) return response;
      const value = await response.json();
      if (failure === "signature") value.result.signature.value = "AAAA";
      if (failure === "key") value.result.signature.key_id = "other-key";
      if (failure === "id") value.id = "wrong-id";
      if (failure === "request_id") value.result.request_id = "00000000-0000-4000-8000-000000000000";
      if (failure === "allow-shape") value.result.decision = "allowed";
      return Response.json(value);
    });
    const { auditPath, hooks } = await configuredPlugin("opencode-acs-matrix-", "proceed");
    await hooks.event!({ event: { type: "session.created", properties: { info: { id: "ses_matrix" } } } } as never);

    const blocking = ["refused", "refused-on-403", "http-403", "malformed", "signature", "key", "id", "request_id", "allow-shape"];
    const open = ["internal", "http-503", "timeout", "offline"];
    for (const kind of [...blocking, ...open]) {
      failure = kind;
      const action = hooks["tool.execute.before"]!({ tool: "bash", sessionID: "ses_matrix", callID: kind }, { args: { command: kind } });
      if (blocking.includes(kind)) await expect(action, kind).rejects.toThrow("ACS decision failure");
      else await expect(action, kind).resolves.toBeUndefined();
    }
    failure = "refused";
    await expect(hooks["tool.execute.before"]!(
      { tool: "task", sessionID: "ses_matrix", callID: "task" }, { args: { description: "child", prompt: "x", subagent_type: "general" } },
    )).rejects.toThrow("ACS decision failure");
    failure = "none";
    await hooks.event!({ event: { type: "session.deleted", properties: { info: { id: "ses_matrix" } } } } as never);

    const audit = await auditRecords(auditPath);
    const failures = audit.filter((record) => record.event === "acs_decision_failure");
    expect(failures).toHaveLength(blocking.length + open.length + 1);
    expect(failures.every((record) => record.posture === "proceed" && typeof record.disposition === "string")).toBe(true);
    expect(failures.filter((record) => record.disposition === "availability")).toHaveLength(open.length);
    expect(audit.filter((record) => record.event === "acs_fail_open")).toHaveLength(open.length);
    expect(audit.filter((record) => record.event === "acs_tool_blocked")).toHaveLength(blocking.length + 1);
    const summary = guardian.requests.at(-1)?.params.payload.summary as { decision_failures: Record<string, number> };
    expect(Object.values(summary.decision_failures).reduce((total, count) => total + count, 0)).toBe(blocking.length + open.length + 1);
  }, 15_000);

  it("never blocks on a refusal in observe mode", async () => {
    const guardian = createGuardian((request) => request.method === "handshake/hello"
      ? { error: { code: -32000, message: "session refused by policy" } }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const { auditPath, hooks } = await configuredPlugin("opencode-acs-observe-refused-", "proceed", "observe");
    await expect(hooks["tool.execute.before"]!(
      { tool: "bash", sessionID: "ses_observe", callID: "one" }, { args: { command: "anything" } },
    )).resolves.toBeUndefined();
    const audit = await auditRecords(auditPath);
    expect(audit.filter((record) => record.event === "acs_session_unguarded")).toEqual([
      expect.objectContaining({ disposition: "refusal", error_code: -32000 }),
    ]);
  });
});

describe("OpenCode plugin lifecycle", () => {
  it.each([
    { posture: "deny" as const, fails: false, blocked: false },
    { posture: "proceed" as const, fails: true, blocked: false },
    { posture: "deny" as const, fails: true, blocked: true },
  ])("preserves enforcement with an unwritable audit file: %j", async ({ posture, fails, blocked }) => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-audit-posture-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    await writeFile(configPath, JSON.stringify({
      mode: "enforce", startupPosture: "refuse",
      guardian: { url: "http://127.0.0.1:8787/", hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY", keyId: "test-key" },
      audit: { path: directory },
    }));
    process.env.OPENCODE_ACS_CONFIG = configPath;
    process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "handshake/hello"
      ? { onDecisionFailure: posture }
      : fails && request.method === "steps/toolCallRequest" ? { error: { code: -32603, message: "internal" } } : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const hooks = await AcsPlugin({ directory, client: { app: { log: vi.fn(async () => undefined) } } } as never);
    const action = hooks["tool.execute.before"]!(
      { tool: "bash", sessionID: "ses_audit", callID: "probe" }, { args: { command: "pwd" } },
    );
    if (blocked) await expect(action).rejects.toThrow();
    else await expect(action).resolves.toBeUndefined();
    const failures = stderr.mock.calls.map(([line]) => JSON.parse(String(line))).filter((record) => record.event === "acs_decision_failure");
    expect(failures).toHaveLength(fails ? 1 : 0);
    await hooks.event!({ event: { type: "session.deleted", properties: { info: { id: "ses_audit" } } } } as never);
    expect(guardian.requests.at(-1)?.params.payload.summary).toEqual({ decision_failures: fails ? { guardian_error: 1 } : {} });
    stderr.mockRestore();
  });

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
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest" ? { raw: "{" } : {});
    vi.stubGlobal("fetch", guardian.fetch);

    const hooks = await AcsPlugin({
      directory,
      client: { app: { log: vi.fn(async () => undefined) } },
    } as never);
    if (!hooks.event) throw new Error("plugin did not register an event hook");

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_host" } } },
    } as never);
    await expect(hooks["tool.execute.before"]!(
      { tool: "bash", sessionID: "ses_host", callID: "failed" },
      { args: { command: "pwd" } },
    )).rejects.toThrow();
    await hooks.event({
      event: { type: "session.deleted", properties: { info: { id: "ses_host" } } },
    } as never);
    const ended = guardian.requests.find((request) => request.method === "steps/sessionEnd");
    expect(ended?.params.payload).toEqual({ reason: "abandoned", summary: { decision_failures: { malformed_response: 1 } } });

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_host" } } },
    } as never);
    expect(guardian.requests.filter((request) => request.method === "handshake/hello")).toHaveLength(2);
    await hooks.event({
      event: { type: "session.deleted", properties: { info: { id: "ses_host" } } },
    } as never);
    expect(guardian.requests.filter((request) => request.method === "steps/sessionEnd").at(-1)?.params.payload.summary)
      .toEqual({ decision_failures: {} });
  });

  it("skips unevaluated tool requests and omits dangling result correlation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-unevaluated-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    const auditPath = join(directory, "audit.jsonl");
    await writeFile(configPath, JSON.stringify({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: {
        url: "http://127.0.0.1:8787/",
        hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY",
        keyId: "test-key",
      },
      audit: { path: auditPath },
    }));
    process.env.OPENCODE_ACS_CONFIG = configPath;
    process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "handshake/hello"
      ? { methodsEvaluated: ["steps/sessionStart", "steps/toolCallResult"] }
      : request.method === "steps/toolCallRequest"
        ? { error: { code: -32601, message: "method not evaluated" } }
        : {});
    vi.stubGlobal("fetch", guardian.fetch);

    const hooks = await AcsPlugin({
      directory,
      client: { app: { log: vi.fn(async () => undefined) } },
    } as never);
    if (!hooks.event || !hooks["tool.execute.before"] || !hooks["tool.execute.after"]) {
      throw new Error("plugin did not register the required lifecycle hooks");
    }
    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_unevaluated" } } },
    } as never);
    await hooks["tool.execute.before"](
      { tool: "bash", sessionID: "ses_unevaluated", callID: "call_unevaluated" },
      { args: { command: "true" } },
    );
    await hooks["tool.execute.after"](
      { tool: "bash", sessionID: "ses_unevaluated", callID: "call_unevaluated" },
      { title: "true", output: "", metadata: { exit: 0 } },
    );

    expect(guardian.requests.some((request) => request.method === "steps/toolCallRequest")).toBe(false);
    const result = guardian.requests.find((request) => request.method === "steps/toolCallResult");
    expect(result).toBeDefined();
    expect(result?.params.payload.request_id_ref).toBeUndefined();
    const audit = (await readFile(auditPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(audit).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "acs_unevaluated_allow", method: "steps/toolCallRequest" }),
    ]));
  });

  it("binds a real child session when subagentStart is unevaluated without inventing a request id", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-unevaluated-subagent-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    const auditPath = join(directory, "audit.jsonl");
    await writeFile(configPath, JSON.stringify({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: {
        url: "http://127.0.0.1:8787/",
        hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY",
        keyId: "test-key",
      },
      audit: { path: auditPath },
    }));
    process.env.OPENCODE_ACS_CONFIG = configPath;
    process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "handshake/hello"
      ? { methodsEvaluated: ["steps/sessionStart", "steps/subagentStop"] }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);

    const hooks = await AcsPlugin({
      directory,
      client: { app: { log: vi.fn(async () => undefined) } },
    } as never);
    if (!hooks.event || !hooks["tool.execute.before"] || !hooks["tool.execute.after"]) {
      throw new Error("plugin did not register the required lifecycle hooks");
    }
    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_parent" } } },
    } as never);
    await hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_parent", callID: "call_task" },
      { args: { description: "child", prompt: "inspect", subagent_type: "general" } },
    );
    await hooks.event({
      event: {
        type: "session.created",
        properties: { info: { id: "ses_child", parentID: "ses_parent", title: "child (@general subagent)" } },
      },
    } as never);
    await hooks["tool.execute.after"](
      { tool: "task", sessionID: "ses_parent", callID: "call_task" },
      { title: "child", output: "done", metadata: { parentSessionId: "ses_parent", sessionId: "ses_child" } },
    );

    expect(guardian.requests.some((request) => request.method === "steps/subagentStart")).toBe(false);
    expect(guardian.requests.some((request) => request.method === "steps/subagentStop")).toBe(true);
    const audit = (await readFile(auditPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(audit).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "acs_unevaluated_allow", method: "steps/subagentStart" }),
    ]));
    const bound = audit.find((event) => event.event === "acs_subagent_session_bound");
    expect(bound).toBeDefined();
    expect(bound?.request_id).toBeUndefined();
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

  it("allows an ambiguous concurrent task in observe mode without fabricating lifecycle evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-observe-subagent-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    const auditPath = join(directory, "audit.jsonl");
    await writeFile(configPath, JSON.stringify({
      mode: "observe",
      startupPosture: "proceed",
      guardian: {
        url: "http://127.0.0.1:8787/",
        hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY",
        keyId: "test-key",
      },
      audit: { path: auditPath },
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
      event: { type: "session.created", properties: { info: { id: "ses_observe_parent" } } },
    } as never);
    await hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_observe_parent", callID: "call_first" },
      { args: { description: "first child", prompt: "first", subagent_type: "general" } },
    );
    await expect(hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_observe_parent", callID: "call_ambiguous" },
      { args: { description: "second child", prompt: "second", subagent_type: "general" } },
    )).resolves.toBeUndefined();
    await hooks["tool.execute.after"](
      { tool: "task", sessionID: "ses_observe_parent", callID: "call_ambiguous" },
      {
        title: "second child",
        output: "done",
        metadata: { parentSessionId: "ses_observe_parent", sessionId: "ses_second_child" },
      },
    );

    expect(guardian.requests.filter((request) => request.method === "steps/subagentStart")).toHaveLength(1);
    expect(guardian.requests.some((request) => request.method === "steps/toolCallResult"
      && (request.params.payload.tool as Record<string, unknown> | undefined)?.name === "task")).toBe(false);
    const audit = (await readFile(auditPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(audit).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "acs_subagent_start_unmapped", call_id: "call_ambiguous" }),
      expect.objectContaining({ event: "acs_subagent_stop_unmapped", call_id: "call_ambiguous" }),
    ]));
  });

  it("releases a task that ends in error without reaching tool.execute.after, so a later task can launch", async () => {
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);
    const { auditPath, hooks } = await configuredPlugin("opencode-acs-failed-task-", "refuse");
    await hooks.event!({ event: { type: "session.created", properties: { info: { id: "ses_parent" } } } } as never);
    await hooks["tool.execute.before"]!(
      { tool: "task", sessionID: "ses_parent", callID: "call_failed" },
      { args: { description: "child", prompt: "inspect", subagent_type: "does-not-exist" } },
    );
    // Host reports the failed launch as a tool part in state "error"; tool.execute.after never fires.
    await hooks.event!({
      event: {
        type: "message.part.updated",
        properties: {
          part: {
            id: "prt_1", sessionID: "ses_parent", messageID: "msg_1", type: "tool", callID: "call_failed", tool: "task",
            state: { status: "error", error: 'Agent not found: "does-not-exist"', input: {} },
          },
        },
      },
    } as never);
    // A later fresh task in the same parent must not be denied as a concurrent launch.
    await expect(hooks["tool.execute.before"]!(
      { tool: "task", sessionID: "ses_parent", callID: "call_second" },
      { args: { description: "child", prompt: "inspect", subagent_type: "general" } },
    )).resolves.toBeUndefined();
    await hooks.event!({
      event: { type: "session.created", properties: { info: { id: "ses_child", parentID: "ses_parent", title: "child (@general subagent)" } } },
    } as never);
    const audit = await auditRecords(auditPath);
    const failed = audit.filter((record) => record.event === "acs_subagent_launch_failed");
    expect(failed).toHaveLength(1);
    expect(failed[0]).toMatchObject({ host_session_id: "ses_parent", call_id: "call_failed" });
    expect(audit.filter((record) => record.event === "acs_subagent_session_bound")).toHaveLength(1);
    expect(audit.some((record) => record.event === "acs_tool_blocked")).toBe(false);
    expect(guardian.requests.filter((request) => request.method === "steps/subagentStart")).toHaveLength(2);
  });

  it("clears an unmatched completed task so a later child can be correlated", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-unmatched-subagent-"));
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
      event: { type: "session.created", properties: { info: { id: "ses_parent" } } },
    } as never);
    await hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_parent", callID: "call_unmatched" },
      { args: { description: "unmatched child", prompt: "first", subagent_type: "general" } },
    );
    await hooks["tool.execute.after"](
      { tool: "task", sessionID: "ses_parent", callID: "call_unmatched" },
      { title: "unmatched child", output: "done", metadata: {} },
    );

    await expect(hooks["tool.execute.before"](
      { tool: "task", sessionID: "ses_parent", callID: "call_later" },
      { args: { description: "later child", prompt: "second", subagent_type: "general" } },
    )).resolves.toBeUndefined();
    expect(guardian.requests.filter((request) => request.method === "steps/subagentStart")).toHaveLength(2);
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
