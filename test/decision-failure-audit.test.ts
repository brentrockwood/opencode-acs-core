import * as mapper from "../src/mapper.js";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditSink } from "../src/audit.js";
import { AcsClient } from "../src/client.js";
import { parseConfig } from "../src/config.js";
import { newSessionState, toolCallPayload } from "../src/mapper.js";
import { createGuardian, TEST_KEY } from "./guardian-helper.js";

const directories: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete process.env.ACS_AUDIT_TEST_KEY;
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function client() {
  process.env.ACS_AUDIT_TEST_KEY = TEST_KEY;
  return new AcsClient(parseConfig({
    mode: "enforce", startupPosture: "refuse",
    guardian: { url: "http://127.0.0.1:8787/", hmacKeyEnv: "ACS_AUDIT_TEST_KEY", keyId: "test-key" },
  }, "/work"));
}

async function temporaryDirectory() {
  const directory = await mkdtemp(join(tmpdir(), "acs-audit-"));
  directories.push(directory);
  return directory;
}

describe("decision failure audit", () => {
  it("does not leak Guardian error text or host-handler messages through default audit", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const secret = "synthetic-sensitive-error-sentinel";
    const guardian = createGuardian(() => ({ error: { code: -32020, message: secret } }));
    vi.stubGlobal("fetch", guardian.fetch);
    await expect(client().request(newSessionState("host-session"), "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))).rejects.toThrow(secret);
    const path = await temporaryDirectory();
    await new AuditSink({ path, includePayloads: true }).write({ event: "acs_fail_open", message: secret, payload: { secret } });
    expect(JSON.stringify(stderr.mock.calls)).not.toContain(secret);
    const file = join(path, "audit.jsonl");
    await new AuditSink({ path: file, includePayloads: false }).write({ event: "acs_fail_open", message: secret });
    expect(await readFile(file, "utf8")).not.toContain(secret);
  });

  it("snapshots session-end counts after preceding queued failures and counts failed shutdown locally", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest"
      ? { delayMs: 20, error: { code: -32020, message: "failed" } }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const acs = client();
    const state = newSessionState("host-session");
    const failed = acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }));
    const checked = expect(failed).rejects.toMatchObject({ kind: "guardian_error" });
    const ended = acs.request(state, "steps/sessionEnd", { reason: "completed" });
    await checked;
    await ended;
    expect(guardian.requests.at(-1)?.params.payload.summary).toEqual({ decision_failures: { guardian_error: 1 } });
    vi.stubGlobal("fetch", async () => { throw new TypeError("offline"); });
    await expect(acs.request(state, "steps/sessionEnd", { reason: "completed" })).rejects.toThrow();
    expect(state.decisionFailures).toEqual({ guardian_error: 1, unreachable: 1 });
  });

  it("releases the session queue when request construction throws", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);
    const build = vi.spyOn(mapper, "buildRequest").mockImplementationOnce(() => { throw new Error("nonce generation failed"); });
    const acs = client();
    const state = newSessionState("host-session");
    await expect(acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))).rejects.toThrow();
    build.mockRestore();
    await expect(acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))).resolves.toMatchObject({ decision: "allow" });
    expect(state.decisionFailures).toEqual({ observed_agent_error: 1 });
  });

  it.each(["timeout", "http", "oversize"])("counts %s exactly once", async (kind) => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const guardian = createGuardian(() => kind === "timeout" ? { delayMs: 50 } : {});
    vi.stubGlobal("fetch", kind === "http" ? async () => new Response("unavailable", { status: 503 })
      : kind === "oversize" ? async () => new Response("x".repeat(1_048_577)) : guardian.fetch);
    const state = newSessionState("host-session");
    await expect(client().request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }), 10)).rejects.toThrow();
    const classification = kind === "timeout" ? "timeout" : kind === "http" ? "guardian_error" : "malformed_response";
    expect(state.decisionFailures).toEqual({ [classification]: 1 });
    expect(stderr).toHaveBeenCalledTimes(1);
  });


  it.each(["proceed", "deny"] as const)("records and counts each failure once under %s", async (posture) => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    let failure = "json";
    const guardian = createGuardian((request) => {
      if (request.method === "handshake/hello") return {};
      if (failure === "json") return { raw: "{" };
      if (failure === "error") return { error: { code: -32020, message: "guardian failed" } };
      return {};
    });
    const fetch = guardian.fetch;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      if (failure === "transport") throw new TypeError("offline");
      const response = await fetch(input, init);
      if (["signature", "schema", "correlation"].includes(failure)) {
        const value = await response.json();
        if (failure === "signature") value.result.signature.value = "invalid";
        if (failure === "schema") value.result.decision = "invalid";
        if (failure === "correlation") value.id = "wrong-id";
        return Response.json(value);
      }
      return response;
    });
    const acs = client();
    const state = newSessionState("host-session");
    state.handshake = await acs.handshake(state);
    state.handshake.on_decision_failure = posture;
    for (const kind of ["json", "schema", "correlation", "signature", "error", "transport"]) {
      failure = kind;
      await expect(acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))).rejects.toThrow();
    }
    expect(state.decisionFailures).toEqual({ malformed_response: 3, signature_invalid: 1, guardian_error: 1, unreachable: 1 });
    const records = stderr.mock.calls.map(([line]) => JSON.parse(String(line)));
    expect(records).toHaveLength(6);
    expect(records.every((record) => record.event === "acs_decision_failure" && record.posture === posture && record.request_id)).toBe(true);
    expect(records.map((record) => record.disposition)).toEqual(["integrity", "integrity", "integrity", "integrity", "refusal", "availability"]);
    expect(records[4]).toMatchObject({ error_code: -32020 });
    expect(acs.failurePosture(state)).toBe(posture);
    failure = "allow";
    await acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }));
    expect(stderr).toHaveBeenCalledTimes(6);
  });

  it("records handshake negotiation failures and keeps counters session-local", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const guardian = createGuardian(() => ({ methodsEvaluated: ["not-advertised"] }));
    vi.stubGlobal("fetch", guardian.fetch);
    const acs = client();
    const state = newSessionState("host-session");
    await expect(acs.handshake(state)).rejects.toMatchObject({ kind: "correlation" });
    expect(state.decisionFailures).toEqual({ handshake_failure: 1 });
    expect((newSessionState("host-session")).decisionFailures).toBeUndefined();
    expect(JSON.parse(String(stderr.mock.calls[0]?.[0]))).toMatchObject({ failure_class: "handshake_failure", posture: "refuse" });
  });

  it("records invalid outgoing payloads without contacting the Guardian", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const state = newSessionState("host-session");
    await expect(client().request(state, "steps/toolCallRequest", {})).rejects.toMatchObject({ kind: "invalid_schema" });
    expect(fetch).not.toHaveBeenCalled();
    expect(state.decisionFailures).toEqual({ observed_agent_error: 1 });
    expect(stderr).toHaveBeenCalledTimes(1);
  });

  it("writes configured audit files without duplicating stderr, omitting payloads", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const path = join(await temporaryDirectory(), "audit.jsonl");
    await new AuditSink({ path, includePayloads: false }).write({ event: "acs_decision_failure", payload: { secret: "hidden" } });
    expect(JSON.parse(await readFile(path, "utf8"))).toMatchObject({ event: "acs_decision_failure", payload: "[omitted]" });
    expect(stderr).not.toHaveBeenCalled();
  });

  it("falls back to stderr when the configured audit destination cannot be written", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const path = await temporaryDirectory();
    await new AuditSink({ path, includePayloads: false }).write({ event: "acs_decision_failure", failure_class: "timeout" });
    expect(JSON.parse(String(stderr.mock.calls[0]?.[0]))).toMatchObject({ event: "acs_decision_failure", failure_class: "timeout" });
  });
});
