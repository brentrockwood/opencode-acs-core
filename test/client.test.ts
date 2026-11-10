import { afterEach, describe, expect, it, vi } from "vitest";
import { AcsClient } from "../src/client.js";
import type { AcsConfig } from "../src/config.js";
import { failureDisposition } from "../src/failure.js";
import { newSessionState, toolCallPayload } from "../src/mapper.js";
import { AcsClientError, type ServerHello } from "../src/types.js";
import { createGuardian, TEST_KEY, TEST_KEY_ID } from "./guardian-helper.js";

function config(timeout = 100, url = "http://127.0.0.1:8787/"): AcsConfig {
  return {
    mode: "enforce",
    startupPosture: "refuse",
    decisionFailurePosture: "deny",
    enableModify: false,
    guardian: {
      url,
      connectTimeoutMs: timeout,
      maxResponseBytes: 1024 * 1024,
      hmacKeyEnv: "OPENCODE_ACS_CLIENT_TEST_KEY",
      keyId: TEST_KEY_ID,
    },
    audit: { includePayloads: false },
    agent: { id: "opencode", environment: "development" },
  };
}

describe("Guardian client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.OPENCODE_ACS_CLIENT_TEST_KEY;
  });

  it.each([
    { local: "proceed", negotiated: "proceed", effective: "proceed" },
    { local: "proceed", negotiated: undefined, effective: "proceed" },
    { local: "proceed", negotiated: "deny", effective: "deny" },
    { local: "deny", negotiated: "proceed", effective: "deny" },
    { local: "deny", negotiated: undefined, effective: "deny" },
    { local: "deny", negotiated: "deny", effective: "deny" },
  ] as const)("lets the Guardian tighten the local decision-failure posture but never loosen it: %j", async ({ local, negotiated, effective }) => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian(() => ({}));
    vi.stubGlobal("fetch", guardian.fetch);
    const acs = new AcsClient({ ...config(), decisionFailurePosture: local });
    const state = newSessionState("tighten-only");
    state.handshake = await acs.handshake(state);
    if (negotiated) state.handshake.on_decision_failure = negotiated;
    else delete state.handshake.on_decision_failure;
    expect(acs.failurePosture(state)).toBe(effective);
  });

  it("accepts a signed direct ServerHello over HTTP and verifies a signed tool decision", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => {
      if (request.method === "handshake/hello") return { directHello: true };
      return request.method === "steps/toolCallRequest"
        ? { result: { decision: "deny", reasoning: "policy" } }
        : {};
    });
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    const result = await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "false" }));
    expect(result).toMatchObject({ decision: "deny", reasoning: "policy" });
    expect(guardian.requests.every((request) => request.method === "system/ping" || request.params.signature?.key_id === TEST_KEY_ID)).toBe(true);
  });

  it("rejects an unsigned direct ServerHello over HTTP", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "handshake/hello"
      ? { directHello: true, unsignedHello: true }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    await expect(client.handshake(newSessionState("ses_local")))
      .rejects.toMatchObject({ kind: "signature" });
  });

  it("rejects tampered signed direct and legacy wrapped ServerHello responses", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    let guardian = createGuardian();
    const signedFetch = guardian.fetch;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await signedFetch(input, init);
      const value = await response.json() as { result?: ServerHello };
      if (value.result?.negotiated_version) value.result.on_decision_failure = "proceed";
      return Response.json(value);
    });
    await expect(new AcsClient(config()).handshake(newSessionState("ses_tampered")))
      .rejects.toMatchObject({ kind: "signature" });

    guardian = createGuardian((request) => request.method === "handshake/hello" ? { legacyHello: true } : {});
    vi.stubGlobal("fetch", guardian.fetch);
    await expect(new AcsClient(config()).handshake(newSessionState("ses_legacy")))
      .rejects.toMatchObject({ kind: "invalid_schema" });
  });

  it("categorizes malformed JSON", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest" ? { raw: "not-json" } : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    await expect(client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "true" })))
      .rejects.toMatchObject({ kind: "invalid_json" });
  });

  it("categorizes decision timeout", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest" ? { delayMs: 50 } : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    state.handshake.timeout_config.default_ms = 5;
    try {
      await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "true" }));
      throw new Error("expected timeout");
    } catch (error) {
      expect(error).toBeInstanceOf(AcsClientError);
      expect(error).toMatchObject({ kind: "timeout" });
    }
  });

  it("sends system/ping unsigned and enforces its response invariant", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    const result = await client.request(state, "system/ping", { echo: "hello" });
    expect(result.decision).toBe("allow");
    expect(guardian.requests.at(-1)?.params.signature).toBeUndefined();

    const invalidGuardian = createGuardian((request) => request.method === "system/ping"
      ? { result: { decision: "deny", reasoning: "invalid ping decision" } }
      : {});
    vi.stubGlobal("fetch", invalidGuardian.fetch);
    const invalidClient = new AcsClient(config());
    const invalidState = newSessionState("ses_invalid_ping");
    invalidState.handshake = await invalidClient.handshake(invalidState);
    await expect(invalidClient.request(invalidState, "system/ping", {}))
      .rejects.toMatchObject({ kind: "guardian_error" });

    const errorGuardian = createGuardian((request) => request.method === "system/ping"
      ? { error: { code: -32001, message: "Ping unavailable" } }
      : {});
    vi.stubGlobal("fetch", errorGuardian.fetch);
    const errorClient = new AcsClient(config());
    const errorState = newSessionState("ses_error_ping");
    errorState.handshake = await errorClient.handshake(errorState);
    await expect(errorClient.request(errorState, "system/ping", {}))
      .rejects.toMatchObject({ kind: "guardian_error", message: "Ping unavailable" });
  });

  it("rejects a response signed under an unexpected key id", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    const originalFetch = guardian.fetch;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await originalFetch(input, init);
      const request = JSON.parse(String(init?.body)) as { method?: string };
      const value = await response.json() as { result?: { signature?: { key_id: string } } };
      if (request.method === "steps/toolCallRequest" && value.result?.signature) {
        value.result.signature.key_id = "different-key";
      }
      return Response.json(value);
    });
    const client = new AcsClient(config());
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    await expect(client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" })))
      .rejects.toMatchObject({ kind: "signature" });
  });

  it("verifies signed JSON-RPC error envelopes before surfacing the error", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest"
      ? { error: { code: -32001, message: "Guardian rejected the request" } }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const state = newSessionState("ses_host");
    const acs = new AcsClient(config());
    state.handshake = await acs.handshake(state);
    await expect(acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" })))
      .rejects.toMatchObject({ kind: "guardian_error", message: "Guardian rejected the request" });

    const originalFetch = guardian.fetch;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await originalFetch(input, init);
      const value = await response.json() as { error?: { signature?: unknown } };
      if (value.error) delete value.error.signature;
      return Response.json(value);
    });
    await expect(acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" })))
      .rejects.toMatchObject({ kind: "signature" });
  });

  it("serializes same-session requests so the next request carries the prior chain head", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    let sequence = 0;
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest"
      ? { result: { decision: "allow", chain_hash: (++sequence).toString(16).padStart(64, "0") } }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    await Promise.all([
      client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "one" })),
      client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "two" })),
    ]);
    const calls = guardian.requests.filter((request) => request.method === "steps/toolCallRequest");
    expect(calls[0]?.params.metadata.session_state).toBeUndefined();
    expect(calls[1]?.params.metadata.session_state?.chain_hash).toBe("1".padStart(64, "0"));
  });

  it("keeps the JSON-RPC error code so a refusal is distinguishable from an internal error", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    let guardian = createGuardian((request) => request.method === "handshake/hello"
      ? { error: { code: -32000, message: "agent not permitted", data: { reason: "agent_id" } } }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const refused = await new AcsClient(config()).handshake(newSessionState("ses_refused")).catch((error: unknown) => error);
    expect(refused).toMatchObject({ kind: "guardian_error", code: -32000 });
    expect(failureDisposition(refused)).toBe("refusal");

    guardian = createGuardian((request) => request.method === "steps/toolCallRequest"
      ? { error: { code: -32603, message: "internal" } }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_internal");
    state.handshake = await client.handshake(state);
    const internal = await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))
      .catch((error: unknown) => error);
    expect(internal).toMatchObject({ kind: "guardian_error", code: -32603 });
    expect(failureDisposition(internal)).toBe("availability");
  });

  it("reads a signed JSON-RPC error carried on a non-2xx response instead of discarding it", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest"
      ? { status: 403, error: { code: -32000, message: "refused on 403" } }
      : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_403");
    state.handshake = await client.handshake(state);
    await expect(client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" })))
      .rejects.toMatchObject({ kind: "guardian_error", code: -32000, status: 403, message: "refused on 403" });

    const signedFetch = guardian.fetch;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await signedFetch(input, init);
      const value = await response.json() as { error?: { signature?: unknown } };
      if (value.error) delete value.error.signature;
      return Response.json(value, { status: response.status });
    });
    await expect(client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" })))
      .rejects.toMatchObject({ kind: "signature", status: 403 });
  });

  it("rejects a success body on a failure status and keeps the oversize cause on a 5xx", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest" ? { status: 502 } : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_contradictory");
    state.handshake = await client.handshake(state);
    const contradictory = await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))
      .catch((caught: unknown) => caught);
    expect(contradictory).toMatchObject({ kind: "invalid_schema", status: 502 });
    expect(failureDisposition(contradictory)).toBe("integrity");

    vi.stubGlobal("fetch", async () => new Response("x".repeat(1_048_577), { status: 503 }));
    const oversized = await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))
      .catch((caught: unknown) => caught);
    expect(oversized).toMatchObject({ kind: "response_too_large", status: 503 });
    expect(failureDisposition(oversized)).toBe("integrity");
  });

  it.each([
    { status: 401, body: "", disposition: "refusal" },
    { status: 403, body: "<html>forbidden</html>", disposition: "refusal" },
    { status: 404, body: '{"error":"not found"}', disposition: "refusal" },
    { status: 429, body: "", disposition: "refusal" },
    { status: 408, body: "", disposition: "availability" },
    { status: 503, body: "unavailable", disposition: "availability" },
  ])("classifies HTTP $status without a JSON-RPC body as $disposition", async ({ status, body, disposition }) => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "steps/toolCallRequest" ? { status, raw: body } : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_http");
    state.handshake = await client.handshake(state);
    const error = await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))
      .catch((caught: unknown) => caught);
    expect(error).toMatchObject({ kind: "http", status });
    expect(failureDisposition(error)).toBe(disposition);
  });

  it("treats every verification failure as an integrity failure", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    const signedFetch = guardian.fetch;
    let tamper: "signature" | "key" | "id" | "schema" | "none" = "none";
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await signedFetch(input, init);
      const request = JSON.parse(String(init?.body)) as { method?: string };
      if (request.method !== "steps/toolCallRequest" || tamper === "none") return response;
      const value = await response.json();
      if (tamper === "signature") value.result.signature.value = "AAAA";
      if (tamper === "key") value.result.signature.key_id = "other-key";
      if (tamper === "id") value.id = "wrong-id";
      if (tamper === "schema") value.result.decision = "allow-ish";
      return Response.json(value);
    });
    const client = new AcsClient(config());
    const state = newSessionState("ses_integrity");
    state.handshake = await client.handshake(state);
    for (const [kind, expected] of [["signature", "signature"], ["key", "signature"], ["id", "correlation"], ["schema", "invalid_schema"]] as const) {
      tamper = kind;
      const error = await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }))
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({ kind: expected });
      expect(failureDisposition(error)).toBe("integrity");
    }
    expect(failureDisposition(new TypeError("not an AcsClientError"))).toBe("integrity");
  });

  it("rejects payloads larger than the advertised client limit before transport", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    await expect(client.request(state, "steps/userMessage", {
      content: [{ type: "text", value: "x".repeat(1_048_576) }],
    })).rejects.toMatchObject({ kind: "request_too_large" });
    expect(guardian.requests).toHaveLength(1);
  });
});
