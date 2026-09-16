import { afterEach, describe, expect, it, vi } from "vitest";
import { AcsClient } from "../src/client.js";
import type { AcsConfig } from "../src/config.js";
import { newSessionState, toolCallPayload } from "../src/mapper.js";
import { AcsClientError } from "../src/types.js";
import { createGuardian, TEST_KEY, TEST_KEY_ID } from "./guardian-helper.js";

function config(timeout = 100, url = "http://127.0.0.1:8787/"): AcsConfig {
  return {
    mode: "enforce",
    startupPosture: "refuse",
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

  it("accepts a direct ServerHello and verifies a signed tool decision", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => {
      if (request.method === "handshake/hello") return { directHello: true };
      return request.method === "steps/toolCallRequest"
        ? { result: { decision: "deny", reasoning: "policy" } }
        : {};
    });
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config(100, "https://guardian.example/"));
    const state = newSessionState("ses_local");
    state.handshake = await client.handshake(state);
    const result = await client.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "false" }));
    expect(result).toMatchObject({ decision: "deny", reasoning: "policy" });
    expect(guardian.requests.every((request) => request.method === "system/ping" || request.params.signature?.key_id === TEST_KEY_ID)).toBe(true);
  });

  it("rejects an unsigned direct ServerHello over HTTP", async () => {
    process.env.OPENCODE_ACS_CLIENT_TEST_KEY = TEST_KEY;
    const guardian = createGuardian((request) => request.method === "handshake/hello" ? { directHello: true } : {});
    vi.stubGlobal("fetch", guardian.fetch);
    const client = new AcsClient(config());
    await expect(client.handshake(newSessionState("ses_local")))
      .rejects.toMatchObject({ kind: "signature" });
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
