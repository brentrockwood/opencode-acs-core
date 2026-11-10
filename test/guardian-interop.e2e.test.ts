/**
 * Interoperability run against the upstream ACS example Guardian.
 *
 * This suite drives this adapter's own client (the verifier under test) against the
 * Python `acs-example-guardian` shipped in the upstream `adapters/` package, with the
 * same secret bytes and key label on both sides. It runs only when
 * `ACS_UPSTREAM_GUARDIAN` names that executable; see docs/coverage.md for the recorded
 * evidence and the Guardian commit it was taken against.
 *
 * It is a wire-level run: the host (OpenCode) is not involved. Host-level behavior
 * against a Guardian is covered by the pinned runtime suite with the repository's
 * fixture.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize } from "json-canonicalize";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { AcsClient } from "../src/client.js";
import { parseConfig, type AcsConfig } from "../src/config.js";
import { deriveSessionKey, signEnvelope, verifyEnvelope } from "../src/crypto.js";
import { failureDisposition } from "../src/failure.js";
import {
  METHODS_IMPLEMENTED, buildRequest, newSessionState, subagentStartPayload, subagentStopPayload, toolCallPayload, toolResultPayload,
} from "../src/mapper.js";
import { AcsClientError, type AcsRequestEnvelope, type AcsResponseEnvelope, type AcsResult, type JsonObject, type SessionState } from "../src/types.js";

const guardianBin = process.env.ACS_UPSTREAM_GUARDIAN;

// 64 ASCII bytes: above the 32-byte §10 minimum on both sides. The Guardian reads
// ACS_HMAC_SECRET as UTF-8 and this adapter reads its key variable as UTF-8, so the
// input key material is byte-identical without a secret file.
const SECRET = "interop-secret-0123456789abcdef0123456789abcdef0123456789abcdef";
const KEY_ID = "interop-key";
const KEY_ENV = "OPENCODE_ACS_INTEROP_KEY";

interface Guardian {
  child: ChildProcess;
  port: number;
  url: string;
  stderr: string[];
}

async function startGuardian(bin: string): Promise<Guardian> {
  const child = spawn(bin, ["--port", "0"], {
    env: {
      ...process.env,
      ACS_HMAC_SECRET: SECRET,
      ACS_HMAC_KEY_ID: KEY_ID,
      // In-memory replay and chain state: nothing is written under the home directory.
      ACS_GUARDIAN_STATE_DIR: "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stderr: string[] = [];
  child.stderr!.on("data", (chunk: Buffer) => {
    for (const line of chunk.toString("utf8").split("\n")) if (line) stderr.push(line);
  });
  const port = await new Promise<number>((resolve, reject) => {
    let stdout = "";
    const timer = setTimeout(() => reject(new Error(`Guardian did not report a port in time; stderr: ${stderr.join(" | ")}`)), 15_000);
    child.stdout!.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      const match = /ACS_GUARDIAN_LISTENING port=(\d+)/.exec(stdout);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`Guardian exited with ${code} before listening; stderr: ${stderr.join(" | ")}`));
    });
  });
  return { child, port, url: `http://127.0.0.1:${port}/acs`, stderr };
}

function sha256(input: Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * §8.2 as the example Guardian publishes it: each step appends a ContextEntry whose
 * request_hash covers the signed params, and the head is
 * sha256(JCS(entry without previous_hash) || previous head bytes). Recomputed here from
 * the requests this client actually sent, so the Guardian's chain_hash is checked, not
 * just propagated.
 */
function expectedChain(sentSteps: AcsRequestEnvelope[]): string[] {
  const heads: string[] = [];
  let previous: string | undefined;
  for (const request of sentSteps) {
    const entry: Record<string, unknown> = {
      entry_id: request.params.request_id,
      step_id: request.params.request_id,
      step_type: request.method,
      request_hash: sha256(Buffer.from(canonicalize(request.params), "utf8")),
      timestamp: request.params.timestamp,
    };
    const head = sha256(Buffer.concat([
      Buffer.from(canonicalize(entry), "utf8"),
      previous ? Buffer.from(previous, "hex") : Buffer.alloc(0),
    ]));
    heads.push(head);
    previous = head;
  }
  return heads;
}

function session(): SessionState {
  return newSessionState(`interop-${randomUUID()}`);
}

describe.skipIf(!guardianBin)("upstream example Guardian interoperability", () => {
  let guardian: Guardian;
  let directory: string;
  let config: AcsConfig;
  let acs: AcsClient;
  const sent: AcsRequestEnvelope[] = [];
  const realFetch = globalThis.fetch;

  function rawSend(envelope: AcsRequestEnvelope): Promise<AcsResponseEnvelope> {
    return realFetch(guardian.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    }).then((response) => response.json() as Promise<AcsResponseEnvelope>);
  }

  function signedRaw(state: SessionState, method: string, payload: JsonObject, mutate?: (envelope: AcsRequestEnvelope) => void, keyId = KEY_ID): AcsRequestEnvelope {
    const envelope = buildRequest(config, state, method, payload);
    mutate?.(envelope);
    delete envelope.params.signature;
    envelope.params.signature = signEnvelope(envelope, deriveSessionKey(SECRET, state.sessionId), keyId);
    return envelope;
  }

  beforeAll(async () => {
    guardian = await startGuardian(guardianBin!);
    directory = await mkdtemp(join(tmpdir(), "opencode-acs-interop-"));
    process.env[KEY_ENV] = SECRET;
    config = parseConfig({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: { url: guardian.url, hmacKeyEnv: KEY_ENV, keyId: KEY_ID, connectTimeoutMs: 2_000 },
      audit: { path: join(directory, "audit.jsonl") },
      agent: { id: "opencode", environment: "development" },
    }, directory);
    acs = new AcsClient(config);
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      if (typeof init?.body === "string") sent.push(JSON.parse(init.body) as AcsRequestEnvelope);
      return realFetch(input, init);
    });
  });

  afterAll(async () => {
    vi.unstubAllGlobals();
    delete process.env[KEY_ENV];
    guardian?.child.kill();
    if (directory) await rm(directory, { recursive: true, force: true });
    console.log(`interop evidence: guardian=${guardianBin} port=${guardian?.port} requests_sent=${sent.length} guardian_log_lines=${guardian?.stderr.length}`);
  });

  it("negotiates a signed handshake on the client's advertised methods and transport", async () => {
    const state = session();
    state.handshake = await acs.handshake(state);
    expect(state.handshake).toMatchObject({
      negotiated_version: "0.1.0",
      methods_evaluated: [...METHODS_IMPLEMENTED],
      selected_transport: "http",
      signature_algorithms_supported: ["HMAC-SHA256"],
      timeout_config: { default_ms: 5_000 },
      on_decision_failure: "deny",
      policy_requires_provenance: false,
      profiles_accepted: [],
    });
    expect(state.handshake.signature).toMatchObject({ algorithm: "HMAC-SHA256", key_id: KEY_ID });
    expect((state.handshake as unknown as { skew_window_ms?: number }).skew_window_ms).toBe(300_000);
    expect(sent.at(-1)).toMatchObject({ method: "handshake/hello", params: { signature: { key_id: KEY_ID } } });
    expect(acs.failurePosture(state)).toBe("deny");
  });

  it("exchanges signed allow and deny decisions, propagates the chain head, and the head recomputes", async () => {
    const state = session();
    state.handshake = await acs.handshake(state);
    const firstStep = sent.length;
    const results: AcsResult[] = [];

    results.push(await acs.request(state, "steps/sessionStart", {}));
    expect(results[0]).toMatchObject({ decision: "allow", signature: { key_id: KEY_ID } });
    expect(results[0]!.chain_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(state.chainHash).toBe(results[0]!.chain_hash);

    results.push(await acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" })));
    expect(results[1]).toMatchObject({ decision: "allow" });
    // The second request carried the head the first answer published.
    expect(sent.at(-1)!.params.metadata.session_state).toEqual({ chain_hash: results[0]!.chain_hash });
    const allowedRequestId = sent.at(-1)!.params.request_id;

    results.push(await acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "rm -rf /" })));
    expect(results[2]).toMatchObject({ decision: "deny", reason_codes: ["destructive_command"], signature: { key_id: KEY_ID } });
    // A deny also publishes a head, and the next step carries it.
    expect(results[2]!.chain_hash).toMatch(/^[0-9a-f]{64}$/);

    // Consecutive content-bearing steps: two tool results and a second request.
    results.push(await acs.request(state, "steps/toolCallResult", toolResultPayload("bash", allowedRequestId, { title: "pwd", output: "/work", metadata: { exit: 0 } })));
    results.push(await acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "ls -la" })));
    results.push(await acs.request(state, "steps/toolCallResult", toolResultPayload("bash", sent.at(-1)!.params.request_id, { title: "ls", output: "total 0", metadata: { exit: 0 } })));
    expect(results.slice(3).every((result) => result.decision === "allow")).toBe(true);
    expect(sent.at(-1)!.params.metadata.session_state).toEqual({ chain_hash: results[4]!.chain_hash });

    const steps = sent.slice(firstStep);
    expect(steps.map((request) => request.method)).toEqual([
      "steps/sessionStart", "steps/toolCallRequest", "steps/toolCallRequest", "steps/toolCallResult", "steps/toolCallRequest", "steps/toolCallResult",
    ]);
    const heads = results.map((result) => result.chain_hash);
    expect(new Set(heads).size).toBe(heads.length);
    expect(heads).toEqual(expectedChain(steps));
  });

  it("gets a signed deny for a subagent launch and a signed allow for its stop", async () => {
    const parent = session();
    const child = session();
    parent.handshake = await acs.handshake(parent);
    await acs.request(parent, "steps/sessionStart", {});
    const start = await acs.request(parent, "steps/subagentStart", subagentStartPayload(parent, child, randomUUID(), { prompt: "explore", subagent_type: "general" }));
    expect(start).toMatchObject({ decision: "deny", reason_codes: ["subagent_gated"], signature: { key_id: KEY_ID } });
    const stop = await acs.request(parent, "steps/subagentStop", subagentStopPayload(child, "cancelled"));
    expect(stop).toMatchObject({ decision: "allow" });
  });

  it("surfaces a replayed request_id as a signed refusal (-32005) through the client", async () => {
    const state = session();
    state.handshake = await acs.handshake(state);
    const requestId = randomUUID();
    await acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }), undefined, requestId);
    const failure = await acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }), undefined, requestId)
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(AcsClientError);
    expect(failure).toMatchObject({ kind: "guardian_error", code: -32005 });
    expect(failureDisposition(failure)).toBe("refusal");
    // The same envelope replayed verbatim is refused too, and the error is signed.
    const replayed = await rawSend(sent.at(-2)!);
    expect(replayed.error).toMatchObject({ code: -32005 });
    expect(verifyEnvelope(replayed, deriveSessionKey(SECRET, state.sessionId), replayed.error!.signature!)).toBe(true);
  });

  it("rejects a stale timestamp with a signed -32006, and a repeated action with a fresh id is not a replay", async () => {
    const state = session();
    state.handshake = await acs.handshake(state);
    await acs.request(state, "steps/sessionStart", {});

    const stale = await rawSend(signedRaw(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }), (envelope) => {
      envelope.params.timestamp = new Date(Date.now() - 10 * 60_000).toISOString();
    }));
    expect(stale.error).toMatchObject({ code: -32006, signature: { key_id: KEY_ID } });

    // §10.3: duplicate request_id rejection is a MUST, nonce rejection a SHOULD. A fresh id
    // with a repeated nonce is accepted by this Guardian; recorded, not asserted as a defect.
    const first = signedRaw(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }));
    expect((await rawSend(first)).result).toMatchObject({ decision: "allow" });
    const sameNonce = signedRaw(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }), (envelope) => {
      envelope.params.nonce = first.params.nonce!;
    });
    const repeated = await rawSend(sameNonce);
    expect(repeated.error ?? repeated.result).toBeDefined();
    console.log(`interop evidence: repeated nonce with fresh request_id -> ${repeated.error ? `error ${repeated.error.code}` : `decision ${repeated.result!.decision}`}`);
  });

  it("scopes replay protection to the session", async () => {
    const first = session();
    const second = session();
    first.handshake = await acs.handshake(first);
    second.handshake = await acs.handshake(second);
    const requestId = randomUUID();
    const inFirst = signedRaw(first, "steps/sessionStart", {}, (envelope) => {
      envelope.id = requestId;
      envelope.params.request_id = requestId;
    });
    const inSecond = signedRaw(second, "steps/sessionStart", {}, (envelope) => {
      envelope.id = requestId;
      envelope.params.request_id = requestId;
    });
    expect((await rawSend(inFirst)).result).toMatchObject({ decision: "allow", request_id: requestId });
    expect((await rawSend(inSecond)).result).toMatchObject({ decision: "allow", request_id: requestId });
    expect((await rawSend(inFirst)).error).toMatchObject({ code: -32005 });
  });

  it("treats the unsigned -32004 for an unknown key label as an integrity failure", async () => {
    process.env[KEY_ENV] = SECRET;
    const otherLabel = new AcsClient(parseConfig({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: { url: guardian.url, hmacKeyEnv: KEY_ENV, keyId: "not-the-guardian-label", connectTimeoutMs: 2_000 },
      audit: { path: join(directory, "audit-other.jsonl") },
    }, directory));
    const state = session();
    const failure = await otherLabel.handshake(state).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(AcsClientError);
    expect((failure as AcsClientError).kind).toBe("signature");
    expect(failureDisposition(failure)).toBe("integrity");
    const answer = await rawSend(signedRaw(state, "steps/sessionStart", {}, undefined, "not-the-guardian-label"));
    expect(answer.error).toMatchObject({ code: -32004 });
    expect(answer.error!.signature).toBeUndefined();
  });

  it("gets a signed -32600 for a step envelope that fails the Guardian's schema check", async () => {
    const state = session();
    state.handshake = await acs.handshake(state);
    const malformed = await rawSend(signedRaw(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }), (envelope) => {
      delete (envelope.params as Record<string, unknown>).nonce;
      delete (envelope.params.metadata as Record<string, unknown>).agent_id;
    }));
    expect(malformed.error).toMatchObject({ code: -32600, signature: { key_id: KEY_ID } });
    const failure = new AcsClientError("guardian_error", malformed.error!.message, malformed.error, { code: malformed.error!.code });
    expect(failureDisposition(failure)).toBe("refusal");
  });

  it("refuses the session on a signed UNSUPPORTED_VERSION (-32001) from the Guardian", async () => {
    const state = session();
    const answer = await rawSend(signedRaw(state, "handshake/hello", {
      acs_versions_supported: ["9.0.0"],
      methods_implemented: [...METHODS_IMPLEMENTED],
      transports_supported: ["http"],
      provenance_producer: "none",
      profiles_supported: [],
    }));
    expect(answer.error).toMatchObject({ code: -32001, signature: { key_id: KEY_ID } });
    const failure = new AcsClientError("guardian_error", answer.error!.message, answer.error, { code: answer.error!.code });
    expect(failureDisposition(failure)).toBe("refusal");
  });

  it("records whether the Guardian checks the head the client propagates", async () => {
    const state = session();
    state.handshake = await acs.handshake(state);
    await acs.request(state, "steps/sessionStart", {});
    const wrongHead = "0".repeat(64);
    const answer = await rawSend(signedRaw(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }), (envelope) => {
      envelope.params.metadata.session_state = { chain_hash: wrongHead };
    }));
    // The example Guardian appends without comparing the propagated head; recorded as an
    // interoperability observation, not asserted either way.
    expect(answer.error ?? answer.result).toBeDefined();
    console.log(`interop evidence: wrong propagated chain head -> ${answer.error ? `error ${answer.error.code}` : `decision ${answer.result!.decision}`}`);
  });

  it("ends the session with the final chain head accepted", async () => {
    const state = session();
    state.handshake = await acs.handshake(state);
    await acs.request(state, "steps/sessionStart", {});
    await acs.request(state, "steps/toolCallRequest", toolCallPayload("bash", { command: "pwd" }));
    const head = state.chainHash;
    const end = await acs.request(state, "steps/sessionEnd", { reason: "completed" });
    expect(end).toMatchObject({ decision: "allow" });
    expect(sent.at(-1)!.params.payload).toMatchObject({ final_chain_hash: head });
  });
});
