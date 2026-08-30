import { deriveSessionKey, signEnvelope, verifyEnvelope } from "../src/crypto.js";
import { ACS_VERSION, type AcsError, type AcsRequestEnvelope, type AcsResponseEnvelope, type AcsResult, type JsonObject } from "../src/types.js";

export const TEST_KEY = "unit-test-key-material-not-for-production";
export const TEST_KEY_ID = "test-key";

export interface GuardianReply {
  status?: number;
  raw?: string;
  delayMs?: number;
  result?: Omit<AcsResult, "type" | "acs_version" | "request_id">;
  error?: Omit<AcsError, "signature">;
}

export interface TestGuardian {
  requests: AcsRequestEnvelope[];
  fetch: typeof globalThis.fetch;
}

function helloPayload(request: AcsRequestEnvelope): JsonObject {
  return {
    negotiated_version: ACS_VERSION,
    methods_evaluated: request.params.payload.methods_implemented ?? [],
    selected_transport: "http",
    signature_algorithms_supported: ["HMAC-SHA256"],
    timeout_config: { default_ms: 1_000 },
    on_decision_failure: "deny",
    policy_requires_provenance: false,
    profiles_accepted: [],
  };
}

async function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(new DOMException("aborted", "AbortError"));
    }, { once: true });
  });
}

export function createGuardian(reply: (request: AcsRequestEnvelope) => GuardianReply = () => ({})): TestGuardian {
  const requests: AcsRequestEnvelope[] = [];
  const guardianFetch: typeof globalThis.fetch = async (_input, init) => {
    const request = JSON.parse(String(init?.body)) as AcsRequestEnvelope;
    requests.push(request);
    const key = deriveSessionKey(TEST_KEY, request.params.metadata.session_id);
    if (request.method !== "system/ping") {
      const signature = request.params.signature;
      if (!signature || signature.key_id !== TEST_KEY_ID || !verifyEnvelope(request, key, signature)) {
        return new Response("", { status: 401 });
      }
    }
    const selected = reply(request);
    if (selected.delayMs) await delay(selected.delayMs, init?.signal ?? undefined);
    if (selected.raw !== undefined) {
      return new Response(selected.raw, {
        status: selected.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (selected.error) {
      const error = { ...selected.error } as AcsError;
      const response: AcsResponseEnvelope = { jsonrpc: "2.0", id: request.id, error };
      if (request.method !== "system/ping") error.signature = signEnvelope(response, key, TEST_KEY_ID);
      return Response.json(response, { status: selected.status ?? 200 });
    }
    const decision = request.method === "handshake/hello"
      ? { decision: "allow" as const, payload: helloPayload(request) }
      : selected.result ?? { decision: "allow" as const };
    const result = {
      type: "final",
      acs_version: ACS_VERSION,
      request_id: request.params.request_id,
      ...decision,
    } as AcsResult;
    const response: AcsResponseEnvelope = { jsonrpc: "2.0", id: request.id, result };
    if (request.method !== "system/ping") result.signature = signEnvelope(response, key, TEST_KEY_ID);
    return Response.json(response, { status: selected.status ?? 200 });
  };
  return { requests, fetch: guardianFetch };
}
