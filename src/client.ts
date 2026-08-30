import type { AcsConfig } from "./config.js";
import { AuditSink } from "./audit.js";
import { deriveSessionKey, signEnvelope, verifyEnvelope } from "./crypto.js";
import { METHODS_IMPLEMENTED, buildRequest, clientHello } from "./mapper.js";
import { validateRequest, validateResponse, validateServerHello } from "./schema.js";
import {
  ACS_VERSION,
  AcsClientError,
  type AcsRequestEnvelope,
  type AcsResponseEnvelope,
  type AcsResult,
  type JsonObject,
  type ServerHello,
  type SessionState,
} from "./types.js";

export class AcsClient {
  private readonly audit: AuditSink;
  private readonly inputKeyMaterial: string | undefined;
  private readonly requestQueues = new Map<string, Promise<void>>();

  constructor(private readonly config: AcsConfig) {
    this.audit = new AuditSink(config.audit);
    const keyEnvironment = config.guardian.hmacKeyEnv;
    this.inputKeyMaterial = keyEnvironment ? process.env[keyEnvironment] : undefined;
    if (keyEnvironment && !this.inputKeyMaterial) {
      throw new AcsClientError("configuration", `environment variable ${keyEnvironment} is not set`);
    }
  }

  get signed(): boolean {
    return this.inputKeyMaterial !== undefined;
  }

  async handshake(state: SessionState): Promise<ServerHello> {
    const result = await this.request(state, "handshake/hello", clientHello(), this.config.guardian.connectTimeoutMs);
    if (!result.payload) throw new AcsClientError("invalid_schema", "handshake response has no ServerHello payload");
    try {
      validateServerHello(result.payload);
    } catch (error) {
      throw new AcsClientError("invalid_schema", (error as Error).message, error);
    }
    if (result.payload.negotiated_version !== ACS_VERSION) {
      throw new AcsClientError("correlation", `Guardian negotiated unsupported ACS version ${result.payload.negotiated_version}`);
    }
    const hello = result.payload as unknown as ServerHello;
    const advertised = new Set<string>(METHODS_IMPLEMENTED);
    const unexpected = hello.methods_evaluated.filter((method) => !advertised.has(method));
    if (unexpected.length > 0) {
      throw new AcsClientError("correlation", `Guardian selected method(s) the client did not advertise: ${unexpected.join(", ")}`);
    }
    const expectedTransport = new URL(this.config.guardian.url).protocol.slice(0, -1);
    if (hello.selected_transport !== expectedTransport) {
      throw new AcsClientError(
        "correlation",
        `Guardian selected ${hello.selected_transport}, but the configured endpoint uses ${expectedTransport}`,
      );
    }
    if (hello.policy_requires_provenance === true) {
      throw new AcsClientError("configuration", "Guardian requires provenance, but this adapter declares provenance_producer=none");
    }
    if ((hello.profiles_accepted?.length ?? 0) > 0) {
      throw new AcsClientError("correlation", "Guardian accepted a conformance profile the client did not offer");
    }
    if (this.signed && !hello.signature_algorithms_supported?.includes("HMAC-SHA256")) {
      throw new AcsClientError("signature", "Guardian did not advertise HMAC-SHA256 support");
    }
    return hello;
  }

  async request(
    state: SessionState,
    method: string,
    payload: JsonObject,
    explicitTimeout?: number,
  ): Promise<AcsResult> {
    const previous = this.requestQueues.get(state.sessionId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    this.requestQueues.set(state.sessionId, current);
    await previous.catch(() => undefined);
    try {
      return await this.performRequest(state, method, payload, explicitTimeout);
    } finally {
      release();
      if (this.requestQueues.get(state.sessionId) === current) this.requestQueues.delete(state.sessionId);
    }
  }

  private async performRequest(
    state: SessionState,
    method: string,
    payload: JsonObject,
    explicitTimeout?: number,
  ): Promise<AcsResult> {
    const request = buildRequest(this.config, state, method, payload);
    if (Buffer.byteLength(JSON.stringify(payload), "utf8") > 1_048_576) {
      throw new AcsClientError("request_too_large", "ACS payload exceeds the advertised 1048576-byte limit");
    }
    const sessionKey = this.inputKeyMaterial ? deriveSessionKey(this.inputKeyMaterial, state.sessionId) : undefined;
    if (sessionKey && this.config.guardian.keyId && method !== "system/ping") {
      request.params.signature = signEnvelope(request, sessionKey, this.config.guardian.keyId);
    }
    try {
      validateRequest(request);
    } catch (error) {
      throw new AcsClientError("invalid_schema", (error as Error).message, error);
    }

    const timeout = explicitTimeout ?? state.handshake?.timeout_config.per_method_ms?.[method]
      ?? state.handshake?.timeout_config.default_ms
      ?? this.config.guardian.connectTimeoutMs;

    await this.audit.write({
      event: "acs_request",
      session_id: state.sessionId,
      request_id: request.params.request_id,
      method,
      payload: request.params.payload,
      signed: Boolean(request.params.signature),
    });

    let response: AcsResponseEnvelope;
    try {
      response = await this.fetchResponse(request, timeout);
    } catch (error) {
      await this.audit.write({
        event: "acs_decision_failure",
        session_id: state.sessionId,
        request_id: request.params.request_id,
        method,
        failure_kind: error instanceof AcsClientError ? error.kind : "transport",
        message: (error as Error).message,
      });
      throw error;
    }

    try {
      validateResponse(response);
    } catch (error) {
      throw new AcsClientError("invalid_schema", (error as Error).message, error);
    }
    if (response.id !== request.id) throw new AcsClientError("correlation", "JSON-RPC response id does not match request");
    if (response.error) {
      if (
        sessionKey && (
          !response.error.signature
          || response.error.signature.key_id !== this.config.guardian.keyId
          || !verifyEnvelope(response, sessionKey, response.error.signature)
        )
      ) {
        throw new AcsClientError("signature", "Guardian error response signature is missing or invalid");
      }
      throw new AcsClientError("guardian_error", response.error.message, response.error);
    }
    if (!response.result) throw new AcsClientError("invalid_schema", "response has neither result nor error");
    if (response.result.request_id !== request.params.request_id) {
      throw new AcsClientError("correlation", "ACS response request_id does not match request");
    }
    if (response.result.acs_version !== ACS_VERSION) {
      throw new AcsClientError("correlation", `ACS response uses unexpected version ${response.result.acs_version}`);
    }
    if (sessionKey && method !== "system/ping") {
      if (
        !response.result.signature
        || response.result.signature.key_id !== this.config.guardian.keyId
        || !verifyEnvelope(response, sessionKey, response.result.signature)
      ) {
        throw new AcsClientError("signature", "Guardian response signature is missing or invalid");
      }
    }

    if (method === "system/ping" && (response.result.decision !== "allow" || response.result.chain_hash)) {
      throw new AcsClientError("guardian_error", "system/ping must return ALLOW without a chain hash");
    }
    if (response.result.chain_hash) state.chainHash = response.result.chain_hash;
    await this.audit.write({
      event: "acs_decision",
      session_id: state.sessionId,
      request_id: request.params.request_id,
      method,
      decision: response.result.decision,
      payload: response.result,
    });
    return response.result;
  }

  failurePosture(state: SessionState): "proceed" | "deny" {
    return state.handshake?.on_decision_failure ?? "proceed";
  }

  isEvaluated(state: SessionState, method: string): boolean {
    return state.handshake?.methods_evaluated.includes(method) === true;
  }

  async record(event: Parameters<AuditSink["write"]>[0]): Promise<void> {
    await this.audit.write(event);
  }

  private async fetchResponse(request: AcsRequestEnvelope, timeoutMs: number): Promise<AcsResponseEnvelope> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(this.config.guardian.url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(request),
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) throw new AcsClientError("http", `Guardian returned HTTP ${response.status}`);
      const declaredLength = Number(response.headers.get("content-length"));
      if (Number.isFinite(declaredLength) && declaredLength > this.config.guardian.maxResponseBytes) {
        throw new AcsClientError("response_too_large", "Guardian response exceeds configured limit");
      }
      const text = await this.readBoundedBody(response, this.config.guardian.maxResponseBytes);
      try {
        return JSON.parse(text) as AcsResponseEnvelope;
      } catch (error) {
        throw new AcsClientError("invalid_json", "Guardian returned invalid JSON", error);
      }
    } catch (error) {
      if (error instanceof AcsClientError) throw error;
      if (controller.signal.aborted) throw new AcsClientError("timeout", `Guardian timed out after ${timeoutMs} ms`, error);
      throw new AcsClientError("transport", `Guardian request failed: ${(error as Error).message}`, error);
    } finally {
      clearTimeout(timer);
    }
  }

  private async readBoundedBody(response: Response, maximumBytes: number): Promise<string> {
    if (!response.body) return "";
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maximumBytes) {
          await reader.cancel();
          throw new AcsClientError("response_too_large", "Guardian response exceeds configured limit");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
  }
}
