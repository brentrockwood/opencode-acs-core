import type { AcsConfig } from "./config.js";
import { AuditSink, decisionFailureClass } from "./audit.js";
import { deriveSessionKey, signEnvelope, verifyEnvelope } from "./crypto.js";
import { failureFields } from "./failure.js";
import { METHODS_IMPLEMENTED, buildRequest, clientHello } from "./mapper.js";
import { validateRequest, validateResponse, validateServerHello } from "./schema.js";
import {
  ACS_VERSION,
  AcsClientError,
  type AcsRequestEnvelope,
  type AcsResponseEnvelope,
  type AcsClientErrorDetail,
  type AcsResult,
  type JsonObject,
  type ServerHello,
  type SessionState,
} from "./types.js";

function isServerHello(result: AcsResult | ServerHello): result is ServerHello {
  return !("decision" in result)
    && typeof result.negotiated_version === "string"
    && Array.isArray(result.methods_evaluated);
}

/**
 * A Guardian may carry a JSON-RPC envelope on a non-2xx status. Only a body that is
 * recognizably JSON-RPC is passed on for schema, correlation and signature checks;
 * anything else leaves the HTTP status as the recorded cause.
 */
function jsonRpcEnvelope(text: string): AcsResponseEnvelope | undefined {
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value === "object" && value !== null && !Array.isArray(value) && (value as { jsonrpc?: unknown }).jsonrpc === "2.0") {
      return value as AcsResponseEnvelope;
    }
  } catch {
    // Not JSON at all; the HTTP status is the cause.
  }
  return undefined;
}

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
    if (this.inputKeyMaterial !== undefined && Buffer.byteLength(this.inputKeyMaterial, "utf8") < 32) {
      throw new AcsClientError("configuration", `environment variable ${keyEnvironment} must contain at least 32 UTF-8 bytes`);
    }
  }

  get signed(): boolean {
    return this.inputKeyMaterial !== undefined;
  }

  async handshake(state: SessionState): Promise<ServerHello> {
    const result = await this.exchange(state, "handshake/hello", clientHello(), this.config.guardian.connectTimeoutMs);
    if (!isServerHello(result)) {
      throw new AcsClientError("invalid_schema", "handshake/hello must return ServerHello directly in result");
    }
    return result;
  }

  private validateHello(result: AcsResult | ServerHello): ServerHello {
    if (!isServerHello(result)) {
      throw new AcsClientError("invalid_schema", "handshake/hello must return ServerHello directly in result");
    }
    const payload = result;
    try {
      validateServerHello(payload);
    } catch (error) {
      throw new AcsClientError("invalid_schema", (error as Error).message, error);
    }
    if (payload.negotiated_version !== ACS_VERSION) {
      throw new AcsClientError("correlation", `Guardian negotiated unsupported ACS version ${payload.negotiated_version}`);
    }
    const hello = payload as unknown as ServerHello;
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
    explicitRequestId?: string,
  ): Promise<AcsResult> {
    const result = await this.exchange(state, method, payload, explicitTimeout, explicitRequestId);
    if (isServerHello(result)) {
      throw new AcsClientError("invalid_schema", "Guardian returned ServerHello outside handshake/hello");
    }
    return result;
  }

  private async exchange(
    state: SessionState,
    method: string,
    payload: JsonObject,
    explicitTimeout?: number,
    explicitRequestId?: string,
  ): Promise<AcsResult | ServerHello> {
    const previous = this.requestQueues.get(state.sessionId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    this.requestQueues.set(state.sessionId, current);
    await previous.catch(() => undefined);
    let request: AcsRequestEnvelope | undefined;
    let requestValid = false;
    try {
      if (method === "steps/sessionEnd") {
        payload = {
          ...payload,
          summary: { ...(payload.summary as JsonObject | undefined), decision_failures: { ...state.decisionFailures } },
          ...(state.chainHash ? { final_chain_hash: state.chainHash } : {}),
        };
      }
      request = buildRequest(this.config, state, method, payload, explicitRequestId);
      if (Buffer.byteLength(JSON.stringify(payload), "utf8") > 1_048_576) {
        throw new AcsClientError("request_too_large", "ACS payload exceeds the advertised 1048576-byte limit");
      }
      validateRequest(request);
      requestValid = true;
      const result = await this.performRequest(state, request, explicitTimeout);
      return method === "handshake/hello" ? this.validateHello(result) : result;
    } catch (error) {
      // Normalize a local request fault once, so the client record and the host records
      // for the same failure carry the same failure_kind.
      const failure = !requestValid && !(error instanceof AcsClientError)
        ? new AcsClientError("invalid_schema", String(error), error)
        : error;
      const failureClass = method === "handshake/hello"
        ? "handshake_failure"
        : requestValid ? decisionFailureClass(failure) : "observed_agent_error";
      state.decisionFailures ??= {};
      state.decisionFailures[failureClass] = (state.decisionFailures[failureClass] ?? 0) + 1;
      await this.audit.write({
        event: "acs_decision_failure",
        session_id: state.sessionId,
        ...(request ? { request_id: request.params.request_id } : {}),
        method,
        failure_class: failureClass,
        ...failureFields(failure),
        posture: method === "handshake/hello" ? this.config.startupPosture : this.failurePosture(state),
        message: `ACS exchange failed: ${failureClass}`,
      });
      throw failure;
    } finally {
      release();
      if (this.requestQueues.get(state.sessionId) === current) this.requestQueues.delete(state.sessionId);
    }
  }

  private async performRequest(
    state: SessionState,
    request: AcsRequestEnvelope,
    explicitTimeout?: number,
  ): Promise<AcsResult | ServerHello> {
    const { method } = request;
    const sessionKey = this.inputKeyMaterial ? deriveSessionKey(this.inputKeyMaterial, state.sessionId) : undefined;
    if (sessionKey && this.config.guardian.keyId && method !== "system/ping") {
      request.params.signature = signEnvelope(request, sessionKey, this.config.guardian.keyId);
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

    const { envelope: response, status } = await this.fetchResponse(request, timeout);
    // Carried on every failure derived from this response so the audit record keeps the
    // HTTP status when an envelope rode a non-2xx answer.
    const detail: AcsClientErrorDetail = status === undefined ? {} : { status };

    try {
      validateResponse(response);
    } catch (error) {
      throw new AcsClientError("invalid_schema", (error as Error).message, error, detail);
    }
    if (response.id !== request.id) throw new AcsClientError("correlation", "JSON-RPC response id does not match request", undefined, detail);
    if (response.error) {
      if (
        sessionKey && method !== "system/ping" && (
          !response.error.signature
          || response.error.signature.key_id !== this.config.guardian.keyId
          || !verifyEnvelope(response, sessionKey, response.error.signature)
        )
      ) {
        throw new AcsClientError("signature", "Guardian error response signature is missing or invalid", undefined, detail);
      }
      throw new AcsClientError("guardian_error", response.error.message, response.error, { ...detail, code: response.error.code });
    }
    if (status !== undefined) {
      // A success body on a failure status is contradictory; neither half can be trusted.
      throw new AcsClientError("invalid_schema", `Guardian returned a result on HTTP ${status}`, undefined, detail);
    }
    if (!response.result) throw new AcsClientError("invalid_schema", "response has neither result nor error");
    if (isServerHello(response.result)) {
      if (method !== "handshake/hello") {
        throw new AcsClientError("invalid_schema", "Guardian returned ServerHello outside handshake/hello");
      }
      const signature = response.result.signature;
      if (sessionKey) {
        if (
          !signature
          || signature.key_id !== this.config.guardian.keyId
          || !verifyEnvelope(response, sessionKey, signature)
        ) {
          throw new AcsClientError("signature", "Direct ServerHello signature is missing or invalid");
        }
      } else if (new URL(this.config.guardian.url).protocol !== "https:") {
        throw new AcsClientError("signature", "Unsigned direct ServerHello requires an authenticated HTTPS Guardian transport");
      }
      return response.result;
    }
    const result = response.result;
    if (result.request_id !== request.params.request_id) {
      throw new AcsClientError("correlation", "ACS response request_id does not match request");
    }
    if (result.acs_version !== ACS_VERSION) {
      throw new AcsClientError("correlation", `ACS response uses unexpected version ${result.acs_version}`);
    }
    if (sessionKey && method !== "system/ping") {
      if (
        !result.signature
        || result.signature.key_id !== this.config.guardian.keyId
        || !verifyEnvelope(response, sessionKey, result.signature)
      ) {
        throw new AcsClientError("signature", "Guardian response signature is missing or invalid");
      }
    }

    if (method === "system/ping" && (result.decision !== "allow" || result.chain_hash)) {
      throw new AcsClientError("guardian_error", "system/ping must return ALLOW without a chain hash");
    }
    if (result.chain_hash) state.chainHash = result.chain_hash;
    await this.audit.write({
      event: "acs_decision",
      session_id: state.sessionId,
      request_id: request.params.request_id,
      method,
      decision: result.decision,
      payload: result,
    });
    return result;
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

  private async fetchResponse(
    request: AcsRequestEnvelope,
    timeoutMs: number,
  ): Promise<{ envelope: AcsResponseEnvelope; status?: number }> {
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
      const status = response.status;
      const declaredLength = Number(response.headers.get("content-length"));
      if (Number.isFinite(declaredLength) && declaredLength > this.config.guardian.maxResponseBytes) {
        throw new AcsClientError("response_too_large", "Guardian response exceeds configured limit", undefined, response.ok ? {} : { status });
      }
      let text: string;
      try {
        text = await this.readBoundedBody(response, this.config.guardian.maxResponseBytes);
      } catch (error) {
        // Keep the oversize cause; an abort mid-body falls through to the timeout check below.
        if (error instanceof AcsClientError && !response.ok) throw new AcsClientError(error.kind, error.message, error.causeValue, { status });
        throw error;
      }
      if (!response.ok) {
        // §17.1 refusals and signed errors can ride on a 4xx/5xx. Read the body before
        // classifying by status so an authenticated refusal is not discarded.
        const envelope = jsonRpcEnvelope(text);
        if (envelope) return { envelope, status };
        throw new AcsClientError("http", `Guardian returned HTTP ${status}`, undefined, { status });
      }
      try {
        return { envelope: JSON.parse(text) as AcsResponseEnvelope };
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
