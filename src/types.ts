export const ACS_VERSION = "0.1.0" as const;
export const OPENCODE_VERSION = "1.18.20" as const;
export const ADAPTER_VERSION = "0.1.0-alpha.1" as const;

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };
export type AcsDecision = "allow" | "deny" | "modify" | "ask" | "defer";

export interface AcsSignature {
  algorithm: "HMAC-SHA256";
  value: string;
  key_id: string;
}

export interface AcsRequestEnvelope {
  jsonrpc: "2.0";
  method: string;
  id: string;
  params: {
    acs_version: string;
    request_id: string;
    timestamp: string;
    nonce?: string;
    metadata: {
      agent_id: string;
      agent_name?: string;
      session_id: string;
      turn_id?: string;
      session_state?: { chain_hash: string };
      environment?: "development" | "staging" | "production";
      platform: string;
      platform_version: string;
    };
    payload: JsonObject;
    signature?: AcsSignature;
  };
}

export interface AcsModifications {
  modified_content?: string;
  redactions?: Array<{ path: string; replacement?: string }>;
  parameter_overrides?: Record<string, JsonValue>;
}

export interface AcsResult {
  type: "final";
  acs_version: string;
  request_id: string;
  decision: AcsDecision;
  reasoning?: string;
  reason_codes?: string[];
  modifications?: AcsModifications;
  ask_details?: JsonObject;
  defer_details?: JsonObject;
  payload?: JsonObject;
  chain_hash?: string;
  signature?: AcsSignature;
  [key: string]: unknown;
}

export interface AcsResponseEnvelope {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: AcsResult;
  error?: { code: number; message: string; data?: unknown };
}

export interface ServerHello {
  negotiated_version: string;
  methods_evaluated: string[];
  selected_transport: "http" | "https" | "stdio";
  signature_algorithms_supported?: string[];
  timeout_config: {
    default_ms: number;
    per_method_ms?: Record<string, number>;
  };
  skew_window_ms?: number;
  on_decision_failure?: "proceed" | "deny";
  policy_requires_provenance?: boolean;
  profiles_accepted?: string[];
  [key: string]: unknown;
}

export interface SessionState {
  sessionId: string;
  hostSessionId: string;
  chainHash?: string;
  handshake?: ServerHello;
  guarded: boolean;
  refuseActions: boolean;
}

export type AcsFailureKind =
  | "configuration"
  | "timeout"
  | "transport"
  | "http"
  | "request_too_large"
  | "response_too_large"
  | "invalid_json"
  | "invalid_schema"
  | "correlation"
  | "signature"
  | "guardian_error"
  | "unsupported_decision"
  | "invalid_modification";

export class AcsClientError extends Error {
  constructor(
    public readonly kind: AcsFailureKind,
    message: string,
    public readonly causeValue?: unknown,
  ) {
    super(message);
    this.name = "AcsClientError";
  }
}
