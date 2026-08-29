import { randomBytes, randomUUID } from "node:crypto";
import type { AcsConfig } from "./config.js";
import type { AcsRequestEnvelope, JsonObject, JsonValue, SessionState } from "./types.js";
import { ACS_VERSION, OPENCODE_VERSION } from "./types.js";

export const METHODS_IMPLEMENTED = [
  "steps/sessionStart",
  "steps/sessionEnd",
  "steps/toolCallRequest",
  "steps/toolCallResult",
] as const;

function jsonValue(value: unknown): JsonValue {
  if (value === undefined) return null;
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

export function newSessionState(sessionId: string): SessionState {
  return { sessionId: randomUUID(), hostSessionId: sessionId, guarded: false, refuseActions: false };
}

export function buildRequest(config: AcsConfig, state: SessionState, method: string, payload: JsonObject): AcsRequestEnvelope {
  const requestId = randomUUID();
  return {
    jsonrpc: "2.0",
    method,
    id: requestId,
    params: {
      acs_version: ACS_VERSION,
      request_id: requestId,
      timestamp: new Date().toISOString(),
      nonce: randomBytes(16).toString("hex"),
      metadata: {
        agent_id: config.agent.id,
        ...(config.agent.name ? { agent_name: config.agent.name } : {}),
        session_id: state.sessionId,
        ...(state.chainHash ? { session_state: { chain_hash: state.chainHash } } : {}),
        environment: config.agent.environment,
        platform: "opencode",
        platform_version: OPENCODE_VERSION,
      },
      payload,
    },
  };
}

export function clientHello(): JsonObject {
  return {
    acs_versions_supported: [ACS_VERSION],
    methods_implemented: [...METHODS_IMPLEMENTED],
    transports_supported: ["http", "https"],
    max_payload_size_bytes: 1_048_576,
    provenance_producer: "none",
    wrapped_protocols: [],
    profiles_supported: [],
  };
}

export function toolCallPayload(toolName: string, input: Record<string, unknown>): JsonObject {
  const argumentsObject: JsonObject = {};
  for (const [name, value] of Object.entries(input)) argumentsObject[name] = { value: jsonValue(value) };
  return {
    tool: { name: toolName },
    arguments: argumentsObject,
    ...(typeof input.command === "string" ? { raw_command: input.command } : {}),
  };
}

export function toolResultPayload(
  toolName: string,
  requestId: string | undefined,
  output: { title?: unknown; output?: unknown; metadata?: unknown },
): JsonObject {
  const metadata = typeof output.metadata === "object" && output.metadata !== null && !Array.isArray(output.metadata)
    ? output.metadata as Record<string, unknown>
    : undefined;
  const exitStatus = typeof metadata?.exit === "number" && metadata.exit !== 0 ? "failure" : "success";
  return {
    tool: { name: toolName },
    ...(requestId ? { request_id_ref: requestId } : {}),
    exit_status: exitStatus,
    outputs: [{ value: jsonValue({ title: output.title, output: output.output, metadata: output.metadata }) }],
  };
}
