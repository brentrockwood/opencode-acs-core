import { AcsClientError } from "./types.js";

/**
 * How a failed Guardian exchange is resolved.
 *
 * The pinned specification (§4.1, §6.4) distinguishes a Guardian that answered from
 * one that did not. The maintainers' rulings on issue #32 (2026-11-04 and 2026-11-05)
 * spell out the split this adapter applies locally:
 *
 * - `availability`: no usable answer arrived. The configured posture decides:
 *   `startupPosture` for the handshake, the negotiated `on_decision_failure` after it.
 *   Covers a silent Guardian, a connection or TLS failure, HTTP 408 or 5xx without a
 *   JSON-RPC body, and an authenticated `-32603` internal error.
 * - `refusal`: the Guardian answered and declined. Covers every authenticated JSON-RPC
 *   error other than `-32603` (including `SESSION_REFUSED`, `UNSUPPORTED_VERSION` and
 *   `PROVENANCE_REQUIRED`) and any other HTTP 4xx without a JSON-RPC body.
 * - `integrity`: the answer cannot be trusted or the adapter could not form a valid
 *   request. Covers a missing or invalid signature, an unexpected key label, a JSON-RPC
 *   id or `request_id` mismatch, malformed or oversized bodies, unsupported decisions,
 *   and local request faults.
 *
 * Refusal and integrity block in enforce mode under either posture. Observe mode never
 * blocks. The default posture itself is unchanged by this classification.
 */
export type FailureDisposition = "availability" | "refusal" | "integrity";

export function failureDisposition(error: unknown): FailureDisposition {
  if (!(error instanceof AcsClientError)) return "integrity";
  switch (error.kind) {
    case "timeout":
    case "transport":
      return "availability";
    case "http":
      return error.status === 408 || (error.status !== undefined && error.status >= 500) ? "availability" : "refusal";
    case "guardian_error":
      return error.code === -32603 ? "availability" : "refusal";
    default:
      return "integrity";
  }
}

export interface FailureFields {
  failure_kind: string;
  disposition: FailureDisposition;
  error_code?: number;
  http_status?: number;
}

/** Machine-readable cause fields for local audit records. Never includes message text. */
export function failureFields(error: unknown): FailureFields {
  const fields: FailureFields = {
    failure_kind: error instanceof AcsClientError ? error.kind : "other",
    disposition: failureDisposition(error),
  };
  if (error instanceof AcsClientError) {
    if (error.code !== undefined) fields.error_code = error.code;
    if (error.status !== undefined) fields.http_status = error.status;
  }
  return fields;
}
