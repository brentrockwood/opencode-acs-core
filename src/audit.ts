import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AcsConfig } from "./config.js";
import { AcsClientError, type DecisionFailureClass, ACS_VERSION, ADAPTER_VERSION, OPENCODE_VERSION } from "./types.js";

export interface AuditEvent {
  event: string;
  session_id?: string;
  call_id?: string;
  request_id?: string;
  method?: string;
  tool?: string;
  decision?: string;
  failure_kind?: string;
  message?: string;
  payload?: unknown;
  [key: string]: unknown;
}

export class AuditSink {
  constructor(private readonly config: AcsConfig["audit"]) {}

  async write(event: AuditEvent): Promise<void> {
    const record = {
      timestamp: new Date().toISOString(),
      adapter_version: ADAPTER_VERSION,
      opencode_version: OPENCODE_VERSION,
      acs_version: ACS_VERSION,
      ...event,
      ...(!this.config.includePayloads && "payload" in event ? { payload: "[omitted]" } : {}),
      ...(!this.config.includePayloads && "message" in event ? { message: "[omitted]" } : {}),
    };
    const fallback = () => console.error(JSON.stringify({
      ...record,
      ...("payload" in event ? { payload: "[omitted]" } : {}),
      ...("message" in event ? { message: "[omitted]" } : {}),
    }));
    if (!this.config.path) {
      if (event.event === "acs_decision_failure") fallback();
      return;
    }
    try {
      await mkdir(dirname(this.config.path), { recursive: true });
      await appendFile(this.config.path, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
    } catch {
      // Preserve the decision; stderr is the fallback audit sink.
      fallback();
    }
  }
}

export function decisionFailureClass(error: unknown): DecisionFailureClass {
  if (!(error instanceof AcsClientError)) return "other";
  switch (error.kind) {
    case "timeout": return "timeout";
    case "transport": return "unreachable";
    case "http":
    case "guardian_error": return "guardian_error";
    case "signature": return "signature_invalid";
    case "invalid_json":
    case "invalid_schema":
    case "correlation":
    case "response_too_large": return "malformed_response";
    case "configuration":
    case "request_too_large":
    case "unsupported_decision":
    case "invalid_modification": return "observed_agent_error";
  }
}
