import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AcsConfig } from "./config.js";
import { ACS_VERSION, ADAPTER_VERSION, OPENCODE_VERSION } from "./types.js";

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
    if (!this.config.path) return;
    const record = {
      timestamp: new Date().toISOString(),
      adapter_version: ADAPTER_VERSION,
      opencode_version: OPENCODE_VERSION,
      acs_version: ACS_VERSION,
      ...event,
      ...(!this.config.includePayloads && "payload" in event ? { payload: "[omitted]" } : {}),
    };
    try {
      await mkdir(dirname(this.config.path), { recursive: true });
      await appendFile(this.config.path, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
    } catch {
      // Audit recording is passive and never changes an enforcement decision.
    }
  }
}
