import type { AcsConfig } from "./config.js";
import { AcsClientError, type AcsResult } from "./types.js";

export type GateOutcome =
  | { action: "allow"; requestId?: string; capability?: string }
  | { action: "deny"; reason: string; requestId?: string }
  | { action: "modify"; replacement: Record<string, unknown>; requestId?: string };

export function resolveDecision(
  result: AcsResult,
  config: AcsConfig,
  tool: string,
  original: Record<string, unknown>,
): GateOutcome {
  if (result.decision === "allow") return { action: "allow", requestId: result.request_id };
  if (result.decision === "deny") {
    return { action: "deny", reason: result.reasoning ?? "Denied by ACS Guardian", requestId: result.request_id };
  }
  if (result.decision === "ask" || result.decision === "defer") {
    return {
      action: "deny",
      reason: `Guardian returned unsupported ${result.decision.toUpperCase()} decision`,
      requestId: result.request_id,
    };
  }
  if (!config.enableModify) {
    return { action: "deny", reason: "Guardian returned MODIFY but modification is disabled", requestId: result.request_id };
  }
  if (!result.modifications?.parameter_overrides
    || result.modifications.modified_content !== undefined
    || (result.modifications.redactions?.length ?? 0) > 0) {
    return { action: "deny", reason: "Guardian returned an unsupported modification shape", requestId: result.request_id };
  }
  if (tool !== "bash") {
    return { action: "deny", reason: `MODIFY is not supported for ${tool}`, requestId: result.request_id };
  }
  const overrides = result.modifications.parameter_overrides;
  if (Object.keys(overrides).some((key) => key !== "command")
    || typeof overrides.command !== "string"
    || overrides.command.length === 0
    || typeof original.command !== "string") {
    return {
      action: "deny",
      reason: "Bash MODIFY supports only a non-empty command replacement",
      requestId: result.request_id,
    };
  }
  return {
    action: "modify",
    replacement: { command: overrides.command },
    requestId: result.request_id,
  };
}

export function applyTopLevelOverrides(target: Record<string, unknown>, overrides: Record<string, unknown>): void {
  if (Object.getPrototypeOf(target) !== Object.prototype && Object.getPrototypeOf(target) !== null) {
    throw new AcsClientError("invalid_modification", "tool arguments must be a plain object");
  }
  for (const [key, value] of Object.entries(overrides)) target[key] = structuredClone(value);
}
