import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin/tool";
import { AcsClient } from "./client.js";
import { loadConfig } from "./config.js";
import { applyTopLevelOverrides, resolveDecision, type GateOutcome } from "./enforcer.js";
import { newSessionState, toolCallPayload, toolResultPayload } from "./mapper.js";
import { appendProtectedValue, PROTECTED_TOOL } from "./protected.js";
import { AcsClientError, type JsonObject, type SessionState } from "./types.js";

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function key(sessionID: string, callID: string): string {
  return `${sessionID}\u0000${callID}`;
}

function protectedKey(sessionID: string, value: string): string {
  return `${sessionID}\u0000${value}`;
}

export const AcsPlugin: Plugin = async ({ directory, client: openCodeClient }) => {
  const loaded = loadConfig(directory);
  if (!loaded) return {};
  const config = loaded;
  const client = new AcsClient(config);
  const sessions = new Map<string, SessionState>();
  const starts = new Map<string, Promise<SessionState>>();
  const toolRequests = new Map<string, { requestId?: string; tool: string }>();
  const protectedCapabilities = new Map<string, string[]>();

  async function log(level: "debug" | "info" | "warn" | "error", text: string, extra?: Record<string, unknown>): Promise<void> {
    await openCodeClient.app.log({
      body: { service: "opencode-acs-core", level, message: text, ...(extra ? { extra } : {}) },
    }).catch(() => undefined);
  }

  async function initialize(sessionID: string): Promise<SessionState> {
    const existing = sessions.get(sessionID);
    if (existing) return existing;
    const pending = starts.get(sessionID);
    if (pending) return pending;
    const start = (async () => {
      const state = newSessionState(sessionID);
      sessions.set(sessionID, state);
      try {
        state.handshake = await client.handshake(state);
        state.guarded = true;
        const result = await client.request(state, "steps/sessionStart", {});
        if (client.isEvaluated(state, "steps/sessionStart") && result.decision !== "allow") {
          state.refuseActions = config.mode === "enforce";
          await client.record({
            event: "acs_session_start_rejected",
            session_id: state.sessionId,
            host_session_id: sessionID,
            decision: result.decision,
          });
        }
      } catch (error) {
        state.guarded = false;
        state.refuseActions = config.mode === "enforce" && config.startupPosture === "refuse";
        await client.record({
          event: state.refuseActions ? "acs_startup_refused" : "acs_session_unguarded",
          session_id: state.sessionId,
          host_session_id: sessionID,
          failure_kind: error instanceof AcsClientError ? error.kind : "transport",
          message: message(error),
        });
        await log(state.refuseActions ? "error" : "warn", `Guardian handshake failed: ${message(error)}`);
      }
      return state;
    })();
    starts.set(sessionID, start);
    try {
      return await start;
    } finally {
      starts.delete(sessionID);
    }
  }

  async function guardTool(
    sessionID: string,
    callID: string,
    tool: string,
    args: Record<string, unknown>,
  ): Promise<GateOutcome> {
    const state = await initialize(sessionID);
    if (state.refuseActions && config.mode === "enforce") {
      return { action: "deny", reason: "ACS session is not guarded and startup posture is refuse" };
    }
    try {
      const decisionArgs = tool === PROTECTED_TOOL
        ? Object.fromEntries(Object.entries(args).filter(([name]) => name !== "capability"))
        : args;
      const result = await client.request(state, "steps/toolCallRequest", toolCallPayload(tool, decisionArgs));
      if (!client.isEvaluated(state, "steps/toolCallRequest") || config.mode === "observe") {
        await client.record({
          event: config.mode === "observe" ? "acs_observe_only" : "acs_unevaluated_allow",
          session_id: state.sessionId,
          host_session_id: sessionID,
          call_id: callID,
          request_id: result.request_id,
          method: "steps/toolCallRequest",
          decision: result.decision,
        });
        return { action: "allow", requestId: result.request_id };
      }
      const outcome = resolveDecision(result, config, tool, decisionArgs);
      if (tool === PROTECTED_TOOL && config.protectedResource && outcome.action === "allow") {
        const capability = result.payload?.capability;
        if (typeof capability !== "string" || capability.length === 0) {
          return { action: "deny", reason: "Guardian ALLOW did not include a protected-resource capability", requestId: result.request_id };
        }
        return { ...outcome, capability };
      }
      return outcome;
    } catch (error) {
      const blocks = config.mode === "enforce" && (state.handshake ? client.failurePosture(state) === "deny" : config.startupPosture === "refuse");
      if (blocks) return { action: "deny", reason: `ACS decision failure: ${message(error)}` };
      await client.record({
        event: "acs_fail_open",
        session_id: state.sessionId,
        host_session_id: sessionID,
        call_id: callID,
        method: "steps/toolCallRequest",
        failure_kind: error instanceof AcsClientError ? error.kind : "transport",
        message: message(error),
      });
      return { action: "allow" };
    }
  }

  return {
    ...(config.protectedResource ? {
      tool: {
        [PROTECTED_TOOL]: tool({
          description: "Append a value to the remotely capability-gated ACS demonstration resource",
          args: {
            value: tool.schema.string().min(1).max(512),
          },
          async execute(args, context) {
            const capabilityKey = protectedKey(context.sessionID, args.value);
            const queued = protectedCapabilities.get(capabilityKey);
            const capability = queued?.shift();
            if (!queued || !capability) throw new Error("protected-resource capability is unavailable");
            if (queued.length === 0) protectedCapabilities.delete(capabilityKey);
            return appendProtectedValue(config.protectedResource!, capability, args.value, context.abort);
          },
        }),
      },
    } : {}),
    "tool.execute.before": async (input, output) => {
      const args = output.args as Record<string, unknown>;
      const outcome = await guardTool(input.sessionID, input.callID, input.tool, args);
      const canonicalSessionID = sessions.get(input.sessionID)?.sessionId;
      if (outcome.action === "deny") {
        await client.record({
          event: "acs_tool_blocked",
          ...(canonicalSessionID ? { session_id: canonicalSessionID } : {}),
          host_session_id: input.sessionID,
          call_id: input.callID,
          ...(outcome.requestId ? { request_id: outcome.requestId } : {}),
          tool: input.tool,
          decision: "deny",
          message: outcome.reason,
        });
        throw new Error(`ACS denied ${input.tool}: ${outcome.reason}`);
      }
      if (outcome.action === "allow" && outcome.capability) {
        const value = args.value;
        if (typeof value !== "string") throw new Error("protected-resource value is missing after Guardian ALLOW");
        const capabilityKey = protectedKey(input.sessionID, value);
        const queued = protectedCapabilities.get(capabilityKey) ?? [];
        queued.push(outcome.capability);
        protectedCapabilities.set(capabilityKey, queued);
      }
      toolRequests.set(key(input.sessionID, input.callID), {
        ...(outcome.requestId ? { requestId: outcome.requestId } : {}),
        tool: input.tool,
      });
      if (outcome.action === "modify") {
        applyTopLevelOverrides(args, outcome.replacement);
        await client.record({
          event: "acs_tool_modified",
          ...(canonicalSessionID ? { session_id: canonicalSessionID } : {}),
          host_session_id: input.sessionID,
          call_id: input.callID,
          ...(outcome.requestId ? { request_id: outcome.requestId } : {}),
          tool: input.tool,
        });
      }
    },
    "tool.execute.after": async (input, output) => {
      const tracked = toolRequests.get(key(input.sessionID, input.callID));
      toolRequests.delete(key(input.sessionID, input.callID));
      const state = sessions.get(input.sessionID);
      if (!state) return;
      const resultPayload = toolResultPayload(input.tool, tracked?.requestId, output);
      await client.record({
        event: "acs_tool_completed",
        session_id: state.sessionId,
        host_session_id: input.sessionID,
        call_id: input.callID,
        ...(tracked?.requestId ? { request_id: tracked.requestId } : {}),
        tool: input.tool,
        exit_status: resultPayload.exit_status,
      });
      try {
        await client.request(
          state,
          "steps/toolCallResult",
          resultPayload,
        );
      } catch (error) {
        await client.record({
          event: "acs_result_observation_failure",
          session_id: state.sessionId,
          host_session_id: input.sessionID,
          call_id: input.callID,
          ...(tracked?.requestId ? { request_id: tracked.requestId } : {}),
          tool: input.tool,
          failure_kind: error instanceof AcsClientError ? error.kind : "transport",
          message: message(error),
        });
      }
    },
    event: async ({ event }) => {
      const properties = event.properties as JsonObject;
      const info = typeof properties.info === "object" && properties.info !== null && !Array.isArray(properties.info)
        ? properties.info as JsonObject
        : undefined;
      const sessionID = typeof properties.sessionID === "string"
        ? properties.sessionID
        : typeof info?.id === "string" ? info.id : undefined;
      if (event.type === "session.created" && sessionID) await initialize(sessionID);
      if (event.type === "session.deleted" && sessionID) {
        const state = sessions.get(sessionID);
        sessions.delete(sessionID);
        for (const requestKey of toolRequests.keys()) {
          if (requestKey.startsWith(`${sessionID}\u0000`)) toolRequests.delete(requestKey);
        }
        for (const capabilityKey of protectedCapabilities.keys()) {
          if (capabilityKey.startsWith(`${sessionID}\u0000`)) protectedCapabilities.delete(capabilityKey);
        }
        if (state?.guarded) {
          await client.request(state, "steps/sessionEnd", {
            reason: "abandoned",
            ...(state.chainHash ? { final_chain_hash: state.chainHash } : {}),
          }).catch(() => undefined);
        }
      }
    },
  };
};

export default AcsPlugin;
