import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin/tool";
import { randomUUID } from "node:crypto";
import { AcsClient } from "./client.js";
import { loadConfig } from "./config.js";
import { applyTopLevelOverrides, resolveDecision, type GateOutcome } from "./enforcer.js";
import { newSessionState, subagentStartPayload, subagentStopPayload, toolCallPayload, toolResultPayload } from "./mapper.js";
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

interface PendingSubagent {
  callID: string;
  expectedTitle?: string;
  state: SessionState;
  startRequestId: string;
  boundHostSessionID?: string;
}

export const AcsPlugin: Plugin = async ({ directory, client: openCodeClient }) => {
  const loaded = loadConfig(directory);
  if (!loaded) return {};
  const config = loaded;
  const client = new AcsClient(config);
  const sessions = new Map<string, SessionState>();
  const starts = new Map<string, Promise<SessionState>>();
  const toolRequests = new Map<string, { requestId?: string; tool: string }>();
  const pendingSubagents = new Map<string, PendingSubagent>();
  const subagentCalls = new Map<string, PendingSubagent>();
  const uncorrelatedSubagentCalls = new Set<string>();
  const protectedCapabilities = new Map<string, string[]>();

  async function log(level: "debug" | "info" | "warn" | "error", text: string, extra?: Record<string, unknown>): Promise<void> {
    await openCodeClient.app.log({
      body: { service: "opencode-acs-core", level, message: text, ...(extra ? { extra } : {}) },
    }).catch(() => undefined);
  }

  async function initialize(sessionID: string, preparedState?: SessionState): Promise<SessionState> {
    const pending = starts.get(sessionID);
    if (pending) return pending;
    const existing = sessions.get(sessionID);
    if (existing) return existing;
    const start = (async () => {
      const state = preparedState ?? newSessionState(sessionID);
      state.hostSessionId = sessionID;
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

  async function guardSubagentStart(
    sessionID: string,
    callID: string,
    args: Record<string, unknown>,
  ): Promise<GateOutcome> {
    const parent = await initialize(sessionID);
    if (parent.refuseActions && config.mode === "enforce") {
      return { action: "deny", reason: "ACS session is not guarded and startup posture is refuse" };
    }
    if (pendingSubagents.has(sessionID)) {
      if (config.mode === "observe") {
        uncorrelatedSubagentCalls.add(key(sessionID, callID));
        await client.record({
          event: "acs_subagent_start_unmapped",
          session_id: parent.sessionId,
          host_session_id: sessionID,
          call_id: callID,
          method: "steps/subagentStart",
          message: "concurrent task launch cannot be correlated to a unique OpenCode child session",
        });
        return { action: "allow" };
      }
      return {
        action: "deny",
        reason: "A concurrent task launch cannot be correlated to a unique OpenCode child session",
      };
    }

    const startRequestId = randomUUID();
    const child = newSessionState(`pending:${callID}`);
    const pending: PendingSubagent = {
      callID,
      ...(typeof args.description === "string" && typeof args.subagent_type === "string"
        ? { expectedTitle: `${args.description} (@${String(args.subagent_type)} subagent)` }
        : {}),
      state: child,
      startRequestId,
    };
    pendingSubagents.set(sessionID, pending);
    subagentCalls.set(key(sessionID, callID), pending);

    try {
      const result = await client.request(
        parent,
        "steps/subagentStart",
        subagentStartPayload(parent, child, startRequestId, args),
        undefined,
        startRequestId,
      );
      if (!client.isEvaluated(parent, "steps/subagentStart") || config.mode === "observe") {
        await client.record({
          event: config.mode === "observe" ? "acs_observe_only" : "acs_unevaluated_allow",
          session_id: parent.sessionId,
          host_session_id: sessionID,
          call_id: callID,
          request_id: result.request_id,
          method: "steps/subagentStart",
          decision: result.decision,
        });
        return { action: "allow", requestId: result.request_id };
      }
      if (result.decision === "allow") return { action: "allow", requestId: result.request_id };
      pendingSubagents.delete(sessionID);
      subagentCalls.delete(key(sessionID, callID));
      return {
        action: "deny",
        reason: result.decision === "deny"
          ? result.reasoning ?? "Denied by ACS Guardian"
          : `Guardian returned unsupported ${result.decision.toUpperCase()} for subagentStart`,
        requestId: result.request_id,
      };
    } catch (error) {
      const blocks = config.mode === "enforce"
        && (parent.handshake ? client.failurePosture(parent) === "deny" : config.startupPosture === "refuse");
      if (blocks) {
        pendingSubagents.delete(sessionID);
        subagentCalls.delete(key(sessionID, callID));
        return { action: "deny", reason: `ACS decision failure: ${message(error)}`, requestId: startRequestId };
      }
      await client.record({
        event: "acs_fail_open",
        session_id: parent.sessionId,
        host_session_id: sessionID,
        call_id: callID,
        request_id: startRequestId,
        method: "steps/subagentStart",
        failure_kind: error instanceof AcsClientError ? error.kind : "transport",
        message: message(error),
      });
      return { action: "allow", requestId: startRequestId };
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
      const freshTask = input.tool === "task" && typeof args.task_id !== "string";
      const outcome = freshTask
        ? await guardSubagentStart(input.sessionID, input.callID, args)
        : await guardTool(input.sessionID, input.callID, input.tool, args);
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
      if (!freshTask) {
        toolRequests.set(key(input.sessionID, input.callID), {
          ...(outcome.requestId ? { requestId: outcome.requestId } : {}),
          tool: input.tool,
        });
      }
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
      const callKey = key(input.sessionID, input.callID);
      if (uncorrelatedSubagentCalls.delete(callKey)) {
        const state = sessions.get(input.sessionID);
        await client.record({
          event: "acs_subagent_stop_unmapped",
          ...(state ? { session_id: state.sessionId } : {}),
          host_session_id: input.sessionID,
          call_id: input.callID,
          message: "uncorrelated concurrent task result has no trustworthy subagent lifecycle mapping",
        });
        return;
      }
      const subagent = subagentCalls.get(callKey);
      if (subagent) {
        subagentCalls.delete(callKey);
        const metadata = typeof output.metadata === "object" && output.metadata !== null && !Array.isArray(output.metadata)
          ? output.metadata as Record<string, unknown>
          : undefined;
        const reportedChildID = typeof metadata?.sessionId === "string" ? metadata.sessionId : undefined;
        const reportedParentID = typeof metadata?.parentSessionId === "string" ? metadata.parentSessionId : undefined;
        const state = sessions.get(input.sessionID);
        if (
          state
          && metadata?.background !== true
          && reportedParentID === input.sessionID
          && reportedChildID === subagent.boundHostSessionID
        ) {
          await client.request(state, "steps/subagentStop", subagentStopPayload(subagent.state, "completed"))
            .catch(async (error) => {
              await client.record({
                event: "acs_subagent_stop_observation_failure",
                session_id: state.sessionId,
                host_session_id: input.sessionID,
                call_id: input.callID,
                subagent_session_id: subagent.state.sessionId,
                failure_kind: error instanceof AcsClientError ? error.kind : "transport",
                message: message(error),
              });
            });
        } else {
          await client.record({
            event: "acs_subagent_stop_unmapped",
            ...(state ? { session_id: state.sessionId } : {}),
            host_session_id: input.sessionID,
            call_id: input.callID,
            subagent_session_id: subagent.state.sessionId,
            ...(reportedChildID ? { reported_child_session_id: reportedChildID } : {}),
            message: metadata?.background === true
              ? "background task completion is not observable at tool.execute.after"
              : "task result did not match the child session bound at session.created",
          });
        }
        return;
      }
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
      if (event.type === "session.created" && sessionID) {
        const parentID = typeof info?.parentID === "string" ? info.parentID : undefined;
        const title = typeof info?.title === "string" ? info.title : undefined;
        const pending = parentID ? pendingSubagents.get(parentID) : undefined;
        if (parentID && pending && (!pending.expectedTitle || pending.expectedTitle === title)) {
          pendingSubagents.delete(parentID);
          pending.boundHostSessionID = sessionID;
          await client.record({
            event: "acs_subagent_session_bound",
            session_id: pending.state.sessionId,
            host_session_id: sessionID,
            parent_host_session_id: parentID,
            call_id: pending.callID,
            request_id: pending.startRequestId,
          });
          await initialize(sessionID, pending.state);
        } else {
          await initialize(sessionID);
        }
      }
      if (event.type === "session.deleted" && sessionID) {
        const state = sessions.get(sessionID);
        sessions.delete(sessionID);
        for (const requestKey of toolRequests.keys()) {
          if (requestKey.startsWith(`${sessionID}\u0000`)) toolRequests.delete(requestKey);
        }
        for (const callKey of uncorrelatedSubagentCalls) {
          if (callKey.startsWith(`${sessionID}\u0000`)) uncorrelatedSubagentCalls.delete(callKey);
        }
        for (const capabilityKey of protectedCapabilities.keys()) {
          if (capabilityKey.startsWith(`${sessionID}\u0000`)) protectedCapabilities.delete(capabilityKey);
        }
        const pendingSubagent = pendingSubagents.get(sessionID);
        if (pendingSubagent) {
          pendingSubagents.delete(sessionID);
          subagentCalls.delete(key(sessionID, pendingSubagent.callID));
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
