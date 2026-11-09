import { describe, expect, it } from "vitest";
import type { AcsConfig } from "../src/config.js";
import {
  buildRequest,
  clientHello,
  newSessionState,
  subagentStartPayload,
  subagentStopPayload,
  toolCallPayload,
  toolResultPayload,
} from "../src/mapper.js";
import { validateRequest, validateResponse } from "../src/schema.js";

const config = {
  mode: "observe",
  startupPosture: "proceed",
  enableModify: false,
  guardian: { url: "https://guardian.example/", connectTimeoutMs: 100, maxResponseBytes: 1024 },
  audit: { includePayloads: false },
  agent: { id: "opencode", environment: "development" },
} satisfies AcsConfig;

describe("ACS mapping", () => {
  it("maps OpenCode's host session id to a canonical ACS UUID", () => {
    const state = newSessionState("ses_host_specific");
    expect(state.hostSessionId).toBe("ses_host_specific");
    expect(state.sessionId).toMatch(/^[0-9a-f-]{36}$/);
    const request = buildRequest(config, state, "handshake/hello", clientHello());
    expect(() => validateRequest(request)).not.toThrow();
    expect(request.params.metadata.platform).toBe("opencode");
    expect(request.params.metadata.platform_version).toBe("1.18.20");
  });

  it("validates tool request and result payloads", () => {
    const state = newSessionState("ses_host_specific");
    const toolRequest = buildRequest(config, state, "steps/toolCallRequest", toolCallPayload("bash", { command: "true" }));
    expect(() => validateRequest(toolRequest)).not.toThrow();
    const result = buildRequest(config, state, "steps/toolCallResult", toolResultPayload("bash", toolRequest.params.request_id, {
      title: "true",
      output: "",
      metadata: { exit: 0 },
    }));
    expect(() => validateRequest(result)).not.toThrow();
    expect(result.params.payload.exit_status).toBe("success");

    const failure = buildRequest(config, state, "steps/toolCallResult", toolResultPayload("bash", toolRequest.params.request_id, {
      title: "false",
      output: "",
      metadata: { exit: 1 },
    }));
    expect(() => validateRequest(failure)).not.toThrow();
    expect(failure.params.payload.exit_status).toBe("failure");
  });

  it("validates a task launch as a correlated subagent lifecycle", () => {
    const parent = newSessionState("ses_parent");
    const child = newSessionState("pending:call_task");
    const requestId = "00000000-0000-4000-8000-000000000001";
    const start = buildRequest(config, parent, "steps/subagentStart", subagentStartPayload(
      parent,
      child,
      requestId,
      { prompt: "inspect the repository", subagent_type: "general" },
    ), requestId);
    expect(() => validateRequest(start)).not.toThrow();
    expect(start.params.request_id).toBe(requestId);
    expect(start.params.payload.parent_step_id).toBe(requestId);
    expect(start.params.payload.subagent_session_id).toBe(child.sessionId);

    const stop = buildRequest(config, parent, "steps/subagentStop", subagentStopPayload(child, "completed"));
    expect(() => validateRequest(stop)).not.toThrow();
  });
});


describe("refreshed ACS schema constraints", () => {
  it.each([undefined, "tool-output", ""])("validates provenance source_id %j", (sourceId) => {
    const request = buildRequest(config, newSessionState("ses_schema_test"), "steps/toolCallRequest", {
      tool: { name: "bash" },
      arguments: {
        command: {
          value: "pwd",
          provenance: {
            provenance_id: "source-1",
            origin: "tool_output",
            ...(sourceId === undefined ? {} : { source_id: sourceId }),
          },
        },
      },
    });
    if (sourceId === "") {
      expect(() => validateRequest(request)).toThrow(/source_id.*fewer than 1 characters/);
    } else {
      expect(() => validateRequest(request)).not.toThrow();
    }
  });

  it.each(["policy_id", "policy_version", "policy_name", "rule_id"])(
    "requires nonempty %s only when present",
    (field) => {
      for (const value of [undefined, "policy-1", ""]) {
        const response = {
          jsonrpc: "2.0" as const,
          id: "decision-1",
          result: {
            type: "final" as const,
            acs_version: "0.1.0",
            request_id: "00000000-0000-4000-8000-000000000001",
            decision: "allow" as const,
            policy_references: [value === undefined ? {} : { [field]: value }],
          },
        };
        if (value === "") {
          expect(() => validateResponse(response)).toThrow(new RegExp(`${field}.*fewer than 1 characters`));
        } else {
          expect(() => validateResponse(response)).not.toThrow();
        }
      }
    },
  );

  const failureClasses = [
    "timeout", "unreachable", "malformed_response", "guardian_error",
    "observed_agent_error", "signature_invalid", "handshake_failure", "other",
  ];

  it.each(failureClasses)("validates session-end %s counters", (failureClass) => {
    for (const count of [0, 2, -1, 0.5, "1", null, true]) {
      const request = buildRequest(config, newSessionState("ses_schema_test"), "steps/sessionEnd", {
        reason: "completed",
        summary: { decision_failures: { [failureClass]: count } },
      });
      if (count === 0 || count === 2) {
        expect(() => validateRequest(request)).not.toThrow();
      } else {
        expect(() => validateRequest(request)).toThrow(/decision_failures/);
      }
    }
  });

  it("keeps failure counters optional and rejects unknown classes and nonobjects", () => {
    for (const payload of [
      { reason: "completed" },
      { reason: "completed", summary: {} },
      { reason: "completed", summary: { decision_failures: {} } },
    ]) {
      expect(() => validateRequest(buildRequest(config, newSessionState("ses_schema_test"), "steps/sessionEnd", payload))).not.toThrow();
    }
    for (const failures of [{ unknown: 1 }, [], null, 1, "timeout"]) {
      const request = buildRequest(config, newSessionState("ses_schema_test"), "steps/sessionEnd", {
        reason: "completed", summary: { decision_failures: failures },
      });
      expect(() => validateRequest(request)).toThrow(/decision_failures/);
    }
  });
});
