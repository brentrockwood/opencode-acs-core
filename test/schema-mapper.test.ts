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
import { validateRequest } from "../src/schema.js";

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
