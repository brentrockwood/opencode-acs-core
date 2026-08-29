import { describe, expect, it } from "vitest";
import type { AcsConfig } from "../src/config.js";
import { applyTopLevelOverrides, resolveDecision } from "../src/enforcer.js";
import type { AcsResult } from "../src/types.js";

const config = {
  mode: "enforce",
  startupPosture: "refuse",
  enableModify: true,
  guardian: { url: "http://127.0.0.1/", connectTimeoutMs: 100, maxResponseBytes: 1024 },
  audit: { includePayloads: false },
  agent: { id: "opencode", environment: "development" },
} satisfies AcsConfig;

function result(decision: AcsResult["decision"], extra: Partial<AcsResult> = {}): AcsResult {
  return { type: "final", acs_version: "0.1.0", request_id: "request", decision, ...extra };
}

describe("enforcement decisions", () => {
  it("allows and denies", () => {
    expect(resolveDecision(result("allow"), config, "bash", { command: "true" }).action).toBe("allow");
    expect(resolveDecision(result("deny", { reasoning: "policy" }), config, "bash", { command: "true" })).toMatchObject({ action: "deny", reason: "policy" });
  });

  it("fails closed on ASK and DEFER", () => {
    expect(resolveDecision(result("ask"), config, "bash", { command: "true" }).action).toBe("deny");
    expect(resolveDecision(result("defer"), config, "bash", { command: "true" }).action).toBe("deny");
  });

  it("permits only a Bash command replacement", () => {
    expect(resolveDecision(result("modify", {
      modifications: { parameter_overrides: { command: "printf safe" } },
    }), config, "bash", { command: "printf unsafe" })).toMatchObject({
      action: "modify",
      replacement: { command: "printf safe" },
    });
    expect(resolveDecision(result("modify", {
      modifications: { parameter_overrides: { path: "/tmp/x" } },
    }), config, "write", { path: "/tmp/y" }).action).toBe("deny");
    expect(resolveDecision(result("modify", {
      modifications: { parameter_overrides: { command: "true", timeout: 1 } },
    }), config, "bash", { command: "false" }).action).toBe("deny");
  });

  it("applies a validated override to the same argument object", () => {
    const args: Record<string, unknown> = { command: "original", description: "test" };
    applyTopLevelOverrides(args, { command: "modified" });
    expect(args).toEqual({ command: "modified", description: "test" });
  });
});
