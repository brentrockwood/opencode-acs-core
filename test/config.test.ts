import { describe, expect, it } from "vitest";
import { parseConfig } from "../src/config.js";

const base = {
  guardian: { url: "http://127.0.0.1:8787" },
};

describe("configuration", () => {
  it("uses observation defaults", () => {
    const config = parseConfig(base, "/work");
    expect(config.mode).toBe("observe");
    expect(config.startupPosture).toBe("proceed");
    expect(config.enableModify).toBe(false);
    expect(config.audit.includePayloads).toBe(false);
    expect(config.agent.id).toBe("opencode");
  });

  it("requires explicit fail posture and HMAC in enforce mode", () => {
    expect(() => parseConfig({ ...base, mode: "enforce" }, "/work")).toThrow("startupPosture must be explicit");
    expect(() => parseConfig({ ...base, mode: "enforce", startupPosture: "refuse" }, "/work")).toThrow("required in enforce mode");
  });

  it("accepts a signed loopback enforcement configuration", () => {
    const config = parseConfig({
      mode: "enforce",
      startupPosture: "refuse",
      enableModify: true,
      guardian: { url: "http://localhost:8787", hmacKeyEnv: "ACS_KEY", keyId: "key-1" },
      audit: { path: "audit/events.jsonl" },
    }, "/work");
    expect(config.guardian.url).toBe("http://localhost:8787/");
    expect(config.audit.path).toBe("/work/audit/events.jsonl");
    expect(config.enableModify).toBe(true);
  });

  it("accepts a protected HTTPS resource only in enforcement mode", () => {
    const config = parseConfig({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: { url: "https://guardian.example/acs", hmacKeyEnv: "ACS_KEY", keyId: "key-1" },
      protectedResource: { url: "https://resource.example/protected" },
    }, "/work");
    expect(config.protectedResource).toEqual({
      url: "https://resource.example/protected",
      timeoutMs: 2_000,
      maxResponseBytes: 65_536,
    });
    expect(() => parseConfig({
      ...base,
      protectedResource: { url: "https://resource.example/protected" },
    }, "/work")).toThrow("requires enforce mode");
  });

  it("rejects insecure or ambiguous configuration", () => {
    expect(() => parseConfig({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: { url: "http://guardian.example/", hmacKeyEnv: "ACS_KEY", keyId: "key-1" },
    }, "/work")).toThrow("requires https");
    expect(() => parseConfig({ ...base, surprise: true }, "/work")).toThrow("unknown key");
    expect(() => parseConfig({ guardian: { url: "file:///tmp/guardian" } }, "/work")).toThrow("must use http or https");
  });
});
