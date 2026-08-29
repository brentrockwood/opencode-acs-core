import { describe, expect, it } from "vitest";
import { CapabilityIssuer, ProtectedResource } from "../examples/protected-resource-demo.js";

const secret = Buffer.alloc(32, 7);
const use = {
  subject: "enrolled-opencode-session",
  action: "deploy",
  resource: "service:acs-demo",
};

describe("protected-resource capability demonstration", () => {
  it("accepts one short-lived capability bound to an ACS ALLOW", () => {
    const issuer = new CapabilityIssuer(secret, 30);
    const resource = new ProtectedResource(secret);
    const token = issuer.issue({ decision: "allow", requestId: "acs-request-1" }, use, 100);
    expect(resource.authorize(token, use, 101).acs_request_id).toBe("acs-request-1");
    expect(() => resource.authorize(token, use, 101)).toThrow("already been used");
  });

  it("rejects a token for a different action or an expired token", () => {
    const issuer = new CapabilityIssuer(secret, 5);
    const token = issuer.issue({ decision: "allow", requestId: "acs-request-2" }, use, 100);
    expect(() => new ProtectedResource(secret).authorize(token, { ...use, action: "delete" }, 101)).toThrow("not bound");
    expect(() => new ProtectedResource(secret).authorize(token, use, 106)).toThrow("expired");
  });

  it("rejects a forged capability", () => {
    const token = new CapabilityIssuer(secret).issue({ decision: "allow", requestId: "acs-request-3" }, use, 100);
    expect(() => new ProtectedResource(Buffer.alloc(32, 8)).authorize(token, use, 101)).toThrow("signature is invalid");
  });

  it("does not issue a capability for a denied decision", () => {
    const issuer = new CapabilityIssuer(secret);
    const denied = { decision: "deny", requestId: "acs-request-4" } as unknown as Parameters<typeof issuer.issue>[0];
    expect(() => issuer.issue(denied, use, 100)).toThrow("requires a correlated ACS ALLOW");
  });
});
