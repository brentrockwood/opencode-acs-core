import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

export interface CapabilityClaims {
  version: 1;
  capability_id: string;
  acs_request_id: string;
  subject: string;
  action: string;
  resource: string;
  issued_at: number;
  expires_at: number;
}

export interface AllowedDecision {
  decision: "allow";
  requestId: string;
}

export interface CapabilityUse {
  subject: string;
  action: string;
  resource: string;
}

function encode(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function signature(payload: string, secret: Buffer): Buffer {
  return createHmac("sha256", secret).update(payload, "utf8").digest();
}

function parseClaims(payload: string): CapabilityClaims {
  const value = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("capability payload is invalid");
  const claims = value as Partial<CapabilityClaims>;
  if (claims.version !== 1
    || typeof claims.capability_id !== "string"
    || typeof claims.acs_request_id !== "string"
    || typeof claims.subject !== "string"
    || typeof claims.action !== "string"
    || typeof claims.resource !== "string"
    || typeof claims.issued_at !== "number"
    || typeof claims.expires_at !== "number") {
    throw new Error("capability claims are invalid");
  }
  return claims as CapabilityClaims;
}

export class CapabilityIssuer {
  constructor(private readonly secret: Buffer, private readonly lifetimeSeconds = 30) {
    if (secret.byteLength < 32) throw new Error("capability secret must contain at least 32 bytes");
  }

  issue(decision: AllowedDecision, use: CapabilityUse, nowSeconds = Math.floor(Date.now() / 1000)): string {
    if (decision.decision !== "allow" || typeof decision.requestId !== "string" || decision.requestId.length === 0) {
      throw new Error("capability issuance requires a correlated ACS ALLOW decision");
    }
    const claims: CapabilityClaims = {
      version: 1,
      capability_id: randomUUID(),
      acs_request_id: decision.requestId,
      subject: use.subject,
      action: use.action,
      resource: use.resource,
      issued_at: nowSeconds,
      expires_at: nowSeconds + this.lifetimeSeconds,
    };
    const payload = encode(JSON.stringify(claims));
    return `${payload}.${encode(signature(payload, this.secret))}`;
  }
}

export class ProtectedResource {
  private readonly consumed = new Set<string>();

  constructor(private readonly secret: Buffer) {
    if (secret.byteLength < 32) throw new Error("capability secret must contain at least 32 bytes");
  }

  authorize(token: string, expected: CapabilityUse, nowSeconds = Math.floor(Date.now() / 1000)): CapabilityClaims {
    const [payload, encodedSignature, extra] = token.split(".");
    if (!payload || !encodedSignature || extra !== undefined) throw new Error("capability token is malformed");
    const actual = Buffer.from(encodedSignature, "base64url");
    const wanted = signature(payload, this.secret);
    if (actual.length !== wanted.length || !timingSafeEqual(actual, wanted)) throw new Error("capability signature is invalid");
    const claims = parseClaims(payload);
    if (claims.expires_at < nowSeconds || claims.issued_at > nowSeconds + 5) throw new Error("capability is expired or not yet valid");
    if (claims.subject !== expected.subject || claims.action !== expected.action || claims.resource !== expected.resource) {
      throw new Error("capability is not bound to this action");
    }
    if (this.consumed.has(claims.capability_id)) throw new Error("capability has already been used");
    this.consumed.add(claims.capability_id);
    return claims;
  }
}
