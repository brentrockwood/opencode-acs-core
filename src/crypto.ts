import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { canonicalize } from "json-canonicalize";
import type { AcsRequestEnvelope, AcsResponseEnvelope, AcsSignature } from "./types.js";

type SignableEnvelope = AcsRequestEnvelope | AcsResponseEnvelope;

export function deriveSessionKey(inputKeyMaterial: string, sessionId: string): Buffer {
  // ACS v0.1 requires HKDF with the session_id but does not fix salt/info byte
  // strings. This adapter publishes its deterministic choice for its demo
  // Guardian and treats it as an implementation detail, not an ACS mandate.
  return Buffer.from(
    hkdfSync(
      "sha256",
      Buffer.from(inputKeyMaterial, "utf8"),
      Buffer.from(sessionId, "utf8"),
      Buffer.from("opencode-acs-core/v0.1.0/HMAC-SHA256", "utf8"),
      32,
    ),
  );
}

export function canonicalEnvelope(envelope: SignableEnvelope): string {
  const value = structuredClone(envelope) as SignableEnvelope;
  if ("params" in value) delete value.params.signature;
  if ("result" in value && value.result) delete value.result.signature;
  return canonicalize(value);
}

export function signEnvelope(envelope: SignableEnvelope, key: Buffer, keyId: string): AcsSignature {
  const value = createHmac("sha256", key).update(canonicalEnvelope(envelope), "utf8").digest("base64");
  return { algorithm: "HMAC-SHA256", value, key_id: keyId };
}

export function verifyEnvelope(envelope: SignableEnvelope, key: Buffer, signature: AcsSignature): boolean {
  if (signature.algorithm !== "HMAC-SHA256") return false;
  const expected = signEnvelope(envelope, key, signature.key_id).value;
  const actualBytes = Buffer.from(signature.value, "base64");
  const expectedBytes = Buffer.from(expected, "base64");
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
}
