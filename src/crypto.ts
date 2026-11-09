import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { canonicalize } from "json-canonicalize";
import type { AcsRequestEnvelope, AcsResponseEnvelope, AcsSignature } from "./types.js";

type SignableEnvelope = AcsRequestEnvelope | AcsResponseEnvelope;

export function deriveSessionKey(inputKeyMaterial: string, sessionId: string): Buffer {
  const secret = Buffer.from(inputKeyMaterial, "utf8");
  if (secret.length < 32) throw new Error("HMAC secret must contain at least 32 UTF-8 bytes");
  // ACS §10: empty salt, exact transmitted session_id as UTF-8 info.
  return Buffer.from(
    hkdfSync(
      "sha256",
      secret,
      Buffer.alloc(0),
      Buffer.from(sessionId, "utf8"),
      32,
    ),
  );
}

export function canonicalEnvelope(envelope: SignableEnvelope): string {
  const value = structuredClone(envelope) as SignableEnvelope;
  if ("params" in value) delete value.params.signature;
  if ("result" in value && value.result) delete value.result.signature;
  if ("error" in value && value.error) delete value.error.signature;
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
