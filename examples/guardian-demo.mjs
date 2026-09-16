import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { canonicalize } from "json-canonicalize";

const port = Number(process.env.OPENCODE_ACS_DEMO_PORT ?? "8787");
const inputKeyMaterial = process.env.OPENCODE_ACS_HMAC_KEY;
const keyId = process.env.OPENCODE_ACS_KEY_ID ?? "demo-key-id";

if (!inputKeyMaterial) throw new Error("OPENCODE_ACS_HMAC_KEY is required");
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("OPENCODE_ACS_DEMO_PORT is invalid");

function sessionKey(sessionId) {
  return Buffer.from(hkdfSync(
    "sha256",
    Buffer.from(inputKeyMaterial, "utf8"),
    Buffer.from(sessionId, "utf8"),
    Buffer.from("opencode-acs-core/v0.1.0/HMAC-SHA256", "utf8"),
    32,
  ));
}

function canonicalEnvelope(envelope) {
  const value = structuredClone(envelope);
  if (value.params) delete value.params.signature;
  if (value.result) delete value.result.signature;
  return canonicalize(value);
}

function signature(envelope, key) {
  return createHmac("sha256", key).update(canonicalEnvelope(envelope), "utf8").digest();
}

function validRequest(request, key) {
  const supplied = request?.params?.signature;
  if (supplied?.algorithm !== "HMAC-SHA256" || supplied.key_id !== keyId || typeof supplied.value !== "string") return false;
  const actual = Buffer.from(supplied.value, "base64");
  const wanted = signature(request, key);
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}

function resultFor(request) {
  if (request.method === "steps/toolCallRequest" && String(request.params.payload.raw_command ?? "").includes("ACS_DEMO_DENY")) {
    return { decision: "deny", reasoning: "blocked by the demo Guardian marker" };
  }
  return { decision: "allow" };
}

const server = createServer(async (incoming, outgoing) => {
  try {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of incoming) {
      bytes += chunk.length;
      if (bytes > 1_048_576) throw new Error("request is too large");
      chunks.push(chunk);
    }
    const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const id = request?.params?.metadata?.session_id;
    if (typeof id !== "string") throw new Error("request has no session id");
    const key = sessionKey(id);
    if (request.method !== "system/ping" && !validRequest(request, key)) {
      outgoing.writeHead(401).end();
      return;
    }
    const response = request.method === "handshake/hello"
      ? {
          jsonrpc: "2.0",
          id: request.id,
          result: {
            negotiated_version: "0.1.0",
            methods_evaluated: request.params.payload.methods_implemented,
            selected_transport: "http",
            signature_algorithms_supported: ["HMAC-SHA256"],
            timeout_config: { default_ms: 2000 },
            on_decision_failure: "deny",
            policy_requires_provenance: false,
            profiles_accepted: [],
          },
        }
      : {
          jsonrpc: "2.0",
          id: request.id,
          result: {
            type: "final",
            acs_version: "0.1.0",
            request_id: request.params.request_id,
            ...resultFor(request),
          },
        };
    if (request.method !== "handshake/hello" && request.method !== "system/ping") {
      response.result.signature = {
        algorithm: "HMAC-SHA256",
        value: signature(response, key).toString("base64"),
        key_id: keyId,
      };
    }
    outgoing.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(response));
  } catch (error) {
    outgoing.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: String(error) }));
  }
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`Demo Guardian listening on http://127.0.0.1:${port}/\n`);
  process.stdout.write("Commands containing ACS_DEMO_DENY are denied. This is a fixture, not a policy service.\n");
});
