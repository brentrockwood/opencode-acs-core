import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsImport from "ajv-formats";
import type { AcsRequestEnvelope, AcsResponseEnvelope, JsonObject } from "./types.js";

const schemaRoot = fileURLToPath(new URL("../vendor/acs/v0.1.0/", import.meta.url));

function jsonFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? jsonFiles(path) : entry.name.endsWith(".json") ? [path] : [];
  });
}

const addFormats = addFormatsImport as unknown as (ajv: Ajv2020) => Ajv2020;
const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: true });
addFormats(ajv);
for (const path of jsonFiles(schemaRoot)) ajv.addSchema(JSON.parse(readFileSync(path, "utf8")) as object);

function schema(id: string): ValidateFunction {
  const found = ajv.getSchema(id);
  if (!found) throw new Error(`Vendored ACS schema is missing: ${id}`);
  return found;
}

const requestValidator = schema("https://acs.org/schema/v0.1.0/request-envelope.json");
const responseValidator = schema("https://acs.org/schema/v0.1.0/response-envelope.json");
const clientHelloValidator = schema("https://acs.org/schema/v0.1.0/handshake.json#/$defs/ClientHello");
const serverHelloValidator = schema("https://acs.org/schema/v0.1.0/handshake.json#/$defs/ServerHello");
const payloadSchemas: Record<string, string> = {
  "steps/sessionStart": "session-start.json",
  "steps/sessionEnd": "session-end.json",
  "steps/subagentStart": "subagent-start.json",
  "steps/subagentStop": "subagent-stop.json",
  "steps/toolCallRequest": "tool-call-request.json",
  "steps/toolCallResult": "tool-call-result.json",
  "system/ping": "system-ping.json",
};

function errors(value: ErrorObject[] | null | undefined): string {
  return (value ?? []).map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
}

function assertValid(validator: ValidateFunction, value: unknown, label: string): void {
  if (!validator(value)) throw new Error(`${label}: ${errors(validator.errors)}`);
}

export function validateRequest(envelope: AcsRequestEnvelope): void {
  assertValid(requestValidator, envelope, "invalid ACS request envelope");
  if (envelope.method === "handshake/hello") {
    assertValid(clientHelloValidator, envelope.params.payload, "invalid ACS ClientHello");
    return;
  }
  const filename = payloadSchemas[envelope.method];
  if (!filename) throw new Error(`unsupported ACS method: ${envelope.method}`);
  assertValid(schema(`https://acs.org/schema/v0.1.0/hooks/${filename}`), envelope.params.payload, `invalid ${envelope.method} payload`);
}

export function validateResponse(envelope: AcsResponseEnvelope): void {
  assertValid(responseValidator, envelope, "invalid ACS response envelope");
}

export function validateServerHello(payload: JsonObject): void {
  assertValid(serverHelloValidator, payload, "invalid ACS ServerHello");
}
