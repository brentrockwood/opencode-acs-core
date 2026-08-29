import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export interface AcsConfig {
  mode: "observe" | "enforce";
  startupPosture: "proceed" | "refuse";
  enableModify: boolean;
  guardian: {
    url: string;
    connectTimeoutMs: number;
    maxResponseBytes: number;
    hmacKeyEnv?: string;
    keyId?: string;
  };
  audit: {
    path?: string;
    includePayloads: boolean;
  };
  protectedResource?: {
    url: string;
    timeoutMs: number;
    maxResponseBytes: number;
  };
  agent: {
    id: string;
    name?: string;
    environment: "development" | "staging" | "production";
  };
}

function assertObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertKeys(value: Record<string, unknown>, allowed: string[], label: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new Error(`${label} has unknown key(s): ${unknown.join(", ")}`);
}

function positiveInteger(value: unknown, fallback: number, label: string): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || (value as number) < 1) throw new Error(`${label} must be a positive integer`);
  return value as number;
}

export function parseConfig(value: unknown, directory: string): AcsConfig {
  assertObject(value, "configuration");
  assertKeys(value, ["mode", "startupPosture", "enableModify", "guardian", "audit", "agent", "protectedResource"], "configuration");
  const mode = value.mode ?? "observe";
  if (mode !== "observe" && mode !== "enforce") throw new Error("mode must be observe or enforce");
  const startupPosture = value.startupPosture ?? "proceed";
  if (startupPosture !== "proceed" && startupPosture !== "refuse") {
    throw new Error("startupPosture must be proceed or refuse");
  }
  if (mode === "enforce" && value.startupPosture === undefined) {
    throw new Error("startupPosture must be explicit in enforce mode");
  }
  if (value.enableModify !== undefined && typeof value.enableModify !== "boolean") {
    throw new Error("enableModify must be a boolean");
  }

  assertObject(value.guardian, "guardian");
  assertKeys(value.guardian, ["url", "connectTimeoutMs", "maxResponseBytes", "hmacKeyEnv", "keyId"], "guardian");
  if (typeof value.guardian.url !== "string") throw new Error("guardian.url is required");
  const url = new URL(value.guardian.url);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("guardian.url must use http or https");
  if (url.username || url.password) throw new Error("guardian.url must not contain credentials");
  const hmacKeyEnv = value.guardian.hmacKeyEnv;
  const keyId = value.guardian.keyId;
  if (hmacKeyEnv !== undefined && (typeof hmacKeyEnv !== "string" || hmacKeyEnv.length === 0)) {
    throw new Error("guardian.hmacKeyEnv must be a non-empty environment variable name");
  }
  if (keyId !== undefined && (typeof keyId !== "string" || keyId.length === 0)) {
    throw new Error("guardian.keyId must be a non-empty string");
  }
  if ((hmacKeyEnv === undefined) !== (keyId === undefined)) {
    throw new Error("guardian.hmacKeyEnv and guardian.keyId must be configured together");
  }
  if (mode === "enforce" && hmacKeyEnv === undefined) {
    throw new Error("guardian.hmacKeyEnv and guardian.keyId are required in enforce mode");
  }
  const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
  if (mode === "enforce" && url.protocol === "http:" && !loopbackHosts.has(url.hostname)) {
    throw new Error("enforce mode requires https for non-loopback Guardian URLs");
  }

  const rawAudit = value.audit ?? {};
  assertObject(rawAudit, "audit");
  assertKeys(rawAudit, ["path", "includePayloads"], "audit");
  if (rawAudit.path !== undefined && typeof rawAudit.path !== "string") throw new Error("audit.path must be a string");
  if (rawAudit.includePayloads !== undefined && typeof rawAudit.includePayloads !== "boolean") {
    throw new Error("audit.includePayloads must be a boolean");
  }

  const rawAgent = value.agent ?? {};
  assertObject(rawAgent, "agent");
  assertKeys(rawAgent, ["id", "name", "environment"], "agent");
  const agentId = rawAgent.id ?? "opencode";
  if (typeof agentId !== "string" || agentId.length === 0) throw new Error("agent.id must be non-empty");
  if (rawAgent.name !== undefined && typeof rawAgent.name !== "string") throw new Error("agent.name must be a string");
  const environment = rawAgent.environment ?? "development";
  if (!(environment === "development" || environment === "staging" || environment === "production")) {
    throw new Error("agent.environment is invalid");
  }
  const auditPath = rawAudit.path === undefined
    ? undefined
    : isAbsolute(rawAudit.path) ? rawAudit.path : resolve(directory, rawAudit.path);

  let protectedResource: AcsConfig["protectedResource"];
  if (value.protectedResource !== undefined) {
    if (mode !== "enforce") throw new Error("protectedResource requires enforce mode");
    assertObject(value.protectedResource, "protectedResource");
    assertKeys(value.protectedResource, ["url", "timeoutMs", "maxResponseBytes"], "protectedResource");
    if (typeof value.protectedResource.url !== "string") throw new Error("protectedResource.url is required");
    const protectedUrl = new URL(value.protectedResource.url);
    if (protectedUrl.username || protectedUrl.password) throw new Error("protectedResource.url must not contain credentials");
    const protectedLoopback = new Set(["localhost", "127.0.0.1", "[::1]"]);
    if (protectedUrl.protocol !== "https:" && !(protectedUrl.protocol === "http:" && protectedLoopback.has(protectedUrl.hostname))) {
      throw new Error("protectedResource.url must use https or loopback http");
    }
    protectedResource = {
      url: protectedUrl.toString(),
      timeoutMs: positiveInteger(value.protectedResource.timeoutMs, 2_000, "protectedResource.timeoutMs"),
      maxResponseBytes: positiveInteger(value.protectedResource.maxResponseBytes, 65_536, "protectedResource.maxResponseBytes"),
    };
  }

  return {
    mode,
    startupPosture,
    enableModify: value.enableModify === true,
    guardian: {
      url: url.toString(),
      connectTimeoutMs: positiveInteger(value.guardian.connectTimeoutMs, 2_000, "guardian.connectTimeoutMs"),
      maxResponseBytes: positiveInteger(value.guardian.maxResponseBytes, 1_048_576, "guardian.maxResponseBytes"),
      ...(hmacKeyEnv === undefined ? {} : { hmacKeyEnv, keyId: keyId as string }),
    },
    audit: {
      ...(auditPath === undefined ? {} : { path: auditPath }),
      includePayloads: rawAudit.includePayloads === true,
    },
    ...(protectedResource ? { protectedResource } : {}),
    agent: {
      id: agentId,
      ...(rawAgent.name === undefined ? {} : { name: rawAgent.name as string }),
      environment,
    },
  };
}

export function findConfigPath(directory: string): string {
  const explicit = process.env.OPENCODE_ACS_CONFIG;
  return explicit
    ? isAbsolute(explicit) ? explicit : resolve(directory, explicit)
    : resolve(directory, ".opencode", "acs-core.json");
}

export function loadConfig(directory: string): AcsConfig | undefined {
  const path = findConfigPath(directory);
  try {
    return parseConfig(JSON.parse(readFileSync(path, "utf8")) as unknown, directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !process.env.OPENCODE_ACS_CONFIG) return undefined;
    throw error;
  }
}
