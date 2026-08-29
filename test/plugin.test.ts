import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AcsPlugin } from "../src/index.js";
import { createGuardian, TEST_KEY } from "./guardian-helper.js";

const temporaryDirectories = new Set<string>();

afterEach(async () => {
  delete process.env.OPENCODE_ACS_CONFIG;
  delete process.env.OPENCODE_ACS_PLUGIN_TEST_KEY;
  vi.unstubAllGlobals();
  await Promise.all([...temporaryDirectories].map((directory) => rm(directory, { recursive: true, force: true })));
  temporaryDirectories.clear();
});

describe("OpenCode plugin lifecycle", () => {
  it("sends a schema-valid sessionEnd and reinitializes a deleted host session", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-plugin-"));
    temporaryDirectories.add(directory);
    const configPath = join(directory, "acs.json");
    await writeFile(configPath, JSON.stringify({
      mode: "enforce",
      startupPosture: "refuse",
      guardian: {
        url: "http://127.0.0.1:8787/",
        hmacKeyEnv: "OPENCODE_ACS_PLUGIN_TEST_KEY",
        keyId: "test-key",
      },
    }));
    process.env.OPENCODE_ACS_CONFIG = configPath;
    process.env.OPENCODE_ACS_PLUGIN_TEST_KEY = TEST_KEY;
    const guardian = createGuardian();
    vi.stubGlobal("fetch", guardian.fetch);

    const hooks = await AcsPlugin({
      directory,
      client: { app: { log: vi.fn(async () => undefined) } },
    } as never);
    if (!hooks.event) throw new Error("plugin did not register an event hook");

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_host" } } },
    } as never);
    await hooks.event({
      event: { type: "session.deleted", properties: { info: { id: "ses_host" } } },
    } as never);
    const ended = guardian.requests.find((request) => request.method === "steps/sessionEnd");
    expect(ended?.params.payload).toEqual({ reason: "abandoned" });

    await hooks.event({
      event: { type: "session.created", properties: { info: { id: "ses_host" } } },
    } as never);
    expect(guardian.requests.filter((request) => request.method === "handshake/hello")).toHaveLength(2);
  });
});
