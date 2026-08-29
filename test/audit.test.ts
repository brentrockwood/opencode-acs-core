import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditSink } from "../src/audit.js";

const directories = new Set<string>();

afterEach(async () => {
  await Promise.all([...directories].map((directory) => rm(directory, { recursive: true, force: true })));
  directories.clear();
});

describe("audit output", () => {
  it("omits payloads by default", async () => {
    const directory = await mkdtemp(join(tmpdir(), "opencode-acs-audit-"));
    directories.add(directory);
    const path = join(directory, "events.jsonl");
    const sink = new AuditSink({ path, includePayloads: false });
    await sink.write({ event: "acs_request", payload: { secret: "must-not-appear" } });
    const text = await readFile(path, "utf8");
    expect(text).not.toContain("must-not-appear");
    const record = JSON.parse(text);
    expect(record.payload).toBe("[omitted]");
    expect(record).toMatchObject({
      adapter_version: "0.1.0-alpha.1",
      opencode_version: "1.18.20",
      acs_version: "0.1.0",
    });
  });
});
