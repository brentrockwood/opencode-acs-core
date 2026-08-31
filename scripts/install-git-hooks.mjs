import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

if (existsSync(join(process.cwd(), ".git"))) {
  execFileSync("git", ["config", "core.hooksPath", ".githooks"], {
    stdio: "inherit",
  });
}
