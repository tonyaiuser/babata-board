import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, signal) => resolve({ code, signal }));
  });
}

async function waitFor(file) {
  for (let i = 0; i < 150; i += 1) {
    try { await fs.access(file); return; } catch { await new Promise((resolve) => setTimeout(resolve, 20)); }
  }
  throw new Error(`Timed out waiting for ${file}`);
}

test("a duplicate daily run exits 75 without touching status or the stable kernel lock", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-run-lock-test-"));
  const monitorDir = path.join(root, "single-page-monitor");
  const dataDir = path.join(monitorDir, "data");
  const lockPath = path.join(dataDir, "run_daily.lock");
  const source = fileURLToPath(new URL("../run_daily.sh", import.meta.url));
  const helperSource = fileURLToPath(new URL("../scripts/locked_exec.py", import.meta.url));
  const script = path.join(monitorDir, "run_daily.sh");
  const helper = path.join(monitorDir, "scripts", "locked_exec.py");
  const ready = path.join(root, "ready");
  try {
    await fs.mkdir(path.dirname(helper), { recursive: true });
    await fs.mkdir(dataDir, { recursive: true });
    await fs.mkdir(path.join(monitorDir, "logs"), { recursive: true });
    await fs.copyFile(source, script);
    await fs.copyFile(helperSource, helper);
    await fs.chmod(script, 0o755);
    const holder = spawn("python3", [helper,
      "--lock", lockPath, "--lock-dir", dataDir, "--fd-env", "SP_SINGLE_PAGE_LOCK_FD",
      "--active-env", "SP_SINGLE_PAGE_LOCK_ACTIVE", "--busy-exit", "75", "--",
      "sleep", "30"], {
      env: { ...process.env, SP_SINGLE_PAGE_TEST_MODE: "1", SP_SINGLE_PAGE_TEST_LOCK_READY_FILE: ready },
      stdio: "ignore",
    });
    const holderExit = waitForExit(holder);
    try {
      await waitFor(ready);
      const statusPath = path.join(dataDir, "run_status.json");
      const sentinel = '{"run_id":"active-run","state":"running"}\n';
      await fs.writeFile(statusPath, sentinel);
      const duplicate = spawn("bash", [script], {
        cwd: root,
        env: {
          ...process.env,
          SP_SINGLE_PAGE_DEPLOY_ROOT: root,
          SP_SINGLE_PAGE_SEND_DINGTALK: "0",
        },
        stdio: "ignore",
      });
      const duplicateExit = waitForExit(duplicate);
      const result = await duplicateExit;
      assert.equal(result.code, 75);
      assert.equal(await fs.readFile(statusPath, "utf8"), sentinel);
      assert.equal((await fs.lstat(lockPath)).isSymbolicLink(), true);
    } finally {
      holder.kill("SIGKILL");
      await holderExit.catch(() => {});
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
