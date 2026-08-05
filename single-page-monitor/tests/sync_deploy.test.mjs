import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const monitorDir = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const deployScript = path.join(monitorDir, "sync_deploy.sh");
const stableRunnerSource = path.join(monitorDir, "stable_run_daily.sh");
const stableHealthSource = path.join(monitorDir, "stable_check_health.mjs");
const lockHelperSource = path.join(monitorDir, "scripts", "locked_exec.py");
const rollbackCleanupSource = path.join(monitorDir, "scripts", "rollback_cleanup.py");
const deploymentTest = process.env.SP_SINGLE_PAGE_STAGE_SELFTEST === "1" ? test.skip : test;
// This fixture is authorized only when SP_SINGLE_PAGE_TEST_MODE is set.  The
// deployment code accepts it by its complete SHA, never by this text marker.
const testLegacyHealthChecker = 'import fs from "node:fs";\nfs.writeFileSync(process.env.HEALTH_MARK, "legacy-health\\n");\n';
const testLegacyHealthCheckerSha = crypto.createHash("sha256").update(testLegacyHealthChecker).digest("hex");

function run(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk) => { stdout += chunk; });
  child.stderr?.on("data", (chunk) => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

function start(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk) => { stdout += chunk; });
  child.stderr?.on("data", (chunk) => { stderr += chunk; });
  const exited = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, exited };
}

async function waitForWhileRunning(file, running) {
  await Promise.race([
    waitFor(file),
    running.then((result) => { throw new Error(`process exited before ${file}: ${JSON.stringify(result)}`); }),
  ]);
}

async function waitFor(file) {
  for (let i = 0; i < 300; i += 1) {
    try { await fs.access(file); return; } catch { await new Promise((resolve) => setTimeout(resolve, 20)); }
  }
  throw new Error(`Timed out waiting for ${file}`);
}

async function removeFixture(root) {
  await run("chmod", ["-R", "u+w", root]).catch(() => {});
  await fs.rm(root, { recursive: true, force: true });
}

async function digestTree(root, { ignoreLockProtocol = false } = {}) {
  const rows = [];
  async function visit(directory, prefix = "") {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (ignoreLockProtocol && prefix === "" &&
          (entry.name === "run_daily.lock" || entry.name === ".run_daily.lock.protocol-v3")) continue;
      const full = path.join(directory, entry.name);
      const relative = path.join(prefix, entry.name);
      const status = await fs.lstat(full);
      if (entry.isDirectory()) {
        rows.push(`d:${relative}:${status.mode & 0o777}:${status.mtimeMs}`);
        await visit(full, relative);
      } else if (entry.isSymbolicLink()) {
        rows.push(`l:${relative}:${await fs.readlink(full)}`);
      } else {
        const bytes = await fs.readFile(full);
        rows.push(`f:${relative}:${status.mode & 0o777}:${status.mtimeMs}:${crypto.createHash("sha256").update(bytes).digest("hex")}`);
      }
    }
  }
  await visit(root);
  return crypto.createHash("sha256").update(rows.join("\n")).digest("hex");
}

async function snapshotRollbackEvidence(deployRoot) {
  const names = (await fs.readdir(deployRoot)).filter((name) => name.startsWith(".rollback-")).sort();
  const values = new Map();
  for (const name of names) {
    const target = path.join(deployRoot, name);
    const status = await fs.lstat(target);
    values.set(name, status.isDirectory()
      ? { kind: "directory", value: await digestTree(target) }
      : status.isSymbolicLink()
        ? { kind: "symlink", value: await fs.readlink(target) }
        : { kind: "file", value: await fs.readFile(target) });
  }
  return { names, values };
}

async function assertRollbackEvidenceUnchanged(deployRoot, snapshot) {
  const current = await snapshotRollbackEvidence(deployRoot);
  assert.deepEqual(current.names, snapshot.names);
  for (const name of snapshot.names) {
    assert.equal(current.values.get(name).kind, snapshot.values.get(name).kind);
    assert.deepEqual(current.values.get(name).value, snapshot.values.get(name).value);
  }
}

async function snapshotRuntimeProtocol(runtime) {
  const names = [
    "run_daily.sh", "check_health.mjs", "locked_exec.py",
    ".stable-health-migration.json", ".precommit_check_health.mjs", ".deployment-phase",
  ];
  const snapshot = new Map();
  for (const name of names) {
    const target = path.join(runtime, name);
    try {
      const status = await fs.lstat(target);
      snapshot.set(name, { mode: status.mode & 0o7777, bytes: await fs.readFile(target) });
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      snapshot.set(name, null);
    }
  }
  return snapshot;
}

async function atomicCurrent(deployRoot, relative) {
  const temporary = path.join(deployRoot, `.current-test-${process.pid}-${Date.now()}`);
  await fs.symlink(relative, temporary);
  await fs.rename(temporary, path.join(deployRoot, "current"));
}

async function writeMigrationMarker(runtime, { schema = 2, wrapperVersion, wrapperSha } = {}) {
  const health = await fs.readFile(path.join(runtime, "check_health.mjs"));
  const version = wrapperVersion ?? Number(/const STABLE_WRAPPER_VERSION = (\d+);/.exec(health)?.[1]);
  const sha = wrapperSha ?? crypto.createHash("sha256").update(health).digest("hex");
  assert.ok(Number.isInteger(version) && version > 0, "fixture health wrapper has a stable version");
  await fs.writeFile(path.join(runtime, ".stable-health-migration.json"), `${JSON.stringify({
    schema,
    kind: "spspy-single-page-stable-health-migration",
    wrapper_id: "spspy-single-page-stable-health",
    wrapper_version: version,
    wrapper_sha256: sha,
  })}\n`);
}

async function seedDetachedRollback(fixture, {
  includeHelper = false,
  includeMarker = false,
  includePrecommit = false,
} = {}) {
  const release = `20260802T010101Z-${process.pid}`;
  const rollback = path.join(fixture.deployRoot, `.rollback-${release}`);
  await fs.mkdir(rollback);
  const names = includeHelper
    ? ["run_daily.sh", "check_health.mjs", "locked_exec.py"]
    : ["run_daily.sh", "check_health.mjs"];
  for (const name of names) {
    await fs.copyFile(path.join(fixture.runtime, name), path.join(rollback, name));
    await fs.writeFile(path.join(rollback, `${name}.present`), "");
  }
  if (includeMarker) {
    await fs.copyFile(
      path.join(fixture.runtime, ".stable-health-migration.json"),
      path.join(rollback, ".stable-health-migration.json"),
    );
    await fs.writeFile(path.join(rollback, ".stable-health-migration.json.present"), "");
  }
  if (includePrecommit) {
    await fs.copyFile(
      path.join(fixture.runtime, ".precommit_check_health.mjs"),
      path.join(rollback, ".precommit_check_health.mjs"),
    );
    await fs.writeFile(path.join(rollback, ".precommit_check_health.mjs.present"), "");
  }
  let expectedCurrent = "__ABSENT__";
  try {
    expectedCurrent = await fs.readlink(path.join(fixture.deployRoot, "current"));
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const sealed = await run("python3", [rollbackCleanupSource,
    "seal", fixture.deployRoot, fixture.runtime, rollback, expectedCurrent, testLegacyHealthCheckerSha,
  ], { env: fixture.env });
  assert.equal(sealed.code, 0, sealed.stderr);
  return rollback;
}

async function setupFixture({ withCurrent = true, withLegacyHelper = true } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sp-atomic-deploy-test-"));
  const bin = path.join(root, "bin");
  const deployRoot = path.join(root, "deploy");
  const runtime = path.join(deployRoot, "single-page-monitor");
  const oldMonitor = path.join(deployRoot, "releases", "old", "single-page-monitor");
  await fs.mkdir(oldMonitor, { recursive: true });
  await fs.mkdir(path.join(runtime, "data"), { recursive: true });
  await fs.mkdir(path.join(runtime, "logs"), { recursive: true });
  await fs.mkdir(path.join(runtime, "reports"), { recursive: true });
  await fs.mkdir(bin, { recursive: true });
  await fs.writeFile(path.join(runtime, "data", "state.json"), "persistent-state\n");
  await fs.writeFile(path.join(runtime, "data", "events.jsonl"), "persistent-events\n");
  await fs.writeFile(
    path.join(oldMonitor, "run_daily.sh"),
    "#!/usr/bin/env bash\nprintf 'old-release\\n' > \"${ENTRY_MARK:?}\"\n",
    { mode: 0o755 },
  );
  await fs.writeFile(path.join(oldMonitor, "check_health.mjs"), "process.exit(0);\n");
  if (withCurrent) await fs.symlink("releases/old", path.join(deployRoot, "current"));
  await fs.copyFile(stableRunnerSource, path.join(runtime, "run_daily.sh"));
  if (withCurrent) {
    await fs.copyFile(stableHealthSource, path.join(runtime, "check_health.mjs"));
  } else {
    await fs.writeFile(path.join(runtime, "check_health.mjs"), testLegacyHealthChecker);
  }
  if (withLegacyHelper) await fs.copyFile(lockHelperSource, path.join(runtime, "locked_exec.py"));
  await fs.chmod(path.join(runtime, "run_daily.sh"), 0o755);
  await fs.chmod(path.join(runtime, "check_health.mjs"), 0o755);
  if (withLegacyHelper) await fs.chmod(path.join(runtime, "locked_exec.py"), 0o755);
  // A pre-existing current is already a migrated runtime.  Keeping this
  // fixture marker honest lets tests distinguish a real interrupted marker
  // commit from an unmarked legacy deployment.
  if (withCurrent) await writeMigrationMarker(runtime);

  const fakeNpm = `#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  ci)
    if [[ "\${FAKE_NPM_FAIL_CI:-0}" == "1" ]]; then exit 31; fi
    if [[ -n "\${FAKE_NPM_CI_MARKER:-}" ]]; then printf '%s\\n' "$PWD" > "\${FAKE_NPM_CI_MARKER}"; fi
    if [[ -n "\${FAKE_NPM_READY_FILE:-}" ]]; then
      : > "\${FAKE_NPM_READY_FILE}"
      while [[ ! -e "\${FAKE_NPM_RELEASE_FILE}" ]]; do sleep 0.02; done
    fi
    ;;
  test)
    if [[ "\${FAKE_NPM_ASSERT_NO_RUNTIME_LOCK_ENV:-0}" == "1" ]]; then
      if [[ -n "\${SP_SINGLE_PAGE_DEPLOY_LOCK_ACTIVE:-}" || -n "\${SP_SINGLE_PAGE_DEPLOY_LOCK_FD:-}" || \
            -n "\${SP_SINGLE_PAGE_LOCK_ACTIVE:-}" || -n "\${SP_SINGLE_PAGE_LOCK_FD:-}" ]]; then
        echo "npm test inherited a runtime lock capability" >&2
        exit 41
      fi
      if [[ -n "\${FAKE_NPM_TEST_ENV_MARKER:-}" ]]; then printf '%s\\n' "$PWD" >> "\${FAKE_NPM_TEST_ENV_MARKER}"; fi
      if [[ -n "\${FAKE_NPM_TEST_READY_FILE:-}" ]]; then
        : > "\${FAKE_NPM_TEST_READY_FILE}"
        while [[ ! -e "\${FAKE_NPM_TEST_CONTINUE_FILE:-}" ]]; do sleep 0.02; done
      fi
      exit 0
    fi
    if [[ -n "\${FAKE_NPM_TEST_MARKER:-}" ]]; then printf '%s\\n' "$PWD" > "\${FAKE_NPM_TEST_MARKER}"; fi
    exec "\${REAL_NODE:?}" --test tests/*.test.mjs
    ;;
  *) exit 64 ;;
esac
`;
  await fs.writeFile(path.join(bin, "npm"), fakeNpm, { mode: 0o755 });
  const env = {
    ...process.env,
    SP_SINGLE_PAGE_DEPLOY_ROOT: deployRoot,
    SP_SINGLE_PAGE_TEST_MODE: "1",
    SP_SINGLE_PAGE_TEST_SKIP_SOURCE_PRECHECK: "1",
    NPM_BIN: path.join(bin, "npm"),
    REAL_NODE: process.execPath,
    SP_SINGLE_PAGE_TEST_TRUSTED_LEGACY_SHA: testLegacyHealthCheckerSha,
  };
  return { root, bin, deployRoot, runtime, env };
}

async function crashSchema2UpgradeBeforeMarker(fixture, prefix) {
  const staged = path.join(fixture.root, `${prefix}-stage-ready`);
  const allowStage = path.join(fixture.root, `${prefix}-stage-go`);
  const committed = path.join(fixture.root, `${prefix}-current-ready`);
  const never = path.join(fixture.root, `${prefix}-current-never`);
  const deploying = start("bash", [deployScript], {
    env: {
      ...fixture.env,
      FAKE_NPM_READY_FILE: staged,
      FAKE_NPM_RELEASE_FILE: allowStage,
      SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_current_fsync_before_marker",
      SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: committed,
      SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
    },
  });
  await waitForWhileRunning(staged, deploying.exited);
  const oldHealth = (await fs.readFile(path.join(fixture.runtime, "check_health.mjs"), "utf8"))
    .replace("const STABLE_WRAPPER_VERSION = 2;", "const STABLE_WRAPPER_VERSION = 1;");
  await fs.writeFile(path.join(fixture.runtime, "check_health.mjs"), oldHealth);
  await writeMigrationMarker(fixture.runtime, {
    schema: 2,
    wrapperVersion: 1,
    wrapperSha: crypto.createHash("sha256").update(oldHealth).digest("hex"),
  });
  const expectedRuntime = await snapshotRuntimeProtocol(fixture.runtime);
  await fs.writeFile(allowStage, "go\n");
  await waitForWhileRunning(committed, deploying.exited);
  deploying.child.kill("SIGKILL");
  assert.equal((await deploying.exited).signal, "SIGKILL");
  return {
    current: await fs.readlink(path.join(fixture.deployRoot, "current")),
    marker: await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json")),
    expectedRuntime,
  };
}

async function crashDetachedCleanupScratch(fixture, prefix) {
  const ready = path.join(fixture.root, `${prefix}-scratch-ready`);
  const never = path.join(fixture.root, `${prefix}-scratch-never`);
  const deploying = start("bash", [deployScript], {
    detached: true,
    env: {
      ...fixture.env,
      SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
      SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_record_temp_partial_write",
      SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
      SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
    },
  });
  await waitForWhileRunning(ready, deploying.exited);
  process.kill(-deploying.child.pid, "SIGKILL");
  assert.equal((await deploying.exited).signal, "SIGKILL");
  const evidence = await snapshotRollbackEvidence(fixture.deployRoot);
  const scratch = evidence.names.find((name) =>
    /^\.rollback-cleanup-detached-.*\.json\.tmp-bound-[a-f0-9]{64}-[a-f0-9]{32}$/.test(name));
  assert.ok(scratch, "a current-bound detached cleanup scratch exists");
  return scratch;
}

async function crashStablePrecurrentTransaction(fixture, prefix) {
  const ready = path.join(fixture.root, `${prefix}-precurrent-ready`);
  const never = path.join(fixture.root, `${prefix}-precurrent-never`);
  const deploying = start("bash", [deployScript], {
    detached: true,
    env: {
      ...fixture.env,
      SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_health_wrapper",
      SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
      SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
    },
  });
  await waitForWhileRunning(ready, deploying.exited);
  process.kill(-deploying.child.pid, "SIGKILL");
  assert.equal((await deploying.exited).signal, "SIGKILL");
}

deploymentTest("staging keeps the stable entrypoint live, runs exact staged npm test, and preserves data", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "stage-ready");
  const release = path.join(fixture.root, "stage-release");
  const entry = path.join(fixture.root, "entry-result");
  const ciMarker = path.join(fixture.root, "ci-marker");
  const testMarker = path.join(fixture.root, "test-marker");
  try {
    const dataBefore = await digestTree(path.join(fixture.runtime, "data"), { ignoreLockProtocol: true });
    const deploying = run("bash", [deployScript], {
      env: {
        ...fixture.env,
        FAKE_NPM_READY_FILE: ready,
        FAKE_NPM_RELEASE_FILE: release,
        FAKE_NPM_CI_MARKER: ciMarker,
        FAKE_NPM_TEST_MARKER: testMarker,
      },
    });
    await waitForWhileRunning(ready, deploying);
    const before = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const entryResult = await run(path.join(fixture.runtime, "run_daily.sh"), [], {
      env: { ...fixture.env, ENTRY_MARK: entry },
    });
    assert.equal(entryResult.code, 75, "the shared deployment lock blocks daily without removing its entrypoint");
    const directSourceDaily = await run(path.join(monitorDir, "run_daily.sh"), [], {
      env: { ...fixture.env, SP_SINGLE_PAGE_SEND_DINGTALK: "0" },
    });
    assert.equal(directSourceDaily.code, 75, "source daily derives and contends on the same persistent data directory");
    await fs.access(path.join(fixture.runtime, "run_daily.sh"));
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), before);
    await fs.writeFile(release, "go\n");
    assert.equal((await deploying).code, 0);
    assert.notEqual(await fs.readlink(path.join(fixture.deployRoot, "current")), before);
    assert.match(await fs.readFile(ciMarker, "utf8"), /\.stage\/single-page-monitor\n$/);
    assert.match(await fs.readFile(testMarker, "utf8"), /\.stage\/single-page-monitor\n$/);
    assert.equal(await digestTree(path.join(fixture.runtime, "data"), { ignoreLockProtocol: true }), dataBefore);
    await assert.rejects(fs.access(path.join(fixture.deployRoot, "current", "single-page-monitor", "data")));
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a failed stage leaves current, stable entrypoints, and data byte-identical", async () => {
  const fixture = await setupFixture();
  try {
    const beforeCurrent = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const dataBefore = await digestTree(path.join(fixture.runtime, "data"), { ignoreLockProtocol: true });
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const result = await run("bash", [deployScript], { env: { ...fixture.env, FAKE_NPM_FAIL_CI: "1" } });
    assert.notEqual(result.code, 0);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), beforeCurrent);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
    assert.equal(await digestTree(path.join(fixture.runtime, "data"), { ignoreLockProtocol: true }), dataBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("two deployers serialize on the same kernel lock and the contender exits 75", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "lock-ready");
  const proceed = path.join(fixture.root, "lock-proceed");
  try {
    const first = run("bash", [deployScript], {
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_LOCK_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_LOCK_CONTINUE_FILE: proceed,
        SP_SINGLE_PAGE_TEST_EXIT_AFTER_LOCK: "1",
      },
    });
    await waitForWhileRunning(ready, first);
    const second = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(second.code, 75);
    await fs.writeFile(proceed, "go\n");
    assert.equal((await first).code, 96);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("deploy-root lock serializes callers that use different external data directories", async () => {
  const fixture = await setupFixture();
  const dataA = path.join(fixture.root, "external-data-a");
  const dataB = path.join(fixture.root, "external-data-b");
  const ready = path.join(fixture.root, "root-lock-data-a-ready");
  const never = path.join(fixture.root, "root-lock-data-a-never");
  const envForData = (data) => ({
    ...fixture.env,
    SP_SINGLE_PAGE_DATA_DIR: data,
    SP_SINGLE_PAGE_LOCK_DIR: path.join(data, "run_daily.lock"),
  });
  try {
    const first = start("bash", [deployScript], {
      detached: true,
      env: {
        ...envForData(dataA),
        FAKE_NPM_READY_FILE: ready,
        FAKE_NPM_RELEASE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, first.exited);
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);

    const contender = await run("bash", [deployScript], { env: envForData(dataB) });
    assert.equal(contender.code, 75, contender.stderr);
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);

    process.kill(-first.child.pid, "SIGKILL");
    assert.equal((await first.exited).signal, "SIGKILL");
    const afterCrash = await run("bash", [deployScript], { env: envForData(dataB) });
    assert.equal(afterCrash.code, 0, afterCrash.stderr);
    assert.notEqual(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("an inherited deployment lock stays live while source and staged npm tests are isolated", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "inherited-lock-npm-ready");
  const proceed = path.join(fixture.root, "inherited-lock-npm-proceed");
  const marker = path.join(fixture.root, "inherited-lock-npm-marker");
  const lock = path.join(fixture.runtime, "data", "run_daily.lock");
  try {
    // locked_exec owns the real data-directory fd and exports its capability
    // into sync_deploy.  sync_deploy must validate that exact inherited fd,
    // while its fixture-spawning npm tests must see neither variable.
    const deploying = start("python3", [lockHelperSource,
      "--lock", lock,
      "--lock-dir", path.join(fixture.runtime, "data"),
      "--fd-env", "SP_SINGLE_PAGE_LOCK_FD",
      "--active-env", "SP_SINGLE_PAGE_LOCK_ACTIVE",
      "--busy-exit", "75",
      "--", "bash", deployScript,
    ], {
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_SKIP_SOURCE_PRECHECK: "0",
        FAKE_NPM_ASSERT_NO_RUNTIME_LOCK_ENV: "1",
        FAKE_NPM_TEST_READY_FILE: ready,
        FAKE_NPM_TEST_CONTINUE_FILE: proceed,
        FAKE_NPM_TEST_ENV_MARKER: marker,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);

    // The npm child is paused after source precheck, so this proves the outer
    // deploy did not release or replace the inherited data-directory lock.
    const contender = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(contender.code, 75, contender.stderr);

    await fs.writeFile(proceed, "go\n");
    const result = await deploying.exited;
    assert.equal(result.code, 0, result.stderr);
    const testedDirs = (await fs.readFile(marker, "utf8")).trim().split("\n");
    assert.equal(testedDirs.length, 2, "source and exact staged npm tests both ran without the inherited lock capability");
    assert.equal(testedDirs[0], monitorDir);
    assert.match(testedDirs[1], /\.stage\/single-page-monitor$/);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("first migration refuses an active legacy daily lock without changing live entrypoints", async () => {
  const fixture = await setupFixture();
  const active = spawn("sleep", ["30"]);
  const activeExit = new Promise((resolve) => active.once("exit", resolve));
  try {
    const lock = path.join(fixture.runtime, "data", "run_daily.lock");
    await fs.mkdir(lock);
    await fs.writeFile(path.join(lock, "pid"), `${active.pid}\n`);
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 75);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
    assert.equal((await fs.readFile(path.join(lock, "pid"), "utf8")).trim(), String(active.pid));
  } finally {
    active.kill("SIGTERM");
    await activeExit;
    await removeFixture(fixture.root);
  }
});

deploymentTest("first migration preserves a dead legacy lock remnant and fails closed", async () => {
  const fixture = await setupFixture();
  try {
    const lock = path.join(fixture.runtime, "data", "run_daily.lock");
    await fs.mkdir(lock);
    await fs.writeFile(path.join(lock, "pid"), "99999999\n");
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 75);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.equal((await fs.lstat(lock)).isDirectory(), true);
    assert.equal(await fs.readFile(path.join(lock, "pid"), "utf8"), "99999999\n");
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a real two-file first legacy migration commits and removes its rollback residue", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  try {
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 0, result.stderr);
    assert.match(await fs.readlink(path.join(fixture.deployRoot, "current")), /^releases\//);
    await fs.access(path.join(fixture.runtime, "locked_exec.py"));
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a committed two-file first-legacy rollback residue resumes without deleting unproven state", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  const ready = path.join(fixture.root, "legacy-two-file-cleanup-ready");
  const never = path.join(fixture.root, "legacy-two-file-cleanup-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "before_rollback_delete",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
    await fs.access(path.join(fixture.deployRoot, `.rollback-${selected}`, "run_daily.sh"));
    await assert.rejects(fs.access(path.join(fixture.deployRoot, `.rollback-${selected}`, "locked_exec.py")));
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");

    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 0, resumed.stderr);
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("an exact selected two-file residue from the pre-authority protocol still converges", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  const ready = path.join(fixture.root, "old-selected-two-file-ready");
  const never = path.join(fixture.root, "old-selected-two-file-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "before_rollback_delete",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
    const rollback = path.join(fixture.deployRoot, `.rollback-${selected}`);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    await fs.unlink(path.join(rollback, ".rollback-manifest.json"));
    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 0, resumed.stderr);
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const point of ["after_cleanup_record_root_fsync", "after_rollback_rename_fsync"]) {
  deploymentTest(`two-file first-legacy formal cleanup record resumes from ${point}`, async () => {
    const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
    const ready = path.join(fixture.root, `legacy-two-file-${point}-ready`);
    const never = path.join(fixture.root, `legacy-two-file-${point}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");
      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
      assert.deepEqual(leftovers, []);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("a migrated marker with no prior lock helper fails closed before a new current commit", async () => {
  const fixture = await setupFixture({ withLegacyHelper: false });
  try {
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /no prior locked_exec\.py rollback pair/);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a failed two-file first legacy migration restores and completes detached cleanup", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  try {
    const result = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper" },
    });
    assert.notEqual(result.code, 0);
    await assert.rejects(fs.access(path.join(fixture.deployRoot, "current")));
    await assert.rejects(fs.access(path.join(fixture.runtime, "locked_exec.py")));
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("immediate detached two-file create rejects a live mode mismatch and preserves the journal", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  try {
    const rollback = await seedDetachedRollback(fixture);
    await fs.chmod(path.join(fixture.runtime, "run_daily.sh"), 0o644);
    const before = await digestTree(rollback);
    const result = await run("python3", [rollbackCleanupSource,
      "create", fixture.deployRoot, fixture.runtime, rollback, "__ABSENT__", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /restored runtime does not match rollback backup: run_daily\.sh/);
    assert.equal(await digestTree(rollback), before);
    const evidence = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(evidence, [path.basename(rollback)]);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("immediate detached stable create rejects a helper mode mismatch and preserves the journal", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  try {
    const rollback = await seedDetachedRollback(fixture, { includeHelper: true });
    await fs.chmod(path.join(fixture.runtime, "locked_exec.py"), 0o644);
    const before = await digestTree(rollback);
    const result = await run("python3", [rollbackCleanupSource,
      "create", fixture.deployRoot, fixture.runtime, rollback, "__ABSENT__", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /restored runtime does not match rollback backup: locked_exec\.py/);
    assert.equal(await digestTree(rollback), before);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("immediate detached stable create rejects a marker mode mismatch and preserves the journal", async () => {
  const fixture = await setupFixture();
  try {
    const rollback = await seedDetachedRollback(fixture, { includeHelper: true, includeMarker: true });
    await fs.chmod(path.join(fixture.runtime, ".stable-health-migration.json"), 0o600);
    const before = await digestTree(rollback);
    const result = await run("python3", [rollbackCleanupSource,
      "create", fixture.deployRoot, fixture.runtime, rollback, "releases/old", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /restored marker differs from rollback/);
    assert.equal(await digestTree(rollback), before);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const pollution of [
  { name: "precommit file only", includeHelper: true, entry: ".precommit_check_health.mjs", content: "orphan-precommit\n" },
  { name: "precommit sentinel only", includeHelper: true, entry: ".precommit_check_health.mjs.present", content: "" },
  { name: "marker file only", includeHelper: true, entry: ".stable-health-migration.json", content: "orphan-marker\n" },
  { name: "helper sentinel only", includeHelper: true, remove: "locked_exec.py" },
]) {
  deploymentTest(`immediate detached create rejects ${pollution.name} before record publication`, async () => {
    const fixture = await setupFixture({ withCurrent: false });
    try {
      const rollback = await seedDetachedRollback(fixture, { includeHelper: pollution.includeHelper });
      if (pollution.remove) await fs.unlink(path.join(rollback, pollution.remove));
      else await fs.writeFile(path.join(rollback, pollution.entry), pollution.content);
      const before = await snapshotRollbackEvidence(fixture.deployRoot);
      const result = await run("python3", [rollbackCleanupSource,
        "create", fixture.deployRoot, fixture.runtime, rollback, "__ABSENT__", testLegacyHealthCheckerSha,
      ], { env: fixture.env });
      assert.equal(result.code, 1);
      assert.match(result.stderr, /incomplete (precommit health|marker|helper) pair/);
      await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
      assert.equal(before.names.some((name) => name.includes("rollback-cleanup")), false);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("immediate detached helper profile rejects a live deployment gate and preserves the journal", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  try {
    const rollback = await seedDetachedRollback(fixture, { includeHelper: true });
    await fs.writeFile(path.join(fixture.runtime, ".deployment-phase"), "foreign-gate\n");
    const before = await snapshotRollbackEvidence(fixture.deployRoot);
    const result = await run("python3", [rollbackCleanupSource,
      "create", fixture.deployRoot, fixture.runtime, rollback, "__ABSENT__", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /retains a deployment phase gate/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
    assert.equal(await fs.readFile(path.join(fixture.runtime, ".deployment-phase"), "utf8"), "foreign-gate\n");
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("complete detached precommit evidence must bind live state and remains compatible when exact", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  try {
    const live = path.join(fixture.runtime, ".precommit_check_health.mjs");
    await fs.writeFile(live, "saved-precommit\n");
    const rollback = await seedDetachedRollback(fixture, { includeHelper: true, includePrecommit: true });
    const saved = path.join(rollback, ".precommit_check_health.mjs");
    await fs.writeFile(live, "different-precommit\n");
    const before = await snapshotRollbackEvidence(fixture.deployRoot);
    const rejected = await run("python3", [rollbackCleanupSource,
      "create", fixture.deployRoot, fixture.runtime, rollback, "__ABSENT__", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.equal(rejected.code, 1);
    assert.match(rejected.stderr, /restored precommit health differs from rollback/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);

    await fs.copyFile(saved, live);
    const accepted = await run("python3", [rollbackCleanupSource,
      "create", fixture.deployRoot, fixture.runtime, rollback, "__ABSENT__", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.equal(accepted.code, 0, accepted.stderr);
    await assert.rejects(fs.access(rollback));
    assert.equal(await fs.readFile(live, "utf8"), "saved-precommit\n");
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const pollution of [
  { name: "precommit file only", entry: ".precommit_check_health.mjs", content: "orphan-precommit\n" },
  { name: "precommit sentinel only", entry: ".precommit_check_health.mjs.present", content: "" },
]) {
  deploymentTest(`detached scratch recovery rejects ${pollution.name} without rewriting evidence`, async () => {
    const fixture = await setupFixture({ withCurrent: false });
    const ready = path.join(fixture.root, `scratch-half-${pollution.entry.replaceAll(".", "-")}-ready`);
    const never = path.join(fixture.root, `scratch-half-${pollution.entry.replaceAll(".", "-")}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_record_temp_partial_write",
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");
      const rootEntries = await fs.readdir(fixture.deployRoot, { withFileTypes: true });
      const rollbackEntry = rootEntries.find((entry) => entry.isDirectory() && /^\.rollback-[0-9]/.test(entry.name));
      assert.ok(rollbackEntry);
      await fs.writeFile(path.join(fixture.deployRoot, rollbackEntry.name, pollution.entry), pollution.content);
      const before = await snapshotRollbackEvidence(fixture.deployRoot);
      assert.equal(before.names.some((name) => /\.json\.tmp-bound-[a-f0-9]{64}-[a-f0-9]{32}$/.test(name)), true);
      const result = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(result.code, 70);
      assert.match(result.stderr, /incomplete precommit health pair/);
      await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("partial detached tombstone rejects a half helper pair in its formal record", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  const ready = path.join(fixture.root, "formal-half-helper-ready");
  const never = path.join(fixture.root, "formal-half-helper-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_tombstone_unlink_check_health.mjs.present",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    const evidence = await snapshotRollbackEvidence(fixture.deployRoot);
    const recordName = evidence.names.find((name) => /^\.rollback-cleanup-detached-.*\.json$/.test(name));
    assert.ok(recordName);
    const recordPath = path.join(fixture.deployRoot, recordName);
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    delete record.entries["locked_exec.py.present"];
    await fs.writeFile(recordPath, `${JSON.stringify(record)}\n`);
    const before = await snapshotRollbackEvidence(fixture.deployRoot);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /incomplete helper pair/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("partial detached tombstone rejects helper metadata jointly forged in record and remaining tombstone", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  const ready = path.join(fixture.root, "formal-helper-binding-ready");
  const never = path.join(fixture.root, "formal-helper-binding-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_tombstone_unlink_check_health.mjs.present",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    const evidence = await snapshotRollbackEvidence(fixture.deployRoot);
    const recordName = evidence.names.find((name) => /^\.rollback-cleanup-detached-.*\.json$/.test(name));
    assert.ok(recordName);
    const recordPath = path.join(fixture.deployRoot, recordName);
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    const tombstoneHelper = path.join(fixture.deployRoot, record.tombstone, "locked_exec.py");
    const forgedMode = record.entries["locked_exec.py"].mode === 0o700 ? 0o744 : 0o700;
    await fs.chmod(tombstoneHelper, forgedMode);
    record.entries["locked_exec.py"].mode = forgedMode;
    await fs.writeFile(recordPath, `${JSON.stringify(record)}\n`);
    const before = await snapshotRollbackEvidence(fixture.deployRoot);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /restored runtime does not match rollback backup: locked_exec\.py/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const point of [
  "after_detached_record_temp_partial_write",
  "after_detached_record_root_fsync",
  "after_detached_rollback_rename_before_root_fsync",
]) {
  deploymentTest(`detached two-file ${point} rejects a later live mode mismatch without changing evidence`, async () => {
    const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
    const ready = path.join(fixture.root, `detached-mode-${point}-ready`);
    const never = path.join(fixture.root, `detached-mode-${point}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");
      const evidenceNames = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-")).sort();
      const evidenceBytes = new Map();
      for (const name of evidenceNames) {
        const full = path.join(fixture.deployRoot, name);
        const status = await fs.lstat(full);
        evidenceBytes.set(name, status.isDirectory() ? await digestTree(full) : await fs.readFile(full));
      }
      await fs.chmod(path.join(fixture.runtime, "run_daily.sh"), 0o644);
      const result = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(result.code, 70);
      assert.deepEqual(
        (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-")).sort(),
        evidenceNames,
      );
      for (const [name, before] of evidenceBytes) {
        const full = path.join(fixture.deployRoot, name);
        const status = await fs.lstat(full);
        if (status.isDirectory()) assert.equal(await digestTree(full), before);
        else assert.deepEqual(await fs.readFile(full), before);
      }
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const point of [
  "after_precurrent_restore_check_health.mjs_fsync",
  "after_precurrent_restore_locked_exec.py_fsync",
  "after_precurrent_gate_unlink_before_dir_fsync",
]) {
  deploymentTest(`sealed real two-file legacy recovery converges after a second SIGKILL at ${point}`, async () => {
    const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
    const ready = path.join(fixture.root, `two-file-${point}-ready`);
    const never = path.join(fixture.root, `two-file-${point}-never`);
    try {
      await crashStablePrecurrentTransaction(fixture, `two-file-${point}`);
      const recovering = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, recovering.exited);
      process.kill(-recovering.child.pid, "SIGKILL");
      assert.equal((await recovering.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      assert.match(await fs.readlink(path.join(fixture.deployRoot, "current")), /^releases\//);
      const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
      assert.deepEqual(leftovers, []);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const point of [
  "after_precurrent_restore_run_daily.sh_fsync",
  "after_precurrent_restore_check_health.mjs_fsync",
  "after_precurrent_restore_locked_exec.py_fsync",
  "after_precurrent_restore_.stable-health-migration.json_fsync",
  "after_precurrent_restore_.precommit_check_health.mjs_fsync",
  "after_precurrent_gate_unlink_before_dir_fsync",
]) {
  deploymentTest(`sealed no-current legacy recovery converges after a second SIGKILL at ${point}`, async () => {
    const fixture = await setupFixture({ withCurrent: false });
    const ready = path.join(fixture.root, `legacy-${point.replaceAll("/", "-")}-ready`);
    const never = path.join(fixture.root, `legacy-${point.replaceAll("/", "-")}-never`);
    try {
      await crashStablePrecurrentTransaction(fixture, `legacy-${point.replaceAll("/", "-")}`);
      const recovering = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, recovering.exited);
      process.kill(-recovering.child.pid, "SIGKILL");
      assert.equal((await recovering.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      assert.match(await fs.readlink(path.join(fixture.deployRoot, "current")), /^releases\//);
      const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
      assert.deepEqual(leftovers, []);
      const runtimeTemps = (await fs.readdir(fixture.runtime)).filter((name) => name.includes(".precurrent-"));
      assert.deepEqual(runtimeTemps, []);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("a detached two-file cleanup record rejects a later current pointer and preserves evidence", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  const ready = path.join(fixture.root, "detached-two-file-current-ready");
  const never = path.join(fixture.root, "detached-two-file-current-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_rollback_rename_before_root_fsync",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    await atomicCurrent(fixture.deployRoot, "releases/old");
    const before = await fs.readdir(fixture.deployRoot);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /detached cleanup record does not bind restored runtime/);
    assert.deepEqual(await fs.readdir(fixture.deployRoot), before);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const scenario of [
  { name: "live gate", point: "after_detached_record_root_fsync", gate: true, fallback: false },
  { name: "live fallback", point: "after_detached_record_root_fsync", gate: false, fallback: true },
  { name: "live gate and fallback", point: "after_detached_record_root_fsync", gate: true, fallback: true },
  { name: "live gate during scratch recovery", point: "after_detached_record_temp_partial_write", gate: true, fallback: false },
  { name: "live fallback during tombstone recovery", point: "after_detached_rollback_rename_before_root_fsync", gate: false, fallback: true },
]) {
  deploymentTest(`detached two-file cleanup rejects ${scenario.name} and preserves evidence`, async () => {
    const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
    const ready = path.join(fixture.root, `detached-contamination-${scenario.point}-${scenario.name}-ready`);
    const never = path.join(fixture.root, `detached-contamination-${scenario.point}-${scenario.name}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: scenario.point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");
      if (scenario.gate) await fs.writeFile(path.join(fixture.runtime, ".deployment-phase"), "foreign-gate\n");
      if (scenario.fallback) await fs.writeFile(path.join(fixture.runtime, ".precommit_check_health.mjs"), "foreign-fallback\n");
      const evidenceBefore = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-")).sort();
      const result = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(result.code, 70);
      const evidenceAfter = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-")).sort();
      assert.deepEqual(evidenceAfter, evidenceBefore);
      if (scenario.gate) await fs.access(path.join(fixture.runtime, ".deployment-phase"));
      if (scenario.fallback) await fs.access(path.join(fixture.runtime, ".precommit_check_health.mjs"));
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("selected two-file cleanup rejects a precommit fallback pair and preserves its journal", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  const ready = path.join(fixture.root, "selected-two-file-precommit-ready");
  const never = path.join(fixture.root, "selected-two-file-precommit-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "before_rollback_delete",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
    const rollback = path.join(fixture.deployRoot, `.rollback-${selected}`);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    await fs.writeFile(path.join(rollback, ".precommit_check_health.mjs"), "foreign-fallback\n");
    await fs.writeFile(path.join(rollback, ".precommit_check_health.mjs.present"), "");
    const before = await digestTree(rollback);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /prior stable runtime|missing an authenticated lock-helper profile/);
    assert.equal(await digestTree(rollback), before);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("selected immediate cleanup rejects a half precommit pair before publishing a record", async () => {
  const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
  const ready = path.join(fixture.root, "selected-half-precommit-ready");
  const never = path.join(fixture.root, "selected-half-precommit-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "before_rollback_delete",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
    const rollback = path.join(fixture.deployRoot, `.rollback-${selected}`);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    await fs.writeFile(path.join(rollback, ".precommit_check_health.mjs.present"), "");
    const before = await snapshotRollbackEvidence(fixture.deployRoot);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /incomplete rollback journal pair: \.precommit_check_health\.mjs/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
    assert.equal(before.names.some((name) => name.includes("rollback-cleanup")), false);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const mutation of [
  { name: "string metadata", apply: () => "corrupt" },
  { name: "bad metadata object", apply: () => ({ mode: 0o600, sha256: "bad", size: 0, extra: true }) },
  { name: "boolean mode", apply: (old) => ({ ...old, mode: true }) },
  { name: "nonempty sentinel digest", apply: (old) => ({ ...old, size: 1, sha256: crypto.createHash("sha256").update("x").digest("hex") }) },
]) {
  deploymentTest(`partial detached tombstone rejects deleted-sentinel ${mutation.name} and preserves evidence`, async () => {
    const fixture = await setupFixture({ withCurrent: false, withLegacyHelper: false });
    const ready = path.join(fixture.root, `detached-record-${mutation.name}-ready`);
    const never = path.join(fixture.root, `detached-record-${mutation.name}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_tombstone_unlink_check_health.mjs.present",
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");
      const evidenceNames = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-")).sort();
      const recordName = evidenceNames.find((name) => /^\.rollback-cleanup-detached-.*\.json$/.test(name));
      assert.ok(recordName);
      const recordPath = path.join(fixture.deployRoot, recordName);
      const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
      record.entries["check_health.mjs.present"] = mutation.apply(record.entries["check_health.mjs.present"]);
      await fs.writeFile(recordPath, `${JSON.stringify(record)}\n`);
      const recordBefore = await fs.readFile(recordPath);
      const tombstone = path.join(fixture.deployRoot, record.tombstone);
      const tombstoneBefore = await digestTree(tombstone);
      const result = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(result.code, 70);
      assert.deepEqual(await fs.readFile(recordPath), recordBefore);
      assert.equal(await digestTree(tombstone), tombstoneBefore);
      assert.deepEqual(
        (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-")).sort(),
        evidenceNames,
      );
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const corruption of [
  {
    name: "dangling expected release",
    apply: async (fixture) => {
      await fs.rm(path.join(fixture.deployRoot, "releases", "old"), { recursive: true });
    },
  },
  {
    name: "symlinked expected release",
    apply: async (fixture) => {
      const releases = path.join(fixture.deployRoot, "releases");
      await fs.rename(path.join(releases, "old"), path.join(releases, "old-real"));
      await fs.symlink("old-real", path.join(releases, "old"));
    },
  },
]) {
  deploymentTest(`pre-current recovery rejects a ${corruption.name} before any live or evidence mutation`, async () => {
    const fixture = await setupFixture();
    try {
      await crashStablePrecurrentTransaction(fixture, corruption.name.replaceAll(" ", "-"));
      await corruption.apply(fixture);
      const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
      const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 70);
      await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
      assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const conflict of [
  {
    name: "malformed formal record from another release",
    apply: async (fixture, release) => {
      await fs.writeFile(
        path.join(fixture.deployRoot, `.rollback-cleanup-detached-${release}.json`),
        "{malformed\n",
      );
    },
  },
  {
    name: "symlinked formal record from another release",
    apply: async (fixture, release) => {
      await fs.symlink(
        "missing-formal-record",
        path.join(fixture.deployRoot, `.rollback-cleanup-detached-${release}.json`),
      );
    },
  },
  {
    name: "bound scratch from another release with no authority",
    apply: async (fixture, release) => {
      const scratch = path.join(
        fixture.deployRoot,
        `.rollback-cleanup-detached-${release}.json.tmp-bound-${"a".repeat(64)}-${"b".repeat(32)}`,
      );
      await fs.writeFile(scratch, "partial-record\n", { mode: 0o600 });
      await fs.chmod(scratch, 0o600);
    },
  },
  {
    name: "bound scratch from another release with bad authority",
    apply: async (fixture, release) => {
      const rollback = path.join(fixture.deployRoot, `.rollback-${release}`);
      await fs.mkdir(rollback);
      await fs.writeFile(path.join(rollback, ".rollback-manifest.json"), '{"schema":true}\n', { mode: 0o600 });
      const scratch = path.join(
        fixture.deployRoot,
        `.rollback-cleanup-detached-${release}.json.tmp-bound-${"c".repeat(64)}-${"d".repeat(32)}`,
      );
      await fs.writeFile(scratch, "partial-record\n", { mode: 0o600 });
      await fs.chmod(scratch, 0o600);
    },
  },
]) {
  deploymentTest(`active sealed recovery rejects a ${conflict.name} before any mutation`, async () => {
    const fixture = await setupFixture();
    const otherRelease = `20260802T030303Z-${process.pid + 100}`;
    try {
      await crashStablePrecurrentTransaction(fixture, conflict.name.replaceAll(" ", "-"));
      await conflict.apply(fixture, otherRelease);
      const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
      const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
      const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 70);
      assert.match(resumed.stderr, /multiple detached cleanup transaction releases are ambiguous/);
      await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
      assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
      assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const kind of ["regular file", "dangling symlink"]) {
  deploymentTest(`resume rejects a rollback-shaped ${kind} without touching it or live runtime`, async () => {
    const fixture = await setupFixture();
    const candidate = path.join(fixture.deployRoot, `.rollback-20260802T020202Z-${process.pid}`);
    try {
      if (kind === "regular file") await fs.writeFile(candidate, "do-not-delete\n");
      else await fs.symlink("missing-rollback-target", candidate);
      const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
      const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
      const result = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(result.code, 70);
      assert.match(result.stderr, /unsafe detached rollback candidate/);
      assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
      assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
      if (kind === "regular file") assert.equal(await fs.readFile(candidate, "utf8"), "do-not-delete\n");
      else assert.equal(await fs.readlink(candidate), "missing-rollback-target");
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("a symlinked runtime root is rejected before helper or shell bootstrap can touch its target", async () => {
  const fixture = await setupFixture();
  const externalRuntime = path.join(fixture.root, "external-runtime");
  try {
    await fs.rename(fixture.runtime, externalRuntime);
    await fs.symlink(externalRuntime, fixture.runtime);
    const externalBefore = await digestTree(externalRuntime);
    const helper = await run("python3", [
      rollbackCleanupSource, "resume", fixture.deployRoot, fixture.runtime, "", "", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.notEqual(helper.code, 0);
    assert.match(helper.stderr, /runtime root is unsafe/);
    assert.equal(await digestTree(externalRuntime), externalBefore);

    const deployed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(deployed.code, 70);
    assert.match(deployed.stderr, /runtime root must be a real direct child directory/);
    assert.equal(await fs.readlink(fixture.runtime), externalRuntime);
    assert.equal(await digestTree(externalRuntime), externalBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a SIGKILL releases the fcntl lock without stale cleanup", async () => {
  const fixture = await setupFixture();
  const lock = path.join(fixture.deployRoot, ".crash-test.lock");
  const ready = path.join(fixture.root, "crash-ready");
  try {
    const holder = spawn("python3", [lockHelperSource,
      "--lock", lock, "--lock-dir", path.join(fixture.runtime, "data"), "--fd-env", "CRASH_LOCK_FD", "--active-env", "CRASH_LOCK_ACTIVE",
      "--busy-exit", "75", "--", "sleep", "30"], {
      env: { ...process.env, SP_SINGLE_PAGE_TEST_MODE: "1", SP_SINGLE_PAGE_TEST_LOCK_READY_FILE: ready },
      stdio: "ignore",
    });
    const holderExit = new Promise((resolve) => holder.once("exit", resolve));
    await waitFor(ready);
    holder.kill("SIGKILL");
    await holderExit;
    const recovered = await run("python3", [lockHelperSource,
      "--lock", lock, "--lock-dir", path.join(fixture.runtime, "data"), "--fd-env", "CRASH_LOCK_FD_2", "--active-env", "CRASH_LOCK_ACTIVE_2",
      "--busy-exit", "75", "--", "/usr/bin/true"]);
    assert.equal(recovered.code, 0);
    assert.equal((await fs.lstat(lock)).isSymbolicLink(), true);
    await assert.rejects(fs.access(path.join(fixture.deployRoot, ".single-page-runtime.fcntl")));
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("renaming the compatibility protocol cannot create a second lock owner", async () => {
  const fixture = await setupFixture();
  const lock = path.join(fixture.runtime, "data", "aba.lock");
  const ready = path.join(fixture.root, "aba-ready");
  const holder = spawn("python3", [lockHelperSource,
    "--lock", lock, "--lock-dir", path.join(fixture.runtime, "data"), "--fd-env", "ABA_LOCK_FD", "--active-env", "ABA_LOCK_ACTIVE",
    "--busy-exit", "75", "--", "sleep", "30"], {
    env: { ...process.env, SP_SINGLE_PAGE_TEST_MODE: "1", SP_SINGLE_PAGE_TEST_LOCK_READY_FILE: ready },
    stdio: "ignore",
  });
  const holderExit = new Promise((resolve) => holder.once("exit", resolve));
  try {
    await waitFor(ready);
    const protocol = path.join(path.dirname(lock), `.${path.basename(lock)}.protocol-v3`);
    const moved = `${protocol}.moved`;
    const obsoleteAnchor = path.join(fixture.deployRoot, ".single-page-runtime.fcntl");
    await fs.writeFile(obsoleteAnchor, "obsolete\n");
    await fs.rename(obsoleteAnchor, `${obsoleteAnchor}.moved`);
    await fs.writeFile(obsoleteAnchor, "replacement\n");
    await fs.rename(protocol, moved);
    const contender = await run("python3", [lockHelperSource,
      "--lock", lock, "--lock-dir", path.join(fixture.runtime, "data"), "--fd-env", "ABA_LOCK_FD_2", "--active-env", "ABA_LOCK_ACTIVE_2",
      "--busy-exit", "75", "--", "/usr/bin/true"]);
    assert.equal(contender.code, 75);
    assert.equal(await fs.readlink(lock), path.basename(protocol));
    holder.kill("SIGKILL");
    await holderExit;
    const recovered = await run("python3", [lockHelperSource,
      "--lock", lock, "--lock-dir", path.join(fixture.runtime, "data"), "--fd-env", "ABA_LOCK_FD_3", "--active-env", "ABA_LOCK_ACTIVE_3",
      "--busy-exit", "75", "--", "/usr/bin/true"]);
    assert.equal(recovered.code, 0);
  } finally {
    if (holder.exitCode === null && holder.signalCode === null) holder.kill("SIGKILL");
    await removeFixture(fixture.root);
  }
});

deploymentTest("the persistent data lock root must be a real directory, not a symlink", async () => {
  const fixture = await setupFixture();
  const data = path.join(fixture.runtime, "data");
  const outsideData = path.join(fixture.root, "outside-data");
  try {
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    await fs.rm(data, { recursive: true });
    await fs.mkdir(outsideData);
    await fs.symlink(outsideData, data);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /runtime lock root must be a real directory/);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("only an authenticated first legacy migration may use the no-current health fallback", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  const ready = path.join(fixture.root, "health-window-ready");
  const proceed = path.join(fixture.root, "health-window-proceed");
  const mark = path.join(fixture.root, "health-result");
  try {
    const deploying = run("bash", [deployScript], {
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: proceed,
      },
    });
    await waitForWhileRunning(ready, deploying);
    await assert.rejects(fs.access(path.join(fixture.deployRoot, "current")));
    const health = await run(process.execPath, [path.join(fixture.runtime, "check_health.mjs")], {
      env: { ...fixture.env, HEALTH_MARK: mark },
    });
    assert.equal(health.code, 0);
    assert.equal(await fs.readFile(mark, "utf8"), "legacy-health\n");
    await fs.writeFile(proceed, "go\n");
    assert.equal((await deploying).code, 0);
    const currentTarget = await fs.readlink(path.join(fixture.deployRoot, "current"));
    assert.match(currentTarget, /^releases\//);
    await assert.rejects(fs.access(path.join(fixture.runtime, ".precommit_check_health.mjs")));
    await assert.rejects(fs.access(path.join(fixture.runtime, ".deployment-phase")));

    const marker = JSON.parse(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"), "utf8"));
    assert.equal(marker.schema, 2);
    assert.equal(marker.wrapper_id, "spspy-single-page-stable-health");
    assert.equal(marker.wrapper_version, 2);
    assert.equal(marker.wrapper_sha256, crypto.createHash("sha256").update(await fs.readFile(path.join(fixture.runtime, "check_health.mjs"))).digest("hex"));

    // A later loss of current is recovery state, never a new fallback window.
    const wrapperBefore = await fs.readFile(path.join(fixture.runtime, "check_health.mjs"));
    await fs.unlink(path.join(fixture.deployRoot, "current"));
    const afterMissing = await run(process.execPath, [path.join(fixture.runtime, "check_health.mjs")], {
      env: { ...fixture.env, HEALTH_MARK: mark },
    });
    assert.equal(afterMissing.code, 70);
    await fs.rm(mark, { force: true });
    const retry = await run("bash", [deployScript], {
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: path.join(fixture.root, "must-not-exist"),
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: path.join(fixture.root, "must-not-exist-continue"),
      },
    });
    assert.equal(retry.code, 70);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "check_health.mjs")), wrapperBefore);
    await assert.rejects(fs.access(path.join(fixture.runtime, ".precommit_check_health.mjs")));
    await assert.rejects(fs.access(path.join(fixture.runtime, ".deployment-phase")));
    const stillMissing = await run(process.execPath, [path.join(fixture.runtime, "check_health.mjs")], {
      env: { ...fixture.env, HEALTH_MARK: mark },
    });
    assert.equal(stillMissing.code, 70);
    await assert.rejects(fs.access(mark));

    // Explicit operator restoration of the known target lets the normal,
    // no-fallback release path finish successfully.
    await atomicCurrent(fixture.deployRoot, currentTarget);
    const recovered = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(recovered.code, 0, recovered.stderr);

    // A corrupt marker and an untrusted no-current checker both stop before
    // any live wrapper, fallback, or phase gate can be written.
    const badMarkerFixture = await setupFixture({ withCurrent: false });
    try {
      const before = await fs.readFile(path.join(badMarkerFixture.runtime, "check_health.mjs"));
      await fs.writeFile(path.join(badMarkerFixture.runtime, ".stable-health-migration.json"), "not-json\n");
      const badMarker = await run("bash", [deployScript], { env: badMarkerFixture.env });
      assert.equal(badMarker.code, 70);
      assert.deepEqual(await fs.readFile(path.join(badMarkerFixture.runtime, "check_health.mjs")), before);
      await assert.rejects(fs.access(path.join(badMarkerFixture.runtime, ".precommit_check_health.mjs")));
      await assert.rejects(fs.access(path.join(badMarkerFixture.runtime, ".deployment-phase")));
    } finally {
      await removeFixture(badMarkerFixture.root);
    }

    const forgedFixture = await setupFixture({ withCurrent: false });
    try {
      const before = await fs.readFile(path.join(forgedFixture.runtime, "check_health.mjs"));
      await fs.writeFile(path.join(forgedFixture.runtime, "check_health.mjs"), "process.exit(0);\n");
      const forged = await run("bash", [deployScript], { env: forgedFixture.env });
      assert.equal(forged.code, 70);
      assert.deepEqual(await fs.readFile(path.join(forgedFixture.runtime, "check_health.mjs")), Buffer.from("process.exit(0);\n"));
      assert.notDeepEqual(before, await fs.readFile(path.join(forgedFixture.runtime, "check_health.mjs")));
      await assert.rejects(fs.access(path.join(forgedFixture.runtime, ".precommit_check_health.mjs")));
      await assert.rejects(fs.access(path.join(forgedFixture.runtime, ".deployment-phase")));
    } finally {
      await removeFixture(forgedFixture.root);
    }
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("SIGKILL in the first no-current health window restores the sealed legacy transaction", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  const ready = path.join(fixture.root, "first-kill-ready");
  const never = path.join(fixture.root, "first-kill-never");
  const mark = path.join(fixture.root, "first-kill-health");
  try {
    const deploying = start("bash", [deployScript], {
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    deploying.child.kill("SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    const health = await run(process.execPath, [path.join(fixture.runtime, "check_health.mjs")], {
      env: { ...fixture.env, HEALTH_MARK: mark },
    });
    assert.equal(health.code, 70);
    await assert.rejects(fs.access(mark));
    const recovery = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(recovery.code, 0, recovery.stderr);
    assert.match(await fs.readlink(path.join(fixture.deployRoot, "current")), /^releases\//);
    await fs.access(path.join(fixture.runtime, ".stable-health-migration.json"));
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a stable launcher executes the release pinned before a current switch", async () => {
  const fixture = await setupFixture();
  const newMonitor = path.join(fixture.deployRoot, "releases", "new", "single-page-monitor");
  const ready = path.join(fixture.root, "pin-ready");
  const proceed = path.join(fixture.root, "pin-proceed");
  const mark = path.join(fixture.root, "pin-result");
  try {
    await fs.mkdir(newMonitor, { recursive: true });
    await fs.writeFile(path.join(newMonitor, "run_daily.sh"), "#!/usr/bin/env bash\nprintf 'new-release\\n' > \"${ENTRY_MARK:?}\"\n", { mode: 0o755 });
    await fs.writeFile(path.join(newMonitor, "check_health.mjs"), "process.exit(0);\n");
    const launched = run(path.join(fixture.runtime, "run_daily.sh"), [], {
      env: {
        ...fixture.env,
        ENTRY_MARK: mark,
        SP_SINGLE_PAGE_TEST_PIN_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PIN_CONTINUE_FILE: proceed,
      },
    });
    await waitFor(ready);
    assert.match(await fs.readFile(ready, "utf8"), /releases\/old\/single-page-monitor\/run_daily\.sh/);
    await atomicCurrent(fixture.deployRoot, "releases/new");
    await fs.writeFile(proceed, "go\n");
    assert.equal((await launched).code, 0);
    assert.equal(await fs.readFile(mark, "utf8"), "old-release\n");
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const point of ["after_lock_helper", "after_daily_wrapper", "after_health_wrapper", "final_fsync"]) {
  deploymentTest(`fault at ${point} durably rolls back current and every stable entrypoint`, async () => {
    const fixture = await setupFixture();
    try {
      const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
      const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
      const healthBefore = await fs.readFile(path.join(fixture.runtime, "check_health.mjs"));
      const helperBefore = await fs.readFile(path.join(fixture.runtime, "locked_exec.py"));
      const result = await run("bash", [deployScript], {
        env: { ...fixture.env, SP_SINGLE_PAGE_TEST_FAIL_POINT: point },
      });
      assert.notEqual(result.code, 0);
      assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
      assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
      assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "check_health.mjs")), healthBefore);
      assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "locked_exec.py")), helperBefore);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("TERM queued after durable current is ignored and the committed deployment returns 0", async () => {
  const fixture = await setupFixture();
  try {
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const result = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_TERM_AFTER_COMMIT: "1" },
    });
    assert.equal(result.code, 0);
    assert.notEqual(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), await fs.readFile(stableRunnerSource));
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("current or migration-marker fsync failure returns nonzero only after restoring old current", async () => {
  const fixture = await setupFixture();
  try {
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const result = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_FAIL_CURRENT_FSYNC: "1" },
    });
    assert.notEqual(result.code, 0);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);

    const markerBefore = await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"));
    const markerFailure = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_FAIL_MARKER_FSYNC: "1" },
    });
    assert.notEqual(markerFailure.code, 0);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json")), markerBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("migration marker installation handles deterministic 1-to-3-byte writes", async () => {
  const fixture = await setupFixture();
  try {
    const result = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES: "3" },
    });
    assert.equal(result.code, 0, result.stderr);
    const marker = JSON.parse(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"), "utf8"));
    assert.equal(marker.schema, 2);
    assert.equal(marker.kind, "spspy-single-page-stable-health-migration");
    assert.match(marker.wrapper_sha256, /^[a-f0-9]{64}$/);
    for (const protocol of [
      path.join(fixture.deployRoot, ".deploy.lock.protocol-v3"),
      path.join(fixture.runtime, "data", ".run_daily.lock.protocol-v3"),
    ]) {
      assert.equal(await fs.readFile(path.join(protocol, ".fcntl-protocol-v3"), "utf8"), "3\n");
      assert.equal(await fs.readFile(path.join(protocol, "pid"), "utf8"), "0\n");
    }
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("zero-length migration marker install write restores old state and preserves gate authority", async () => {
  const fixture = await setupFixture();
  try {
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const result = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_ZERO_WRITE_CONTEXT: "marker-install" },
    });
    assert.equal(result.code, 70);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    const runtimeAfter = await snapshotRuntimeProtocol(fixture.runtime);
    assert.notEqual(runtimeAfter.get(".deployment-phase"), null);
    runtimeAfter.set(".deployment-phase", null);
    assert.deepEqual(runtimeAfter, runtimeBefore);
    const evidence = await snapshotRollbackEvidence(fixture.deployRoot);
    const rollbackName = evidence.names.find((name) => /^\.rollback-[0-9]/.test(name));
    assert.ok(rollbackName);
    await fs.access(path.join(fixture.deployRoot, rollbackName, ".rollback-manifest.json"));
    assert.equal(evidence.names.some((name) => name.includes("rollback-cleanup")), false);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("an unsafe current target fails before any stable entrypoint changes", async () => {
  const fixture = await setupFixture();
  try {
    await fs.unlink(path.join(fixture.deployRoot, "current"));
    await fs.symlink("../../escape", path.join(fixture.deployRoot, "current"));
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const healthBefore = await fs.readFile(path.join(fixture.runtime, "check_health.mjs"));
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.notEqual(result.code, 0);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), "../../escape");
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "check_health.mjs")), healthBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("an intermediate single-page-monitor symlink escape is rejected by deploy, daily, and health", async () => {
  const fixture = await setupFixture();
  const selectedMonitor = path.join(fixture.deployRoot, "releases", "old", "single-page-monitor");
  const outside = path.join(fixture.root, "outside-monitor");
  try {
    await fs.rm(selectedMonitor, { recursive: true, force: true });
    await fs.mkdir(outside);
    await fs.writeFile(path.join(outside, "run_daily.sh"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
    await fs.writeFile(path.join(outside, "check_health.mjs"), "process.exit(0);\n");
    await fs.symlink(outside, selectedMonitor);
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const deploy = await run("bash", [deployScript], { env: fixture.env });
    assert.notEqual(deploy.code, 0);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
    const daily = await run(path.join(fixture.runtime, "run_daily.sh"), [], { env: fixture.env });
    assert.equal(daily.code, 70);
    const health = await run(process.execPath, [path.join(fixture.runtime, "check_health.mjs")], { env: fixture.env });
    assert.equal(health.code, 70);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const point of ["after_lock_helper", "after_daily_wrapper", "after_health_wrapper", "final_fsync", "after_current"]) {
  deploymentTest(`SIGKILL at live point ${point} is recoverable by the next serialized deploy`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `kill-ready-${point}`);
    const never = path.join(fixture.root, `kill-never-${point}`);
    try {
      const deploying = start("bash", [deployScript], {
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      deploying.child.kill("SIGKILL");
      const killed = await deploying.exited;
      assert.equal(killed.signal, "SIGKILL");
      const recovery = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(recovery.code, 0, recovery.stderr);
      assert.match(await fs.readlink(path.join(fixture.deployRoot, "current")), /^releases\//);
      await fs.access(path.join(fixture.runtime, "run_daily.sh"));
      await fs.access(path.join(fixture.runtime, "check_health.mjs"));
      await fs.access(path.join(fixture.runtime, "locked_exec.py"));
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("SIGKILL after durable current repairs a legitimate schema-v2 older-wrapper marker", async () => {
  const fixture = await setupFixture();
  try {
    // The initial inspection has already authenticated v2.  Model a legal
    // schema-v2/v1 runtime marker being upgraded while this deploy is staged;
    // live commit subsequently installs v2, then dies before its marker.
    const crashed = await crashSchema2UpgradeBeforeMarker(fixture, "schema2-upgrade");
    assert.match(crashed.current, /^releases\//);
    const interrupted = JSON.parse(crashed.marker);
    assert.equal(interrupted.schema, 2);
    assert.equal(interrupted.wrapper_version, 1);

    const recovered = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(recovered.code, 0, recovered.stderr);
    const marker = JSON.parse(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"), "utf8"));
    assert.equal(marker.schema, 2);
    assert.equal(marker.wrapper_version, 2);
    assert.equal(marker.wrapper_sha256, crypto.createHash("sha256")
      .update(await fs.readFile(path.join(fixture.runtime, "check_health.mjs"))).digest("hex"));
    await assert.rejects(fs.access(path.join(fixture.runtime, ".deployment-phase")));
    await assert.rejects(fs.access(path.join(fixture.runtime, ".precommit_check_health.mjs")));
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("post-current migration marker recovery handles deterministic 1-to-3-byte writes", async () => {
  const fixture = await setupFixture();
  try {
    await crashSchema2UpgradeBeforeMarker(fixture, "short-marker-recovery");
    const recovered = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_WRITE_MAX_BYTES: "3" },
    });
    assert.equal(recovered.code, 0, recovered.stderr);
    const marker = JSON.parse(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"), "utf8"));
    assert.equal(marker.schema, 2);
    assert.equal(marker.wrapper_version, 2);
    assert.match(marker.wrapper_sha256, /^[a-f0-9]{64}$/);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("marker recovery write exception preserves selected current gate and rollback evidence", async () => {
  const fixture = await setupFixture();
  try {
    const crashed = await crashSchema2UpgradeBeforeMarker(fixture, "failed-marker-recovery-write");
    const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const releaseBefore = await digestTree(path.join(fixture.deployRoot, crashed.current));
    const recovered = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_RAISE_WRITE_CONTEXT: "marker-recovery" },
    });
    assert.equal(recovered.code, 70);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), crashed.current);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
    assert.equal(await digestTree(path.join(fixture.deployRoot, crashed.current)), releaseBefore);
    await fs.access(path.join(fixture.runtime, ".deployment-phase"));
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("SIGKILL after durable current with no marker repairs only the proven selected release", async () => {
  const fixture = await setupFixture({ withCurrent: false });
  const committed = path.join(fixture.root, "missing-current-ready");
  const never = path.join(fixture.root, "missing-current-never");
  try {
    const deploying = start("bash", [deployScript], {
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_current_fsync_before_marker",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: committed,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(committed, deploying.exited);
    await assert.rejects(fs.access(path.join(fixture.runtime, ".stable-health-migration.json")));
    deploying.child.kill("SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");

    const recovered = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(recovered.code, 0, recovered.stderr);
    const marker = JSON.parse(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"), "utf8"));
    assert.equal(marker.schema, 2);
    assert.equal(marker.wrapper_version, 2);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("an unknown schema-v2 marker mismatch is fail-closed without repairing live files", async () => {
  const fixture = await setupFixture();
  try {
    const seeded = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(seeded.code, 0, seeded.stderr);
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const healthBefore = await fs.readFile(path.join(fixture.runtime, "check_health.mjs"));
    const helperBefore = await fs.readFile(path.join(fixture.runtime, "locked_exec.py"));
    await writeMigrationMarker(fixture.runtime, {
      schema: 2,
      wrapperVersion: 1,
      wrapperSha: "0".repeat(64),
    });
    const markerBefore = await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"));
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /missing deployment phase gate/);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "check_health.mjs")), healthBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "locked_exec.py")), helperBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json")), markerBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("schema-v2 recovery rejects a phase gate whose release_id does not bind current", async () => {
  const fixture = await setupFixture();
  try {
    const crashed = await crashSchema2UpgradeBeforeMarker(fixture, "wrong-gate");
    const gatePath = path.join(fixture.runtime, ".deployment-phase");
    const gate = JSON.parse(await fs.readFile(gatePath, "utf8"));
    gate.release_id = `${crashed.current.split("/").at(-1)}:999999`;
    await fs.writeFile(gatePath, `${JSON.stringify(gate)}\n`);
    const dailyBefore = await fs.readFile(path.join(fixture.runtime, "run_daily.sh"));
    const healthBefore = await fs.readFile(path.join(fixture.runtime, "check_health.mjs"));
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /phase gate does not bind selected current release/);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), crashed.current);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json")), crashed.marker);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "run_daily.sh")), dailyBefore);
    assert.deepEqual(await fs.readFile(path.join(fixture.runtime, "check_health.mjs")), healthBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("post-current recovery rejects a boolean phase wrapper version even when numeric one is expected", async () => {
  const fixture = await setupFixture();
  try {
    const crashed = await crashSchema2UpgradeBeforeMarker(fixture, "boolean-gate-version");
    const selectedMonitor = path.join(fixture.deployRoot, crashed.current, "single-page-monitor");
    const selectedWrapper = path.join(selectedMonitor, "stable_check_health.mjs");
    await fs.chmod(selectedWrapper, 0o644);
    const versionOneWrapper = `${(await fs.readFile(selectedWrapper, "utf8"))
      .replace("const STABLE_WRAPPER_VERSION = 2;", "const STABLE_WRAPPER_VERSION = 1;")}\n// distinct boolean-gate fixture\n`;
    await fs.writeFile(selectedWrapper, versionOneWrapper);
    await fs.chmod(selectedWrapper, 0o444);
    await fs.writeFile(path.join(fixture.runtime, "check_health.mjs"), versionOneWrapper, { mode: 0o755 });
    await fs.chmod(path.join(fixture.runtime, "check_health.mjs"), 0o755);
    const gatePath = path.join(fixture.runtime, ".deployment-phase");
    const gate = JSON.parse(await fs.readFile(gatePath, "utf8"));
    gate.wrapper_version = true;
    gate.wrapper_sha256 = crypto.createHash("sha256").update(versionOneWrapper).digest("hex");
    await fs.writeFile(gatePath, `${JSON.stringify(gate)}\n`);

    const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const releaseBefore = await digestTree(path.join(fixture.deployRoot, crashed.current));
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /phase gate does not bind selected current release/);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), crashed.current);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
    assert.equal(await digestTree(path.join(fixture.deployRoot, crashed.current)), releaseBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("schema-v2 pre-current recovery restores the exact authority state when current is observably old", async () => {
  const fixture = await setupFixture();
  try {
    const crashed = await crashSchema2UpgradeBeforeMarker(fixture, "wrong-current");
    await atomicCurrent(fixture.deployRoot, "releases/old");
    const recovered = await run("python3", [
      rollbackCleanupSource, "resume", fixture.deployRoot, fixture.runtime, "", "", testLegacyHealthCheckerSha,
    ], { env: fixture.env });
    assert.equal(recovered.code, 0, recovered.stderr);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), "releases/old");
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), crashed.expectedRuntime);
    const rootResidue = (await fs.readdir(fixture.deployRoot)).filter((name) =>
      name.startsWith(".rollback-") || name.startsWith(".current-precurrent-"));
    assert.deepEqual(rootResidue, []);
    const runtimeTemps = (await fs.readdir(fixture.runtime)).filter((name) => name.includes(".precurrent-"));
    assert.deepEqual(runtimeTemps, []);

    const deployed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(deployed.code, 0, deployed.stderr);
    assert.notEqual(await fs.readlink(path.join(fixture.deployRoot, "current")), "releases/old");
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const point of ["after_gate_unlink_fsync", "before_rollback_delete"]) {
  deploymentTest(`recovery SIGKILL at ${point} resumes and removes the selected rollback journal`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `${point}-ready`);
    const never = path.join(fixture.root, `${point}-never`);
    try {
      const crashed = await crashSchema2UpgradeBeforeMarker(fixture, `${point}-seed`);
      const selected = crashed.current.split("/").at(-1);
      const rollback = path.join(fixture.deployRoot, `.rollback-${selected}`);
      await fs.access(rollback);
      const recovering = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, recovering.exited);
      const installed = JSON.parse(await fs.readFile(path.join(fixture.runtime, ".stable-health-migration.json"), "utf8"));
      assert.equal(installed.schema, 2);
      assert.equal(installed.wrapper_version, 2);
      await assert.rejects(fs.access(path.join(fixture.runtime, ".deployment-phase")));
      await assert.rejects(fs.access(path.join(fixture.runtime, ".precommit_check_health.mjs")));
      await fs.access(rollback);
      process.kill(-recovering.child.pid, "SIGKILL");
      assert.equal((await recovering.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      await assert.rejects(fs.access(rollback));
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const point of ["after_rollback_rename_fsync", "after_tombstone_unlink_run_daily.sh"]) {
  deploymentTest(`recovery SIGKILL at ${point} resumes partially deleted tombstone`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `${point}-ready`);
    const never = path.join(fixture.root, `${point}-never`);
    try {
      const crashed = await crashSchema2UpgradeBeforeMarker(fixture, `${point}-seed`);
      const selected = crashed.current.split("/").at(-1);
      const rollback = path.join(fixture.deployRoot, `.rollback-${selected}`);
      const cleanupRecord = path.join(fixture.deployRoot, `.rollback-cleanup-${selected}.json`);
      const recovering = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, recovering.exited);
      const cleanup = JSON.parse(await fs.readFile(cleanupRecord, "utf8"));
      const tombstone = path.join(fixture.deployRoot, cleanup.tombstone);
      await assert.rejects(fs.access(rollback));
      await fs.access(tombstone);
      if (point === "after_tombstone_unlink_run_daily.sh") {
        await assert.rejects(fs.access(path.join(tombstone, "run_daily.sh")));
        await fs.access(path.join(tombstone, "run_daily.sh.present"));
      }
      process.kill(-recovering.child.pid, "SIGKILL");
      assert.equal((await recovering.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      await assert.rejects(fs.access(rollback));
      await assert.rejects(fs.access(tombstone));
      await assert.rejects(fs.access(cleanupRecord));
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

const normalRollbackEntries = [
  ".stable-health-migration.json",
  ".stable-health-migration.json.present",
  "check_health.mjs",
  "check_health.mjs.present",
  "locked_exec.py",
  "locked_exec.py.present",
  "run_daily.sh",
  "run_daily.sh.present",
];

for (const entryName of normalRollbackEntries) {
  deploymentTest(`normal post-commit cleanup resumes after deleting ${entryName}`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `normal-delete-${entryName}-ready`);
    const never = path.join(fixture.root, `normal-delete-${entryName}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: `after_tombstone_unlink_${entryName}`,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
      const recordPath = path.join(fixture.deployRoot, `.rollback-cleanup-${selected}.json`);
      const cleanup = JSON.parse(await fs.readFile(recordPath, "utf8"));
      const tombstone = path.join(fixture.deployRoot, cleanup.tombstone);
      await assert.rejects(fs.access(path.join(tombstone, entryName)));
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      await assert.rejects(fs.access(tombstone));
      await assert.rejects(fs.access(recordPath));
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const point of [
  "after_cleanup_record_temp_create",
  "after_cleanup_record_temp_partial_write",
  "after_cleanup_record_file_fsync_before_replace",
  "after_cleanup_record_replace_before_root_fsync",
  "after_cleanup_record_root_fsync",
  "after_rollback_rename_before_root_fsync",
  "after_tombstone_rmdir_before_root_fsync",
  "after_cleanup_record_unlink_before_root_fsync",
]) {
  deploymentTest(`normal cleanup transaction resumes from ${point}`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `${point}-ready`);
    const never = path.join(fixture.root, `${point}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");
      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) =>
        name === `.rollback-${selected}` ||
        name.startsWith(`.rollback-cleanup-${selected}.json`) ||
        name.startsWith(`.rollback-tombstone-${selected}-`));
      assert.deepEqual(leftovers, []);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const point of [
  "after_detached_record_temp_create",
  "after_detached_record_temp_partial_write",
  "after_detached_record_file_fsync_before_replace",
  "after_detached_record_replace_before_root_fsync",
  "after_detached_record_root_fsync",
  "after_detached_rollback_rename_before_root_fsync",
  "after_detached_tombstone_rmdir_before_root_fsync",
  "after_detached_record_unlink_before_root_fsync",
]) {
  deploymentTest(`detached cleanup record publication survives SIGKILL at ${point}`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `${point}-ready`);
    const never = path.join(fixture.root, `${point}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) =>
        name.startsWith(".rollback-cleanup-detached-") ||
        name.startsWith(".rollback-tombstone-detached-") ||
        name.startsWith(".rollback-"));
      assert.deepEqual(leftovers, []);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("detached partial-record recovery keeps its release binding across a second SIGKILL", async () => {
  const fixture = await setupFixture();
  const firstReady = path.join(fixture.root, "detached-first-ready");
  const secondReady = path.join(fixture.root, "detached-second-ready");
  const never = path.join(fixture.root, "detached-never");
  try {
    const first = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_record_temp_partial_write",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: firstReady,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(firstReady, first.exited);
    process.kill(-first.child.pid, "SIGKILL");
    assert.equal((await first.exited).signal, "SIGKILL");

    const second = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_record_recovery_rewrite_before_file_fsync",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: secondReady,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(secondReady, second.exited);
    process.kill(-second.child.pid, "SIGKILL");
    assert.equal((await second.exited).signal, "SIGKILL");

    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 0, resumed.stderr);
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) =>
      name.startsWith(".rollback-cleanup-detached-") ||
      name.startsWith(".rollback-tombstone-detached-") ||
      name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("durable rollback authority recovers a kill before detached cleanup scratch creation", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "pre-scratch-authority-ready");
  const never = path.join(fixture.root, "pre-scratch-authority-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_PAUSE_POINT: "before_detached_cleanup_create",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    const evidence = await snapshotRollbackEvidence(fixture.deployRoot);
    const rollbackName = evidence.names.find((name) => /^\.rollback-[0-9]/.test(name));
    assert.ok(rollbackName);
    await fs.access(path.join(fixture.deployRoot, rollbackName, ".rollback-manifest.json"));
    assert.equal(evidence.names.some((name) => name.includes("rollback-cleanup-detached")), false);

    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 0, resumed.stderr);
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("partial rollback authority publication is fail-closed and byte-preserving", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "partial-authority-ready");
  const never = path.join(fixture.root, "partial-authority-never");
  try {
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_authority_temp_partial_write",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    const before = await snapshotRollbackEvidence(fixture.deployRoot);
    assert.equal(before.names.length, 1);
    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 70);
    assert.match(resumed.stderr, /unsealed detached rollback has no durable expected-current authority/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("rollback backup fsync failure preserves an unsealed journal before gate or live progress", async () => {
  const fixture = await setupFixture();
  try {
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const result = await run("bash", [deployScript], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_FAIL_ROLLBACK_FSYNC_NAME: "run_daily.sh" },
    });
    assert.equal(result.code, 70);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
    const evidence = await snapshotRollbackEvidence(fixture.deployRoot);
    const rollbackName = evidence.names.find((name) => /^\.rollback-[0-9]/.test(name));
    assert.ok(rollbackName);
    await assert.rejects(fs.access(path.join(fixture.deployRoot, rollbackName, ".rollback-manifest.json")));
    assert.equal(evidence.names.some((name) => name.includes("rollback-cleanup")), false);
    const releases = (await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort();
    assert.equal(releases.length, 2, "the immutable release remains with its unsealed rollback evidence");
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a fully durable rollback authority converges before the first live edit", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "durable-authority-ready");
  const never = path.join(fixture.root, "durable-authority-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_authority_root_fsync",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    const evidence = await snapshotRollbackEvidence(fixture.deployRoot);
    const rollbackName = evidence.names.find((name) => /^\.rollback-[0-9]/.test(name));
    assert.ok(rollbackName);
    await fs.access(path.join(fixture.deployRoot, rollbackName, ".rollback-manifest.json"));

    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 0, resumed.stderr);
    const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
    assert.deepEqual(leftovers, []);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const mutation of [
  {
    name: "backup content",
    apply: async (rollback) => { await fs.writeFile(path.join(rollback, "run_daily.sh"), "FORGED\n"); },
  },
  {
    name: "backup mode",
    apply: async (rollback) => { await fs.chmod(path.join(rollback, "check_health.mjs"), 0o600); },
  },
  {
    name: "presence sentinel",
    apply: async (rollback) => { await fs.writeFile(path.join(rollback, "run_daily.sh.present"), "FORGED\n"); },
  },
  {
    name: "authority schema",
    apply: async (rollback) => {
      const authorityPath = path.join(rollback, ".rollback-manifest.json");
      const authority = JSON.parse(await fs.readFile(authorityPath, "utf8"));
      authority.schema = true;
      await fs.writeFile(authorityPath, `${JSON.stringify(authority)}\n`, { mode: 0o600 });
      await fs.chmod(authorityPath, 0o600);
    },
  },
]) {
  deploymentTest(`post-seal ${mutation.name} mutation is rejected before gate or live writes`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `post-seal-${mutation.name.replaceAll(" ", "-")}-ready`);
    const proceed = path.join(fixture.root, `post-seal-${mutation.name.replaceAll(" ", "-")}-go`);
    try {
      const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
      const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
      const deploying = start("bash", [deployScript], {
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_authority_root_fsync",
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: proceed,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      const rollbackName = (await fs.readdir(fixture.deployRoot)).find((name) => /^\.rollback-[0-9]/.test(name));
      assert.ok(rollbackName);
      const rollback = path.join(fixture.deployRoot, rollbackName);
      await mutation.apply(rollback);
      const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
      const releasesBefore = (await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort();
      await fs.writeFile(proceed, "go\n");
      const result = await deploying.exited;
      assert.equal(result.code, 70);
      assert.doesNotMatch(result.stderr, /runtime is safe/i);
      await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
      assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
      assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
      assert.deepEqual((await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort(), releasesBefore);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("caught rollback rejects a post-live forged backup and preserves the active transaction", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "caught-forged-backup-ready");
  const never = path.join(fixture.root, "caught-forged-backup-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    const rollbackName = (await fs.readdir(fixture.deployRoot)).find((name) => /^\.rollback-[0-9]/.test(name));
    assert.ok(rollbackName);
    const rollback = path.join(fixture.deployRoot, rollbackName);
    await fs.writeFile(path.join(rollback, "run_daily.sh"), "FORGED\n");
    const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const releasesBefore = (await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort();
    const deploymentPid = Number.parseInt((await fs.readFile(ready, "utf8")).trim(), 10);
    assert.ok(Number.isSafeInteger(deploymentPid) && deploymentPid > 1);
    process.kill(deploymentPid, "SIGTERM");
    const result = await deploying.exited;
    assert.equal(result.code, 70);
    assert.doesNotMatch(result.stderr, /runtime is safe/i);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual((await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort(), releasesBefore);
    assert.equal(await fs.readFile(path.join(rollback, "run_daily.sh"), "utf8"), "FORGED\n");
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("failed gate publication preserves an external symlink and the complete transaction", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "unproven-gate-ready");
  const proceed = path.join(fixture.root, "unproven-gate-go");
  const externalGate = path.join(fixture.root, "external-gate");
  try {
    await fs.writeFile(externalGate, "external-do-not-delete\n");
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_PAUSE_POINT: "after_phase_lock",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: proceed,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    const gate = path.join(fixture.runtime, ".deployment-phase");
    await fs.symlink(externalGate, gate);
    const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
    const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const releasesBefore = (await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort();
    await fs.writeFile(proceed, "go\n");
    const result = await deploying.exited;
    assert.equal(result.code, 70);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
    assert.deepEqual((await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort(), releasesBefore);
    assert.equal(await fs.readlink(gate), externalGate);
    assert.equal(await fs.readFile(externalGate, "utf8"), "external-do-not-delete\n");
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a formal detached cleanup record rejects boolean schema without changing evidence", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "formal-boolean-schema-ready");
  const never = path.join(fixture.root, "formal-boolean-schema-never");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_detached_record_root_fsync",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    process.kill(-deploying.child.pid, "SIGKILL");
    assert.equal((await deploying.exited).signal, "SIGKILL");
    const recordName = (await fs.readdir(fixture.deployRoot)).find((name) =>
      /^\.rollback-cleanup-detached-.*\.json$/.test(name));
    assert.ok(recordName);
    const recordPath = path.join(fixture.deployRoot, recordName);
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    record.schema = true;
    await fs.writeFile(recordPath, `${JSON.stringify(record)}\n`);
    const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 70);
    assert.match(resumed.stderr, /detached cleanup record/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const mutation of [
  {
    name: "current absence",
    apply: async (fixture) => { await fs.unlink(path.join(fixture.deployRoot, "current")); },
    expected: null,
  },
  {
    name: "another valid current target",
    apply: async (fixture) => {
      await fs.mkdir(path.join(fixture.deployRoot, "releases", "later", "single-page-monitor"), { recursive: true });
      await atomicCurrent(fixture.deployRoot, "releases/later");
    },
    expected: "releases/later",
  },
]) {
  deploymentTest(`stable bound scratch rejects ${mutation.name} and preserves all cleanup evidence`, async () => {
    const fixture = await setupFixture();
    try {
      await crashDetachedCleanupScratch(fixture, `changed-current-${mutation.name.replaceAll(" ", "-")}`);
      await mutation.apply(fixture);
      const before = await snapshotRollbackEvidence(fixture.deployRoot);
      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 70);
      assert.match(resumed.stderr, /detached cleanup temporary expected current changed/);
      await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
      try {
        assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), mutation.expected);
      } catch (error) {
        if (mutation.expected !== null || error?.code !== "ENOENT") throw error;
      }
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("old unbound stable scratch fails closed and remains byte-identical", async () => {
  const fixture = await setupFixture();
  try {
    const scratch = await crashDetachedCleanupScratch(fixture, "old-unbound");
    const match = /^(.*\.json)\.tmp-bound-[a-f0-9]{64}-([a-f0-9]{32})$/.exec(scratch);
    assert.ok(match);
    const oldName = `${match[1]}.tmp-${match[2]}`;
    await fs.rename(path.join(fixture.deployRoot, scratch), path.join(fixture.deployRoot, oldName));
    const before = await snapshotRollbackEvidence(fixture.deployRoot);
    const resumed = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(resumed.code, 70);
    assert.match(resumed.stderr, /legacy detached cleanup temporary has no durable expected-current binding/);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const ambiguity of ["multiple bound", "bound plus legacy"]) {
  deploymentTest(`${ambiguity} detached scratches fail closed before any cleanup mutation`, async () => {
    const fixture = await setupFixture();
    try {
      const scratch = await crashDetachedCleanupScratch(fixture, ambiguity.replaceAll(" ", "-"));
      const match = /^(.*\.json)\.tmp-bound-([a-f0-9]{64})-[a-f0-9]{32}$/.exec(scratch);
      assert.ok(match);
      const nonce = "e".repeat(32);
      const extraName = ambiguity === "multiple bound"
        ? `${match[1]}.tmp-bound-${match[2]}-${nonce}`
        : `${match[1]}.tmp-${nonce}`;
      await fs.copyFile(path.join(fixture.deployRoot, scratch), path.join(fixture.deployRoot, extraName));
      await fs.chmod(path.join(fixture.deployRoot, extraName), 0o600);
      const before = await snapshotRollbackEvidence(fixture.deployRoot);
      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 70);
      assert.match(resumed.stderr, /multiple detached cleanup temporaries for one rollback/);
      await assertRollbackEvidenceUnchanged(fixture.deployRoot, before);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const point of [
  "after_precurrent_restore_run_daily.sh_fsync",
  "after_precurrent_restore_check_health.mjs_fsync",
  "after_precurrent_restore_locked_exec.py_fsync",
  "after_precurrent_restore_.stable-health-migration.json_fsync",
  "after_precurrent_restore_.precommit_check_health.mjs_fsync",
  "after_precurrent_restore_temp_fsync_check_health.mjs",
  "after_precurrent_gate_unlink_before_dir_fsync",
]) {
  deploymentTest(`sealed pre-current recovery converges after a second SIGKILL at ${point}`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `${point.replaceAll("/", "-")}-ready`);
    const never = path.join(fixture.root, `${point.replaceAll("/", "-")}-never`);
    try {
      await crashStablePrecurrentTransaction(fixture, point.replaceAll("/", "-"));
      const recovering = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, recovering.exited);
      process.kill(-recovering.child.pid, "SIGKILL");
      assert.equal((await recovering.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      const leftovers = (await fs.readdir(fixture.deployRoot)).filter((name) => name.startsWith(".rollback-"));
      assert.deepEqual(leftovers, []);
      const runtimeTemps = (await fs.readdir(fixture.runtime)).filter((name) => name.includes(".precurrent-"));
      assert.deepEqual(runtimeTemps, []);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

for (const point of [
  "after_caught_current_temp_create_before_root_fsync",
  "after_caught_current_temp_fsync",
  "after_caught_current_restore_fsync",
  "after_precurrent_restore_run_daily.sh_fsync",
  "after_precurrent_restore_check_health.mjs_fsync",
  "after_precurrent_restore_locked_exec.py_fsync",
  "after_precurrent_restore_.stable-health-migration.json_fsync",
  "after_precurrent_restore_.precommit_check_health.mjs_fsync",
  "after_precurrent_gate_unlink_before_dir_fsync",
]) {
  deploymentTest(`selected caught rollback resumes after SIGKILL at ${point} with no intent residue`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `caught-${point.replaceAll("/", "-")}-ready`);
    const never = path.join(fixture.root, `caught-${point.replaceAll("/", "-")}-never`);
    try {
      const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
      const currentBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_MARKER_FSYNC: "1",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: point,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");

      const recovered = await run("python3", [
        rollbackCleanupSource, "resume", fixture.deployRoot, fixture.runtime, "", "", testLegacyHealthCheckerSha,
      ], { env: fixture.env });
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), currentBefore);
      assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
      const protocolResidue = (await fs.readdir(fixture.deployRoot)).filter((name) =>
        name.startsWith(".rollback-") || name.startsWith(".current-precurrent-"));
      assert.deepEqual(protocolResidue, []);
      const runtimeTemps = (await fs.readdir(fixture.runtime)).filter((name) => name.includes(".precurrent-"));
      assert.deepEqual(runtimeTemps, []);
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("caught current intent replacement cannot redirect current after the creation pause", async () => {
  const fixture = await setupFixture();
  const ready = path.join(fixture.root, "caught-intent-swap-ready");
  const proceed = path.join(fixture.root, "caught-intent-swap-go");
  try {
    const deploying = start("bash", [deployScript], {
      detached: true,
      env: {
        ...fixture.env,
        SP_SINGLE_PAGE_TEST_FAIL_MARKER_FSYNC: "1",
        SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: "after_caught_current_temp_create_before_root_fsync",
        SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
        SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: proceed,
      },
    });
    await waitForWhileRunning(ready, deploying.exited);
    const selectedBefore = await fs.readlink(path.join(fixture.deployRoot, "current"));
    const runtimeBefore = await snapshotRuntimeProtocol(fixture.runtime);
    const attackerMonitor = path.join(fixture.deployRoot, "releases", "attacker", "single-page-monitor");
    await fs.mkdir(attackerMonitor, { recursive: true });
    await fs.writeFile(path.join(attackerMonitor, "run_daily.sh"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
    await fs.writeFile(path.join(attackerMonitor, "check_health.mjs"), "process.exit(0);\n", { mode: 0o755 });
    const intentName = (await fs.readdir(fixture.deployRoot)).find((name) => name.startsWith(".current-precurrent-"));
    assert.ok(intentName);
    const intent = path.join(fixture.deployRoot, intentName);
    await fs.unlink(intent);
    await fs.symlink("releases/attacker", intent);
    const evidenceBefore = await snapshotRollbackEvidence(fixture.deployRoot);
    const releasesBefore = (await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort();
    await fs.writeFile(proceed, "go\n");
    const result = await deploying.exited;
    assert.equal(result.code, 70);
    assert.equal(await fs.readlink(path.join(fixture.deployRoot, "current")), selectedBefore);
    assert.deepEqual(await snapshotRuntimeProtocol(fixture.runtime), runtimeBefore);
    await assertRollbackEvidenceUnchanged(fixture.deployRoot, evidenceBefore);
    assert.equal(await fs.readlink(intent), "releases/attacker");
    assert.deepEqual((await fs.readdir(path.join(fixture.deployRoot, "releases"))).sort(), releasesBefore);
  } finally {
    await removeFixture(fixture.root);
  }
});

for (const entryName of normalRollbackEntries) {
  deploymentTest(`failed deployment rollback cleanup resumes after deleting ${entryName}`, async () => {
    const fixture = await setupFixture();
    const ready = path.join(fixture.root, `failed-delete-${entryName}-ready`);
    const never = path.join(fixture.root, `failed-delete-${entryName}-never`);
    try {
      const deploying = start("bash", [deployScript], {
        detached: true,
        env: {
          ...fixture.env,
          SP_SINGLE_PAGE_TEST_FAIL_POINT: "after_health_wrapper",
          SP_SINGLE_PAGE_TEST_RECOVERY_PAUSE_POINT: `after_detached_tombstone_unlink_${entryName}`,
          SP_SINGLE_PAGE_TEST_PAUSE_READY_FILE: ready,
          SP_SINGLE_PAGE_TEST_PAUSE_CONTINUE_FILE: never,
        },
      });
      await waitForWhileRunning(ready, deploying.exited);
      const names = await fs.readdir(fixture.deployRoot);
      const recordName = names.find((name) => /^\.rollback-cleanup-detached-.*\.json$/.test(name));
      assert.ok(recordName, "detached cleanup record is durable before physical deletion");
      const recordPath = path.join(fixture.deployRoot, recordName);
      const cleanup = JSON.parse(await fs.readFile(recordPath, "utf8"));
      const tombstone = path.join(fixture.deployRoot, cleanup.tombstone);
      await assert.rejects(fs.access(path.join(tombstone, entryName)));
      process.kill(-deploying.child.pid, "SIGKILL");
      assert.equal((await deploying.exited).signal, "SIGKILL");

      const resumed = await run("bash", [deployScript], { env: fixture.env });
      assert.equal(resumed.code, 0, resumed.stderr);
      await assert.rejects(fs.access(tombstone));
      await assert.rejects(fs.access(recordPath));
    } finally {
      await removeFixture(fixture.root);
    }
  });
}

deploymentTest("a forged selected-release rollback journal is never deleted or used for cleanup", async () => {
  const fixture = await setupFixture();
  try {
    const seeded = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(seeded.code, 0, seeded.stderr);
    const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
    const rollback = path.join(fixture.deployRoot, `.rollback-${selected}`);
    await fs.mkdir(rollback);
    for (const name of ["run_daily.sh", "check_health.mjs", "locked_exec.py"]) {
      await fs.copyFile(path.join(fixture.runtime, name), path.join(rollback, name));
      await fs.writeFile(path.join(rollback, `${name}.present`), "");
    }
    const forged = {
      schema: 2,
      kind: "spspy-single-page-stable-health-migration",
      wrapper_id: "spspy-single-page-stable-health",
      wrapper_version: 1,
      wrapper_sha256: "0".repeat(64),
    };
    await fs.writeFile(path.join(rollback, ".stable-health-migration.json"), `${JSON.stringify(forged)}\n`);
    await fs.writeFile(path.join(rollback, ".stable-health-migration.json.present"), "");
    const before = await digestTree(rollback);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /rollback marker does not bind the prior health wrapper/);
    assert.equal(await digestTree(rollback), before);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("a tombstone without its exact durable cleanup record is never deleted", async () => {
  const fixture = await setupFixture();
  try {
    const seeded = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(seeded.code, 0, seeded.stderr);
    const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
    const tombstone = path.join(fixture.deployRoot, `.rollback-tombstone-${selected}-${"a".repeat(32)}`);
    await fs.mkdir(tombstone);
    await fs.writeFile(path.join(tombstone, "do-not-delete"), "forged tombstone\n");
    const before = await digestTree(tombstone);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(await digestTree(tombstone), before);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("an unsafe uncommitted cleanup temporary fails closed and is never removed", async () => {
  const fixture = await setupFixture();
  try {
    const seeded = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(seeded.code, 0, seeded.stderr);
    const selected = (await fs.readlink(path.join(fixture.deployRoot, "current"))).split("/").at(-1);
    const temporary = path.join(
      fixture.deployRoot,
      `.rollback-cleanup-${selected}.json.tmp-${"b".repeat(32)}`,
    );
    await fs.symlink("/tmp", temporary);
    const result = await run("bash", [deployScript], { env: fixture.env });
    assert.equal(result.code, 70);
    assert.match(result.stderr, /unsafe uncommitted rollback cleanup temporary/);
    assert.equal(await fs.readlink(temporary), "/tmp");
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("source sync_deploy is mode 0755 and can be invoked directly", async () => {
  const fixture = await setupFixture();
  try {
    const mode = (await fs.stat(deployScript)).mode & 0o777;
    assert.equal(mode, 0o755);
    const result = await run(deployScript, [], {
      env: { ...fixture.env, SP_SINGLE_PAGE_TEST_EXIT_AFTER_LOCK: "1" },
    });
    assert.equal(result.code, 96);
  } finally {
    await removeFixture(fixture.root);
  }
});

deploymentTest("the real readonly daily runner writes only external runtime and pages paths", async () => {
  const fixture = await setupFixture();
  const releaseMonitor = path.join(fixture.deployRoot, "releases", "readonly", "single-page-monitor");
  const fakeNode = path.join(fixture.bin, "daily-node");
  const fakeGit = path.join(fixture.bin, "git");
  try {
    await fs.mkdir(path.join(releaseMonitor, "scripts"), { recursive: true });
    await fs.copyFile(path.join(monitorDir, "run_daily.sh"), path.join(releaseMonitor, "run_daily.sh"));
    await fs.copyFile(lockHelperSource, path.join(releaseMonitor, "scripts", "locked_exec.py"));
    await fs.writeFile(path.join(releaseMonitor, "check_health.mjs"), "process.exit(0);\n");
    await fs.chmod(path.join(releaseMonitor, "run_daily.sh"), 0o755);
    await fs.writeFile(fakeNode, `#!/usr/bin/env bash
set -euo pipefail
target="\${1:-}"; shift || true
if [[ "\${target}" == *build_dashboard.mjs ]]; then
  out="\${SP_SINGLE_PAGE_MONTH:-2026-08}"
  while (( $# )); do
    if [[ "$1" == "--month" || "$1" == "--out" ]]; then out="$2"; shift 2; else shift; fi
  done
  mkdir -p "\${SP_SINGLE_PAGE_REPORTS_DIR}/\${out}"
  printf '<html>ok</html>\\n' > "\${SP_SINGLE_PAGE_REPORTS_DIR}/\${out}/dashboard.html"
  printf '{}\\n' > "\${SP_SINGLE_PAGE_REPORTS_DIR}/\${out}/dashboard_data.json"
fi
exit 0
`, { mode: 0o755 });
    await fs.writeFile(fakeGit, "#!/usr/bin/env bash\nif [[ \"$*\" == *'diff --cached --quiet'* ]]; then exit 0; fi\nexit 0\n", { mode: 0o755 });
    const pages = path.join(fixture.deployRoot, ".pages", "babata-board-pages-main");
    await fs.mkdir(path.join(pages, ".git"), { recursive: true });
    await atomicCurrent(fixture.deployRoot, "releases/readonly");
    await run("chmod", ["-R", "a-w", path.join(fixture.deployRoot, "releases", "readonly")]);
    const before = await digestTree(path.join(fixture.deployRoot, "releases", "readonly"));
    const result = await run(path.join(fixture.runtime, "run_daily.sh"), [], {
      env: {
        ...fixture.env,
        PATH: `${fixture.bin}:${process.env.PATH}`,
        NODE_BIN: fakeNode,
        SP_SINGLE_PAGE_MONTH: "2026-08",
        SP_SINGLE_PAGE_PREV_MONTH: "2026-07",
        SP_SINGLE_PAGE_INCLUDE_PREV: "0",
        SP_SINGLE_PAGE_SEND_DINGTALK: "0",
        SP_SINGLE_PAGE_HEARTBEAT_INTERVAL: "0.01",
      },
    });
    assert.equal(result.code, 0);
    assert.equal(await digestTree(path.join(fixture.deployRoot, "releases", "readonly")), before);
    await fs.access(path.join(fixture.runtime, "data", "run_status.json"));
    await fs.access(path.join(fixture.runtime, "reports", "latest", "dashboard.html"));
    await fs.access(path.join(pages, "single-page-monitor", "latest.html"));
  } finally {
    await removeFixture(fixture.root);
  }
});
