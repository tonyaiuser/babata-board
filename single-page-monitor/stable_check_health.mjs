#!/usr/bin/env node
// Stable health entrypoint.  Resolve `current` once and spawn only the pinned
// absolute release, so an atomic switch cannot mix code generations.
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const STABLE_WRAPPER_ID = "spspy-single-page-stable-health";
const STABLE_WRAPPER_VERSION = 2;
const MIGRATION_MARKER_KIND = "spspy-single-page-stable-health-migration";
const PHASE_GATE_KIND = "spspy-single-page-deployment-phase";

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function validSha(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function readJsonRegular(file, label) {
  const status = fs.lstatSync(file);
  if (!status.isFile() || status.isSymbolicLink()) fail(`${label} is unsafe: ${file}`);
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${label} is invalid JSON: ${error.message}`);
  }
}

function validMigrationMarker(payload) {
  return payload?.schema === 2 &&
    payload?.kind === MIGRATION_MARKER_KIND &&
    payload?.wrapper_id === STABLE_WRAPPER_ID &&
    payload?.wrapper_version === STABLE_WRAPPER_VERSION &&
    payload?.wrapper_sha256 === stableWrapperSha;
}

function fail(message) {
  console.error(message);
  process.exit(70);
}

const stableDir = fs.realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const stableWrapperPath = fileURLToPath(import.meta.url);
const stableWrapperSha = sha256(fs.readFileSync(stableWrapperPath));
const deployRoot = path.dirname(stableDir);
const releasesDir = path.join(deployRoot, "releases");
const current = path.join(deployRoot, "current");
let releasesStatus;
try {
  releasesStatus = fs.lstatSync(releasesDir);
} catch (error) {
  fail(`releases directory is missing: ${error.message}`);
}
if (!releasesStatus.isDirectory() || releasesStatus.isSymbolicLink()) fail(`releases must be a real directory: ${releasesDir}`);
let raw;
let currentMissing = false;
try {
  if (!fs.lstatSync(current).isSymbolicLink()) fail(`current must be a symlink: ${current}`);
  raw = fs.readlinkSync(current);
} catch (error) {
  if (error?.code === "ENOENT") currentMissing = true;
  else fail(`No validated single-page-monitor release is active: ${error.message}`);
}
let pinnedChecker;
if (currentMissing) {
  // During first migration the new stable wrapper is installed before the
  // final current commit.  A durable copy of the old health checker remains
  // available for this bounded window; invalid current values never fallback.
  const fallback = path.join(stableDir, ".precommit_check_health.mjs");
  const gate = path.join(stableDir, ".deployment-phase");
  const migrationMarker = path.join(stableDir, ".stable-health-migration.json");
  try {
    const marker = readJsonRegular(migrationMarker, "stable migration marker");
    if (!validMigrationMarker(marker)) fail(`stable migration marker has an unsupported schema: ${migrationMarker}`);
    fail("A migrated runtime has no current release; legacy health fallback is disabled");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  let phase;
  try {
    phase = readJsonRegular(gate, "deployment phase gate");
  } catch (error) {
    fail(`No active deployment phase permits health fallback: ${error.message}`);
  }
  const phaseKeys = ["fallback_sha256", "kind", "mode", "release_id", "schema", "wrapper_id", "wrapper_sha256", "wrapper_version"];
  if (!phase || Object.keys(phase).sort().join(",") !== phaseKeys.join(",") ||
      phase?.schema !== 1 || phase?.kind !== PHASE_GATE_KIND ||
      phase?.mode !== "legacy_fallback" || phase?.wrapper_id !== STABLE_WRAPPER_ID ||
      phase?.wrapper_version !== STABLE_WRAPPER_VERSION ||
      !validSha(phase?.wrapper_sha256) || !validSha(phase?.fallback_sha256) ||
      phase.wrapper_sha256 !== stableWrapperSha) {
    fail("Deployment phase does not authorize a legacy health fallback");
  }
  const phaseProbe = spawnSync(
    process.env.PYTHON_BIN || "python3",
    [
      "-c",
      `import errno,fcntl,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]); s=p.lstat()
if not stat.S_ISDIR(s.st_mode) or p.is_symlink(): raise SystemExit(70)
fd=os.open(str(p), os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
f=os.fstat(fd)
if (f.st_dev,f.st_ino)!=(s.st_dev,s.st_ino): raise SystemExit(70)
try:
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except OSError as e:
 raise SystemExit(75 if e.errno in (errno.EACCES,errno.EAGAIN) else 70)
raise SystemExit(0)`,
      stableDir,
    ],
    { stdio: "ignore" },
  );
  if (phaseProbe.error || phaseProbe.status !== 75) {
    fail("No live deployment phase lock permits health fallback");
  }
  let fallbackStatus;
  try {
    fallbackStatus = fs.lstatSync(fallback);
  } catch (error) {
    fail(`No validated release or precommit health checker is active: ${error.message}`);
  }
  if (!fallbackStatus.isFile() || fallbackStatus.isSymbolicLink()) fail(`precommit health checker is unsafe: ${fallback}`);
  pinnedChecker = fs.realpathSync(fallback);
  if (path.dirname(pinnedChecker) !== stableDir) fail("precommit health checker resolves outside stable runtime");
  const fallbackBytes = fs.readFileSync(pinnedChecker);
  if (sha256(fallbackBytes) !== phase.fallback_sha256 || fallbackBytes.includes(Buffer.from(STABLE_WRAPPER_ID))) {
    fail("precommit health checker does not match the authorized legacy implementation");
  }
} else {
  const parts = raw.split("/");
  if (path.isAbsolute(raw) || parts.length !== 2 || parts[0] !== "releases" || !parts[1] || [".", ".."].includes(parts[1])) {
    fail(`unsafe current target: ${raw}`);
  }
  const release = path.join(releasesDir, parts[1]);
  let releaseStatus;
  try {
    releaseStatus = fs.lstatSync(release);
  } catch (error) {
    fail(`current release is missing: ${error.message}`);
  }
  if (!releaseStatus.isDirectory() || releaseStatus.isSymbolicLink()) fail(`current release is not a real directory: ${release}`);
  const releaseReal = fs.realpathSync(release);
  if (path.dirname(releaseReal) !== fs.realpathSync(releasesDir)) fail("current release resolves outside releases");
  const monitor = path.join(release, "single-page-monitor");
  let monitorStatus;
  try {
    monitorStatus = fs.lstatSync(monitor);
  } catch (error) {
    fail(`release monitor path is missing: ${error.message}`);
  }
  if (!monitorStatus.isDirectory() || monitorStatus.isSymbolicLink()) fail(`release monitor path is unsafe: ${monitor}`);
  const monitorReal = fs.realpathSync(monitor);
  if (path.dirname(monitorReal) !== releaseReal) fail("release monitor resolves outside selected release");
  const checker = path.join(monitor, "check_health.mjs");
  let checkerStatus;
  try {
    checkerStatus = fs.lstatSync(checker);
  } catch (error) {
    fail(`pinned health checker is missing: ${error.message}`);
  }
  if (!checkerStatus.isFile() || checkerStatus.isSymbolicLink()) fail(`pinned health checker is unsafe: ${checker}`);
  pinnedChecker = fs.realpathSync(checker);
  if (path.dirname(pinnedChecker) !== monitorReal || !pinnedChecker.startsWith(`${releaseReal}${path.sep}`)) {
    fail("pinned health checker resolves outside selected release");
  }
}

const result = spawnSync(process.execPath, [pinnedChecker, ...process.argv.slice(2)], {
  cwd: path.dirname(pinnedChecker),
  env: {
    ...process.env,
    SP_SINGLE_PAGE_DATA_DIR: process.env.SP_SINGLE_PAGE_DATA_DIR || path.join(stableDir, "data"),
    SP_SINGLE_PAGE_REPORTS_DIR: process.env.SP_SINGLE_PAGE_REPORTS_DIR || path.join(stableDir, "reports"),
    SP_SINGLE_PAGE_PAGES_DIR:
      process.env.SP_SINGLE_PAGE_PAGES_DIR || path.join(deployRoot, ".pages", "babata-board-pages-main"),
  },
  stdio: "inherit",
});
if (result.error) fail(result.error.message);
process.exit(result.status === null ? 70 : result.status);
