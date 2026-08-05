import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { atomicWriteFile } from "../lib/file_utils.mjs";

test("atomicWriteFile replaces content without leaving temp files", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "sp-single-page-test-"));
  const file = path.join(dir, "state.json");
  try {
    await atomicWriteFile(file, '{"version":1}\n');
    await atomicWriteFile(file, '{"version":2}\n');
    assert.equal(await fs.readFile(file, "utf8"), '{"version":2}\n');
    assert.deepEqual(await fs.readdir(dir), ["state.json"]);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
