import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

export async function atomicWriteFile(file, data, encoding = "utf8") {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const temp = path.join(
    path.dirname(file),
    `.${path.basename(file)}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString("hex")}.tmp`
  );
  try {
    await fs.writeFile(temp, data, encoding);
    await fs.rename(temp, file);
  } catch (error) {
    await fs.rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}
