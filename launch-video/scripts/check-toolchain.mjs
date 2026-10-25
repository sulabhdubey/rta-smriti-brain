import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bundle } from "@remotion/bundler";

const require = createRequire(import.meta.url);
const videoRoot = fileURLToPath(new URL("../", import.meta.url));
const zodPath = require.resolve("zod");

// Check resolution from the actual consumers, not only from this script.
for (const consumer of ["@remotion/studio", "@remotion/studio-server"]) {
  const consumerRequire = createRequire(require.resolve(consumer));
  assert.equal(consumerRequire.resolve("zod"), zodPath);
  const { z } = consumerRequire("zod");
  let visited = 0;
  const schema = z.array(z.string().transform((value) => {
    visited += 1;
    return value;
  })).max(2);
  assert.deepEqual(schema.parse(["valid"]), ["valid"]);
  visited = 0;
  const oversized = schema.safeParse(Array(32).fill("bounded-test"));
  assert.equal(oversized.success, false);
  assert.equal(visited, 0);
  assert.equal(oversized.error.issues.length, 1);
  assert.equal(oversized.error.issues[0].code, "too_big");
}

const temporaryRoot = resolve(tmpdir());
const scratch = await mkdtemp(join(temporaryRoot, "rta-smriti-video-check-"));
try {
  const output = await bundle({
    entryPoint: join(videoRoot, "src", "index.jsx"),
    rootDir: videoRoot,
    outDir: join(scratch, "bundle"),
    enableCaching: false,
    askAIEnabled: false,
    gitSource: null,
    webpackOverride: (config) => ({
      ...config,
      parallelism: 1,
      optimization: { ...config.optimization, minimize: false },
    }),
  });
  const html = await readFile(join(output, "index.html"), "utf8");
  assert.match(html, /<html/i);
  assert.ok((await stat(join(output, "bundle.js"))).size > 0);
  console.log("Video toolchain passed: consumer resolution, bounded Zod validation, demo bundle.");
} finally {
  assert.equal(dirname(scratch), temporaryRoot);
  await rm(scratch, { recursive: true, force: true });
}
