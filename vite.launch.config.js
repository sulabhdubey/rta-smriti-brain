import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

function assertInside(root, candidate, label) {
  const rel = relative(root, candidate);
  if (rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))) return;
  throw new Error(`${label} escaped its approved root`);
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

export function copyPublicTreeSafely(sourceRoot, destinationRoot) {
  const source = resolve(sourceRoot);
  const destination = resolve(destinationRoot);
  const sourceMetadata = lstatSync(source);
  if (sourceMetadata.isSymbolicLink() || !sourceMetadata.isDirectory()) {
    throw new Error("linked public asset root is forbidden");
  }
  const canonicalSource = realpathSync(source);
  const pending = [source];

  while (pending.length) {
    const directory = pending.pop();
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const input = resolve(directory, entry.name);
      assertInside(source, input, "public asset");
      const rel = relative(source, input);
      const output = resolve(destination, rel);
      assertInside(destination, output, "public destination");
      const before = lstatSync(input);
      if (before.isSymbolicLink()) throw new Error(`linked public asset is forbidden: ${rel}`);
      if (before.isDirectory()) {
        mkdirSync(output, { recursive: true });
        pending.push(input);
        continue;
      }
      if (!before.isFile()) throw new Error(`special public asset is forbidden: ${rel}`);

      let descriptor;
      try {
        descriptor = openSync(input, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        const opened = fstatSync(descriptor);
        const canonicalInput = realpathSync(input);
        assertInside(canonicalSource, canonicalInput, "public asset");
        if (!sameFile(before, opened)) throw new Error(`public asset changed before read: ${rel}`);
        const data = readFileSync(descriptor);
        const afterRead = fstatSync(descriptor);
        const afterPath = lstatSync(input);
        if (
          !sameFile(opened, afterRead)
          || !sameFile(opened, afterPath)
          || opened.size !== afterRead.size
          || opened.mtimeMs !== afterRead.mtimeMs
        ) {
          throw new Error(`public asset changed during read: ${rel}`);
        }
        mkdirSync(dirname(output), { recursive: true });
        writeFileSync(output, data, { flag: "wx" });
      } finally {
        if (descriptor !== undefined) closeSync(descriptor);
      }
    }
  }
}

function safePublicAssets() {
  return {
    name: "rta-smriti-safe-public-assets",
    closeBundle() {
      copyPublicTreeSafely(resolve("launch-site", "public"), resolve("launch-dist"));
    },
  };
}

export default defineConfig({
  root: "launch-site",
  base: "./",
  publicDir: false,
  plugins: [react(), safePublicAssets()],
  build: {
    outDir: "../launch-dist",
    emptyOutDir: true,
  },
});
