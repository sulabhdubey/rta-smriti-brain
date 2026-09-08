import { chromium } from "@playwright/test";
import { spawn } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function startFixtureServer(tempRoot) {
  const python = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
  const child = spawn(python, [path.join(root, "scripts", "operator_qa_server.py"), tempRoot], {
    cwd: root,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const ready = new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => reject(new Error(`operator fixture timed out: ${stderr}`)), 30_000);
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      const line = stdout.split(/\r?\n/).find((value) => value.trim().startsWith("{"));
      if (!line) return;
      clearTimeout(timer);
      try { resolve(JSON.parse(line)); } catch (error) { reject(error); }
    });
    child.once("exit", (code) => {
      if (code && !stdout.includes("\"url\"")) {
        clearTimeout(timer);
        reject(new Error(`operator fixture exited ${code}: ${stderr}`));
      }
    });
  });
  return { child, ready };
}

async function stopFixtureServer(child) {
  if (child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

function configuredFederation() {
  return {
    schema: "rta-smriti.federation-inventory/v1",
    mutations_enabled: true,
    status: {
      state: "healthy",
      operationally_ready: true,
      space_count: 1,
      scope_count: 1,
      peer_count: 2,
      axes: {
        federation: "healthy",
        governance: "healthy",
        encryption: "healthy",
        projection: "healthy",
        sync: "idle",
        relay: "not_configured",
      },
      prior_plaintext_revocation_limit: true,
      guidance: "Configure and probe a relay separately; local health does not prove relay reachability.",
    },
    spaces: [{ space_id: "a".repeat(64), owner_peer_id: "b".repeat(64), created_at: "2026-09-07T00:00:00Z" }],
    scopes: [{ space_id: "a".repeat(64), scope_id: "c".repeat(64), scope_kind: "team", label: "Release reviewers", current_epoch: 2 }],
    peers: [
      { space_id: "a".repeat(64), peer_id: "b".repeat(64), label: "Owner device" },
      { space_id: "a".repeat(64), peer_id: "d".repeat(64), label: "Reviewer device" },
    ],
    quarantine: [{ quarantine_id: 7, claimed_event_id: "e".repeat(64), reason_code: "peer_revoked", encoded_bytes: 812 }],
    counts: { encrypted_events: 12, quarantined: 1, quarantine_pending: 1 },
    managed_sync: {
      status: "attention_required",
      state: "configured",
      sync_state: "offline",
      cycles: 3,
      successful_cycles: 2,
      consecutive_failures: 1,
      last_success_at: "2026-09-07T00:00:00Z",
      local_event_count: 12,
      relay_event_count: 10,
    },
  };
}

const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-federation-capture-"));
const outputDir = path.join(root, "launch-assets", "screenshots");
const siteAssetDir = path.join(root, "launch-site", "public", "assets");
const output = path.join(outputDir, "governed-federation-v1.1b.png");
const siteOutput = path.join(siteAssetDir, "governed-federation-v1.1b.png");
const { child, ready } = startFixtureServer(tempRoot);
let browser;

try {
  const fixture = await ready;
  await mkdir(outputDir, { recursive: true });
  await mkdir(siteAssetDir, { recursive: true });
  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) errors.push(`${message.type()}: ${message.text()}`);
  });
  await page.route(/\/api\/federation(?:\?|$)/, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(configuredFederation()),
  }));
  await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
  await page.getByText("operator-demo", { exact: true }).first().waitFor();
  await page.getByText(/^Brain Path /).evaluate((element) => {
    element.textContent = "Brain Path %USERPROFILE%\\Documents\\Rta-Smriti\\brains";
  });
  await page.getByRole("navigation", { name: "Operator console navigation" })
    .getByRole("button", { name: /^Federation/ }).click();
  await page.getByRole("heading", { name: "Team Brain Control Plane" }).waitFor();
  await page.waitForFunction(() => document.fonts.status === "loaded");
  await page.screenshot({ path: output, animations: "disabled" });
  await copyFile(output, siteOutput);
  if (errors.length) throw new Error(`capture emitted errors:\n${errors.join("\n")}`);
  process.stdout.write(`Captured ${path.relative(root, output)} and launch-site copy\n`);
} finally {
  await browser?.close();
  await stopFixtureServer(child);
  await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
