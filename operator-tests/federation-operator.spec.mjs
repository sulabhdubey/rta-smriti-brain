import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function startFixtureServer(tempRoot) {
  const python = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
  mkdirSync(path.join(tempRoot, ".codex", "sessions"), { recursive: true });
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

function configuredFederation(overrides = {}) {
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
    ...overrides,
  };
}

async function openFederation(page, fixtureUrl) {
  await page.goto(fixtureUrl, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("operator-demo", { exact: true }).first()).toBeVisible();
  await page.getByRole("navigation", { name: "Operator console navigation" })
    .getByRole("button", { name: /^Federation/ }).click();
  await expect(page.getByRole("heading", { name: "Team Brain Control Plane" })).toBeVisible();
}

test("federation recovery is preview-bound, accessible, and explicit", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-federation-operator-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  const actions = [];
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/federation(?:\?|$)/, async (route) => {
      if (route.request().method() === "GET") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(configuredFederation()) });
      }
      const payload = route.request().postDataJSON();
      actions.push(payload);
      if (payload.action === "plan") {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            state: "preview",
            action: payload.operation,
            parameters: payload.parameters,
            confirmation_digest: "f".repeat(64),
            warnings: [],
          }),
        });
      }
      if (payload.action === "sync-plan") {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            state: "preview",
            action: payload.operation,
            confirmation_digest: "a".repeat(64),
            warnings: [],
          }),
        });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "applied" }) });
    });
    await openFederation(page, fixture.url);

    await expect(page.getByText("Revocation protects future key epochs", { exact: false })).toBeVisible();
    const managedSync = page.getByRole("region", { name: "Managed federation sync" });
    await expect(managedSync).toContainText("Offline");
    await expect(managedSync).toContainText("Last successful sync");
    await managedSync.getByRole("button", { name: "Preview start" }).click();
    await expect(managedSync.getByRole("region", { name: "Managed sync change preview" })).toBeVisible();
    await managedSync.getByRole("button", { name: "Confirm start" }).click();
    expect(actions[0]).toEqual(expect.objectContaining({ action: "sync-plan", operation: "start" }));
    expect(actions[1]).toEqual(expect.objectContaining({
      action: "sync-apply",
      operation: "start",
      confirmation_digest: "a".repeat(64),
    }));
    const actionCenter = page.getByRole("region", { name: "Federation action center" });
    await actionCenter.getByRole("combobox").first().selectOption("quarantine-promote");
    await page.getByLabel("Decision reason", { exact: true }).fill("Revalidated after explicit device readmission");
    await page.getByRole("button", { name: "Preview change" }).click();
    await expect(page.getByRole("region", { name: "Federation change preview" })).toContainText("quarantine promote");
    expect(actions).toHaveLength(3);
    expect(actions[2].parameters).toEqual({
      quarantine_id: 7,
      reason: "Revalidated after explicit device readmission",
    });
    await page.getByRole("button", { name: "Confirm" }).click();
    await expect.poll(() => actions.length).toBe(4);
    expect(actions[3].confirmation_digest).toBe("f".repeat(64));
    await expect(managedSync.getByRole("button", { name: "Preview start" })).toBeEnabled();

    const accessibility = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(
      accessibility.violations.map((item) => item.id),
      JSON.stringify(accessibility.violations, null, 2),
    ).toEqual([]);
  } finally {
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("federation stays local-only and read-only on a narrow viewport", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-federation-mobile-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await context.newPage();
    await page.route(/\/api\/federation(?:\?|$)/, (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...configuredFederation({ mutations_enabled: false, spaces: [], scopes: [], peers: [], quarantine: [] }),
        status: {
          state: "not_configured",
          operationally_ready: false,
          space_count: 0,
          scope_count: 0,
          peer_count: 0,
          axes: Object.fromEntries(["federation", "governance", "encryption", "projection", "sync", "relay"].map((key) => [key, "not_configured"])),
          guidance: "Create a federation space only when selective team sharing is needed.",
        },
        counts: { encrypted_events: 0, quarantined: 0 },
        managed_sync: { status: "ok", state: "not_configured" },
      }),
    }));
    await openFederation(page, fixture.url);

    await expect(page.getByText("Local-only brain", { exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Managed federation sync" })).toContainText("Not configured");
    await expect(page.getByText("Changes are locked until the console starts with a private local identity.", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Preview change" })).toBeDisabled();
    const overflow = await page.evaluate(() => ({ width: document.documentElement.scrollWidth, viewport: window.innerWidth }));
    expect(overflow.width).toBeLessThanOrEqual(overflow.viewport + 1);
  } finally {
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
