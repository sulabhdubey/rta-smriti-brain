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

function lifecycleSnapshot(overrides = {}) {
  return {
    status: "attention_required",
    enrollment_state: "configured",
    reason_codes: ["capture_state_mismatch"],
    desired_state: {
      watcher: true,
      capture: true,
      continuity: true,
      console: true,
      login_restoration: false,
      mcp_hosts: ["codex", "zed"],
      schema_policy: "current-only",
    },
    desired_state_digest: "d".repeat(64),
    observed_state_digest: "o".repeat(64),
    services: {
      watcher: "running",
      capture: "stopped",
      continuity: "running",
      console: "current",
      login_restoration: "disabled",
    },
    health_axes: {
      database_health: { state: "healthy", schema_state: "current", schema_version: 11 },
      project_integrity: { state: "healthy" },
      capture_health: { state: "degraded" },
      continuation_health: { state: "healthy" },
      mcp_health: {
        state: "configuration_pending",
        fresh_session_proof: "pending",
        configured_host_count: 2,
        verified_host_count: 1,
        pending_hosts: ["zed"],
      },
      federation_health: { state: "not_configured" },
    },
    ...overrides,
  };
}

function lifecyclePlan(action) {
  const operation = action === "repair" ? "start_capture" : action === "setup" ? "start_watcher" : "stop_capture";
  return {
    status: "ok",
    read_only: true,
    blocked: false,
    blockers: [],
    plan_digest: `${action[0]}`.repeat(64),
    observed_state_digest: "o".repeat(64),
    desired_state: lifecycleSnapshot().desired_state,
    steps: [{ operation, reversible: true }],
  };
}

async function openSettings(page, fixtureUrl) {
  await page.goto(fixtureUrl, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("operator-demo", { exact: true }).first()).toBeVisible();
  await page.getByRole("navigation", { name: "Operator console navigation" })
    .getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByText("System lifecycle", { exact: true })).toBeVisible();
}

async function expectNoAxeViolations(page, label) {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(result.violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target),
  })), `${label} has WCAG violations`).toEqual([]);
}

test("lifecycle changes require a detailed digest-bound preview and can be cancelled", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-lifecycle-preview-"));
  const { child, ready } = startFixtureServer(tempRoot);
  const actions = [];
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/lifecycle(?:\?|$)/, async (route) => {
      const request = route.request();
      if (request.method() === "GET") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecycleSnapshot()) });
      }
      const payload = request.postDataJSON();
      actions.push(payload.action);
      if (payload.action === "plan") {
        const planKind = payload.desired_state?.capture === false ? "stop" : "repair";
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecyclePlan(planKind)) });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ status: "ok", state: payload.action === "remove" ? "removed" : "complete" }) });
    });
    await openSettings(page, fixture.url);

    await page.getByRole("button", { name: "Repair", exact: true }).click();
    await expect(page.getByRole("region", { name: "Repair lifecycle preview" })).toBeVisible();
    await expect(page.getByText("Precondition", { exact: true })).toBeVisible();
    await expect(page.getByText("Effect", { exact: true })).toBeVisible();
    await expect(page.getByText("Reversible", { exact: true })).toBeVisible();
    await expect(page.getByText("Backup", { exact: true })).toBeVisible();
    await expect(page.getByText("Verification", { exact: true })).toBeVisible();
    await expect(page.getByText("r".repeat(64), { exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "MCP host proof status" })).toContainText("2 configured / 1 verified");
    await expect(page.getByRole("region", { name: "MCP host proof status" })).toContainText("Pending: zed");
    await expect(page.getByRole("region", { name: "Lifecycle review bundle" })).toContainText("Non-authoritative local JSON");
    await expect(page.getByRole("button", { name: "Copy review command", exact: true })).toBeEnabled();
    await expectNoAxeViolations(page, "repair preview");
    expect(actions).toEqual(["plan"]);

    await page.getByRole("button", { name: "Cancel lifecycle preview", exact: true }).click();
    await expect(page.getByRole("region", { name: "Repair lifecycle preview" })).toHaveCount(0);
    expect(actions).toEqual(["plan"]);

    await page.getByRole("button", { name: "Repair", exact: true }).click();
    await page.getByRole("button", { name: "Confirm repair", exact: true }).click();
    await expect.poll(() => actions).toEqual(["plan", "plan", "repair"]);
  } finally {
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("lifecycle planning exposes quiet progress and disables competing changes", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-lifecycle-progress-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let releasePlan;
  const planReleased = new Promise((resolve) => { releasePlan = resolve; });
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/lifecycle(?:\?|$)/, async (route) => {
      if (route.request().method() === "GET") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecycleSnapshot()) });
      }
      await planReleased;
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecyclePlan("setup")) });
    });
    await openSettings(page, fixture.url);

    await page.getByRole("button", { name: "Review lifecycle plan", exact: true }).click();
    await expect(page.locator(".lifecycleSettings")).toHaveAttribute("aria-busy", "true");
    await expect(page.getByText(/Lifecycle operation in progress/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Repair", exact: true })).toBeDisabled();
    releasePlan();
    await expect(page.getByRole("region", { name: "Setup lifecycle preview" })).toBeVisible();
    await expect(page.locator(".lifecycleSettings")).toHaveAttribute("aria-busy", "false");
  } finally {
    releasePlan?.();
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("lifecycle empty, stale, recovery, conflict, and offline states give next actions", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-lifecycle-states-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1100, height: 900 } });
    const page = await context.newPage();
    let mode = "empty";
    await page.route(/\/api\/lifecycle(?:\?|$)/, async (route) => {
      if (route.request().method() === "GET") {
        const base = lifecycleSnapshot();
        const payload = mode === "empty"
          ? lifecycleSnapshot({ status: "attention_required", enrollment_state: "not_configured", desired_state: null, desired_state_digest: null, reason_codes: [] })
          : mode === "stale"
            ? lifecycleSnapshot({ health_axes: { ...base.health_axes, capture_health: { state: "stale" } } })
            : lifecycleSnapshot({ status: "attention_required", enrollment_state: "recovery_required", reason_codes: ["interrupted_operation_pending"] });
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(payload) });
      }
      if (mode === "conflict") {
        return route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ status: "error", error: { type: "LifecycleConflict", message: "state changed" } }) });
      }
      if (mode === "offline") return route.abort("connectionrefused");
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecyclePlan("setup")) });
    });

    await openSettings(page, fixture.url);
    await expect(page.getByText("No managed lifecycle enrollment exists. Review a setup plan to begin.", { exact: true })).toBeVisible();
    mode = "stale";
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.getByRole("navigation", { name: "Operator console navigation" }).getByRole("button", { name: "Settings", exact: true }).click();
    await expect(page.getByText("Lifecycle evidence is stale. Verify the affected health axis before relying on it.", { exact: true })).toBeVisible();
    mode = "recovery";
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.getByRole("navigation", { name: "Operator console navigation" }).getByRole("button", { name: "Settings", exact: true }).click();
    await expect(page.getByText("An interrupted lifecycle operation needs a repair preview before work continues.", { exact: true })).toBeVisible();

    mode = "conflict";
    await page.getByRole("button", { name: "Review lifecycle plan", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("conflict: state changed");
    await expect(page.getByRole("alert")).toContainText("Inspect and preview the current state again.");
    mode = "offline";
    await page.getByRole("button", { name: "Review lifecycle plan", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("offline:");
    await expect(page.getByRole("alert")).toContainText("Check the local console process, then retry.");
  } finally {
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("stop and removal stay behind explicit preview confirmation", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-lifecycle-stop-remove-"));
  const { child, ready } = startFixtureServer(tempRoot);
  const actions = [];
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/lifecycle(?:\?|$)/, async (route) => {
      const request = route.request();
      if (request.method() === "GET") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecycleSnapshot()) });
      }
      const payload = request.postDataJSON();
      actions.push(payload.action);
      if (payload.action === "plan") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecyclePlan("stop")) });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ status: "ok", state: payload.action === "remove" ? "removed" : "complete" }) });
    });
    await openSettings(page, fixture.url);

    await page.getByRole("button", { name: "Stop managed services", exact: true }).click();
    await expect(page.getByRole("region", { name: "Stop lifecycle preview" })).toBeVisible();
    expect(actions).toEqual(["plan"]);
    await page.getByRole("button", { name: "Confirm stop", exact: true }).click();
    await expect.poll(() => actions).toContain("stop");

    await openSettings(page, fixture.url);
    await page.getByRole("button", { name: "Remove lifecycle enrollment", exact: true }).click();
    await expect(page.getByRole("region", { name: "Remove lifecycle preview" })).toContainText("immutable receipts are preserved");
    await page.getByRole("button", { name: "Confirm removal", exact: true }).click();
    await expect.poll(() => actions).toContain("remove");
  } finally {
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("partial lifecycle failure is actionable and never reported as healthy", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-lifecycle-partial-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await context.newPage();
    await page.route(/\/api\/lifecycle(?:\?|$)/, (route) => route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ status: "error", error: { type: "MigrationRequired", message: "schema upgrade must be reviewed" } }),
    }));
    await openSettings(page, fixture.url);

    await expect(page.getByRole("alert")).toContainText("migration");
    await expect(page.locator("footer.statusBar")).toContainText("Brain Status: Needs attention");
    await expect(page.locator("footer.statusBar")).not.toContainText("Brain Status: Healthy");
    await expect(page.locator(".lifecycleSettings")).toHaveAttribute("aria-busy", "false");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  } finally {
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("lifecycle controls remain usable at 200 percent zoom and honor reduced motion", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-lifecycle-a11y-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 720, height: 900 }, reducedMotion: "reduce", forcedColors: "active" });
    const page = await context.newPage();
    await page.route(/\/api\/lifecycle(?:\?|$)/, async (route) => {
      if (route.request().method() === "GET") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecycleSnapshot()) });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(lifecyclePlan("setup")) });
    });
    await openSettings(page, fixture.url);
    await page.evaluate(() => { document.documentElement.style.zoom = "2"; });
    await page.getByRole("button", { name: "Review lifecycle plan", exact: true }).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("region", { name: "Setup lifecycle preview" })).toBeVisible();
    await page.getByRole("button", { name: "Cancel lifecycle preview", exact: true }).press("Enter");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  } finally {
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
