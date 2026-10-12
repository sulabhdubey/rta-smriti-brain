import { test, expect } from "@playwright/test";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function startFixtureServer(tempRoot) {
  const python = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
  const child = spawn(python, [path.join(root, "scripts", "operator_qa_server.py"), tempRoot], {
    cwd: root,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
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
  });
  return { child, ready };
}

async function stopProcess(child) {
  if (child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function closeRoutedContext(context) {
  if (!context) return;
  for (const page of context.pages()) {
    await page.unrouteAll({ behavior: "wait" });
  }
  await context.unrouteAll({ behavior: "wait" });
  await context.close();
}

test("many project identities use one health budget instead of a request fanout", async ({ page }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-health-batch-"));
  const { child, ready } = startFixtureServer(tempRoot);
  try {
    const fixture = await ready;
    let identities = [];
    let batches = 0;
    let singles = 0;
    await page.route("**/api/bootstrap", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects[0];
      identities = [first, ...Array.from({ length: 12 }, (_, index) => ({
        ...first, project: `other-${index}`, db_path: path.join(tempRoot, `other-${index}.sqlite`),
      }))];
      await route.fulfill({ response, json: { ...payload, projects: identities } });
    });
    await page.route(/\/api\/project-health\?/, async (route) => {
      singles += 1;
      await route.fulfill({ json: { status: "ok", project: {
        status: "deferred", scan_state: "deferred", ready: false,
        integrity: { status: "deferred", operationally_ready: false },
      } } });
    });
    await page.route(/\/api\/projects(?:\?|$)/, async (route) => {
      batches += 1;
      const url = new URL(route.request().url());
      expect(url.searchParams.get("db_path")).toBe(identities[0].db_path);
      expect(url.searchParams.get("project")).toBe(identities[0].project);
      await route.fulfill({ json: { status: "partial", projects: identities.map((item) => ({
        ...item, status: "deferred", scan_state: "deferred", ready: false,
        integrity: { status: "deferred", operationally_ready: false },
      })) } });
    });
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await expect.poll(() => batches, { timeout: 3_000 }).toBe(1);
    await expect(page.locator(".railFooter")).toContainText("0/13 verified");
    await expect(page.locator(".railFooter")).not.toContainText("checking");
    await expect(page.locator(".graphNode").first()).toBeVisible();
    expect(singles).toBe(0);
    expect(batches).toBe(1);
  } finally {
    await page.unrouteAll({ behavior: "wait" });
    await page.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("busy and failed refreshes retain identities and known errors without automatic retries", async ({ page }, testInfo) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-health-admission-"));
  const { child, ready } = startFixtureServer(tempRoot);
  try {
    const fixture = await ready;
    let phase = "busy";
    let requests = 0;
    let broken;
    await page.route("**/api/bootstrap", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      broken = { ...payload.projects[0], project: "broken-demo", ready: false,
        status: "error", scan_state: "error", error: "known fixture corruption",
        integrity: { status: "attention_required", operationally_ready: false } };
      await route.fulfill({ response, json: { ...payload, projects: [...payload.projects, broken] } });
    });
    await page.route(/\/api\/projects(?:\?|$)/, async (route) => {
      requests += 1;
      if (phase === "busy") return route.fulfill({ json: {
        status: "partial", project_scan_state: "deferred", projects: [],
        reason: "another_project_refresh_is_running",
      } });
      if (phase === "failed") return route.fulfill({ status: 503, json: {
        status: "error", error: { message: "fixture transport unavailable" },
      } });
      const response = await route.fetch();
      const payload = await response.json();
      return route.fulfill({ response, json: { ...payload, projects: [...payload.projects, broken] } });
    });
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await expect(page.locator(".railFooter")).toContainText("0/2 verified");
    await expect(page.locator(".railFooter")).not.toContainText("checking");
    await page.locator(".activeProjectButton").click();
    const brokenProject = page.locator(".compactProject").filter({ has: page.getByText("broken-demo", { exact: true }) });
    await expect(brokenProject.locator("i")).toHaveAttribute("title", "Project health needs attention");
    await expect(page.getByText("Health verification deferred.", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("busy-health-identities.png") });
    expect(requests).toBe(1);
    phase = "failed";
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(page.locator(".railFooter")).toContainText("0/2 verified");
    await expect(page.locator(".railFooter")).not.toContainText("checking");
    await expect(brokenProject.locator("i")).toHaveAttribute("title", "Project health needs attention");
    await expect(page.locator("footer.statusBar")).not.toContainText("Brain Status: Healthy");
    expect(requests).toBe(2);
    phase = "ready";
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(page.locator(".railFooter")).toContainText("1/2 verified");
    await expect(brokenProject.locator("i")).toHaveAttribute("title", "Project health needs attention");
    expect(requests).toBe(3);
  } finally {
    await page.unrouteAll({ behavior: "wait" });
    await page.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("deferred health ends checking, stays unverified, and recovers on manual refresh", async ({ browser }, testInfo) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-health-deferred-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    let deferred = true;
    let requests = 0;
    await page.route(/\/api\/projects(?:\?|$)/, async (route) => {
      requests += 1;
      const response = await route.fetch();
      const payload = await response.json();
      if (deferred) {
        payload.projects = payload.projects.map((project) => ({
          ...project,
          status: "deferred", scan_state: "deferred", ready: false,
          integrity: { status: "deferred", operationally_ready: false, database_verification: "deferred" },
        }));
      }
      await route.fulfill({ response, json: payload });
    });
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Health verification deferred.", { exact: true })).toBeVisible();
    await expect(page.locator(".railFooter")).toContainText("0/1 verified");
    await expect(page.locator(".railFooter")).not.toContainText("checking");
    await expect(page.locator("footer.statusBar")).toContainText("Brain Status: Verification deferred");
    await expect(page.getByText("Checkout integrity needs attention.", { exact: true })).toHaveCount(0);
    await page.locator(".activeProjectButton").click();
    await expect(page.getByRole("button", { name: /operator-demo, .*verification deferred/ })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("health-deferred-desktop.png") });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByText("Health verification deferred.", { exact: true })).toBeVisible();
    const banner = await page.locator(".rootConflictBanner").boundingBox();
    expect(banner.x).toBeGreaterThanOrEqual(0);
    expect(banner.x + banner.width).toBeLessThanOrEqual(390);
    expect(banner.y + banner.height).toBeLessThanOrEqual(844);
    await page.screenshot({ path: testInfo.outputPath("health-deferred-mobile.png"), fullPage: true });
    expect(requests).toBe(1);
    deferred = false;
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(page.locator(".railFooter")).toContainText("1/1 verified");
    await expect(page.getByText("Health verification deferred.", { exact: true })).toHaveCount(0);
    expect(requests).toBe(2);
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("deferred settings never invent an active check or an unbound root", async ({ page }, testInfo) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-health-settings-"));
  const { child, ready } = startFixtureServer(tempRoot);
  try {
    const fixture = await ready;
    await page.route(/\/api\/projects(?:\?|$)/, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.projects = payload.projects.map((project) => ({
        ...project, status: "deferred", scan_state: "deferred", ready: false,
        integrity: { status: "deferred", operationally_ready: false },
      }));
      await route.fulfill({ response, json: payload });
    });
    await page.route(/\/api\/lifecycle\?/, (route) => route.fulfill({ json: {
      status: "partial", unavailable: true, continuation_ready: false,
      health_axes: { database_health: { state: "deferred" }, mcp_health: { state: "unavailable" } },
    } }));
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Health verification deferred.", { exact: true })).toBeVisible();
    await page.getByRole("navigation", { name: "Operator console navigation" }).getByRole("button", { name: "Settings", exact: true }).click();
    await expect(page.getByRole("region", { name: "Database integrity verification" })).toContainText("Verification deferred");
    await expect(page.getByText("Live check in progress", { exact: true })).toHaveCount(0);
    await expect(page.locator(".integritySettings")).toContainText("Verification deferred");
    await expect(page.locator(".integrityFacts")).not.toContainText("unbound");
    await expect(page.locator(".integrityFacts")).toContainText("Root unknown");
    await expect(page.locator(".integrityFacts")).toContainText("Duplicates unknown");
    await expect(page.getByRole("region", { name: "MCP host proof status" })).toContainText("Proof unavailable");
    await page.screenshot({ path: testInfo.outputPath("deferred-settings.png"), fullPage: true });
  } finally {
    await page.unrouteAll({ behavior: "wait" });
    await page.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("fast project data renders while continuity diagnostics are slow", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-progressive-load-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let releaseSlowRequests;
  const slowRequestsReleased = new Promise((resolve) => { releaseSlowRequests = resolve; });
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/(?:continuity|checkpoint)\?/, async (route) => {
      await slowRequestsReleased;
      await route.continue();
    });
    const graphResponse = page.waitForResponse((response) => response.url().includes("/api/graph?"));
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await graphResponse;

    await expect(page.getByRole("button", { name: /^Imports, \d+ nodes\./ })).toBeVisible({ timeout: 2_000 });
    await expect(page.locator("footer.statusBar").getByRole("status")).toContainText(/core data available; checking/);
  } finally {
    releaseSlowRequests?.();
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("collapsed graph groups are not reported as empty", async ({ page }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-collapsed-graph-"));
  const { child, ready } = startFixtureServer(tempRoot);
  try {
    const fixture = await ready;
    await page.goto(fixture.url);
    await expect(page.locator(".graphNode").first()).toBeVisible();
    const hubs = page.locator(".semanticHub");
    const count = await hubs.count();
    expect(count).toBeGreaterThan(0);
    for (let index = 0; index < count; index += 1) await hubs.nth(index).click();
    await expect(page.locator(".graphNode")).toHaveCount(0);
    await expect(page.locator(".emptyGraph")).toHaveCount(0);
    await expect(page.locator(".projectCore")).toBeVisible();
  } finally {
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("project switch clears captured events before the next brain loads", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-project-isolation-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let releaseSecond;
  const secondReleased = new Promise((resolve) => { releaseSecond = resolve; });
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();

    const addSecondProject = async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects?.[0];
      const second = first ? { ...first, project: "second-demo", ready: true, scan_state: "ready" } : null;
      await route.fulfill({ response, json: { ...payload, projects: second ? [...payload.projects, second] : payload.projects } });
    };
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return addSecondProject(route);
    });
    await page.route(/\/api\/projects(?:\?|$)/, addSecondProject);
    await page.route(/\/api\/capture\?/, async (route) => {
      const requestUrl = new URL(route.request().url());
      const project = requestUrl.searchParams.get("project");
      const mode = requestUrl.searchParams.get("mode");
      if (project === "second-demo") {
        await secondReleased;
        const empty = mode === "overview"
          ? { status: "ok", state: "stopped", sources: [], counts: {} }
          : mode === "replay"
            ? { status: "ok", events: [], count: 0 }
            : { status: "ok", gaps: [], counts: {} };
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(empty) });
        return;
      }
      const response = await route.fetch();
      const payload = await response.json();
      if (mode === "replay") {
        payload.events = [{
          event_id: "old-project-event",
          project_sequence: 1,
          event_name: "old.project.secret.v1",
          recorded_at: "2026-08-24T00:00:00Z",
          source_id: "old-project-only",
          verification_status: "unverified",
          privacy_class: "internal",
        }];
      }
      await route.fulfill({ response, json: payload });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    const navigation = page.getByRole("navigation", { name: "Operator console navigation" });
    await navigation.getByRole("button", { name: /^Capture(?:\s|$)/ }).click();
    await expect(page.getByRole("button", { name: /old project secret/ })).toBeVisible();
    await page.getByRole("tab", { name: "diagnostics" }).click();
    await expect(page.getByRole("heading", { name: "Journal integrity verified" })).toBeVisible();

    await page.locator(".activeProjectButton").click();
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");
    await expect(page.getByRole("button", { name: /old project secret/ })).toHaveCount(0);
    await expect(page.getByText("Loading capture diagnostics...", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Journal needs attention" })).toHaveCount(0);
  } finally {
    releaseSecond?.();
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("background registry completion preserves a newer operator project selection", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-registry-race-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let releaseRegistry;
  const registryReleased = new Promise((resolve) => { releaseRegistry = resolve; });
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    const secondDatabase = path.join(tempRoot, "second-demo.sqlite");
    const secondRoot = path.join(tempRoot, "second-project");
    const addSecondProject = async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects?.[0];
      const second = first ? {
        ...first,
        project: "second-demo",
        db_path: secondDatabase,
        db_file: "second-demo.sqlite",
        root_path: secondRoot,
        canonical_root: secondRoot,
        repository_identity: "second-repository",
        checkout_identity: "second-checkout",
        ready: true,
        scan_state: "ready",
      } : null;
      await route.fulfill({ response, json: { ...payload, projects: second ? [...payload.projects, second] : payload.projects } });
    };
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return addSecondProject(route);
    });
    await page.route(/\/api\/projects(?:\?|$)/, async (route) => {
      await registryReleased;
      return addSecondProject(route);
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.locator(".activeProjectButton").click();
    await expect(
      page.locator(".compactProject").filter({ has: page.getByText("operator-demo", { exact: true }) }).locator("i"),
    ).toHaveAttribute("title", "Repository and database health are still being verified");
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");

    const healthResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/projects");
    releaseRegistry();
    const health = await (await healthResponse).json();
    expect(health.projects.find((item) => item.project === "second-demo")).toMatchObject({
      project: "second-demo",
      db_path: secondDatabase,
      root_path: secondRoot,
      repository_identity: "second-repository",
    });
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");
    await expect(page.locator("footer.statusBar").getByRole("status")).not.toContainText("verified / checking");
  } finally {
    releaseRegistry?.();
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

for (const otherState of ["error", "deferred"]) {
test(`project health completes independently when another brain is ${otherState}`, async ({ browser }, testInfo) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-independent-health-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      const response = await route.fetch();
      const payload = await response.json();
      if (!Array.isArray(payload.projects) || !payload.projects.length) return route.continue();
      const first = payload.projects[0];
      const second = { ...first, project: "second-demo", ready: null, scan_state: "checking" };
      await route.fulfill({ response, json: { ...payload, projects: [first, second] } });
    });
    await page.route(/\/api\/projects(?:\?|$)/, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      await route.fulfill({ response, json: { ...payload, projects: [...payload.projects, {
        ...payload.projects[0], project: "second-demo", status: otherState, scan_state: otherState,
        ready: false, error: otherState === "deferred" ? "Health verification deferred: bank budget exhausted." : "selected repository unavailable",
        integrity: { status: otherState === "deferred" ? "deferred" : "attention_required", operationally_ready: false },
      }] } });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.locator(".activeProjectButton").click();
    const firstProject = page.locator(".compactProject").filter({ has: page.getByText("operator-demo", { exact: true }) });
    const secondProject = page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) });
    await expect(firstProject.locator("i")).toHaveAttribute("title", "Repository binding and SQLite integrity verified", { timeout: 10_000 });
    await expect(secondProject.locator("i")).toHaveAttribute("title", otherState === "deferred" ? "Health verification deferred; no verdict issued" : "Project health needs attention");
    await expect(page.getByText("1/2 verified", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`${otherState}-mixed-health-desktop.png`) });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("button", { name: /operator-demo, .*verified and ready/ })).toBeVisible();
    await expect(page.getByRole("button", { name: otherState === "deferred" ? /second-demo, .*verification deferred/ : /second-demo, .*needs attention/ })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`${otherState}-mixed-health-mobile.png`), fullPage: true });
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
}

test("partial health keeps observed failures visible and review opens diagnostics", async ({ browser }, testInfo) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-partial-health-evidence-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    let replyMode = "diagnosed";
    await page.route(/\/api\/projects(?:\?|$)/, async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      if (replyMode === "busy") return route.fulfill({ response, json: { status: "partial", projects: [] } });
      if (replyMode === "healthy") return route.fulfill({ response, json: payload });
      if (replyMode === "empty") return route.fulfill({ response, json: { ...payload, projects: payload.projects.map((project) => ({
        ...project, ready: false, sources: 0, memories: 0, health_reasons: ["no_indexed_content"],
        integrity: { ...project.integrity, status: "attention_required" },
      })) } });
      await route.fulfill({ response, json: { ...payload, projects: payload.projects.map((project) => ({
        ...project, status: "deferred", scan_state: "deferred", ready: false,
        health_reasons: ["schema_mismatch", "binding_drift", "database_verification_deferred"],
        integrity: {
          ...project.integrity, status: "attention_required", operationally_ready: false,
          schema_version: 91, schema_current: false, sqlite_quick_check: "not_completed",
          database_verification: "deferred", binding: { state: "binding_drift", ready: false, root_match: true },
        },
      })) } });
    });
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    const banner = page.locator(".rootConflictBanner");
    await expect(banner).toContainText("Project binding changed.");
    await expect(banner).toContainText("SQLite integrity verification is deferred.");
    await expect(page.locator("footer.statusBar")).toContainText("Needs attention");
    await banner.getByRole("button", { name: "Review", exact: true }).click();
    await expect(page.locator(".integritySettings")).toContainText("Attention required; verification deferred");
    await expect(page.locator(".integrityFacts")).toContainText("v91 (mismatch)");
    await expect(page.locator(".integrityFacts")).toContainText("binding drift");
    await expect(page.locator(".integrityFacts")).toContainText("SQLite deferred");
    await expect(page.getByLabel("Trusted lifecycle health axes").getByText("conflicting evidence", { exact: true })).toHaveCount(2);
    for (const [label, viewport] of [["desktop", { width: 1440, height: 900 }], ["mobile", { width: 390, height: 844 }]]) {
      await page.setViewportSize(viewport);
      await page.locator(".integritySettings").scrollIntoViewIfNeeded();
      const bounds = await page.locator(".integritySettings").boundingBox();
      expect(bounds.x).toBeGreaterThanOrEqual(0);
      expect(bounds.x + bounds.width).toBeLessThanOrEqual(viewport.width);
      await page.screenshot({ path: testInfo.outputPath(`partial-health-${label}.png`), fullPage: true });
    }
    replyMode = "busy";
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(page.locator(".integritySettings")).toContainText("Project binding changed.");
    await expect(page.locator("footer.statusBar")).toContainText("Needs attention");
    replyMode = "healthy";
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(banner).toHaveCount(0);
    await expect(page.locator(".integritySettings")).not.toContainText("Project binding changed.");
    replyMode = "empty";
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(page.locator(".integritySettings")).toContainText("No files or memories have been indexed.");
    await expect(page.locator(".integritySettings")).not.toHaveClass(/verified/);
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("freshness warnings explain indexed coverage and reused verification", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-freshness-trust-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/stale-check\?/, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          status: "ok",
          state: "fresh_with_warnings",
          mode: "sha256",
          fresh: 4,
          changed: 0,
          missing: 0,
          added: 0,
          uninspectable: 0,
          metadata_only: 1,
          hash_cache_hits: 4,
          hash_cache_misses: 0,
        }),
      });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.getByTitle("Inspect evidence and freshness").click();

    await expect(page.getByText("Fresh with warnings", { exact: true })).toBeVisible();
    await expect(page.getByText(/4 content-verified files match the index/)).toBeVisible();
    await expect(page.getByText(/1 oversized file is tracked by metadata only/)).toBeVisible();
    await expect(page.getByText(/4 content hashes reused/)).toBeVisible();
    await expect(page.getByText(/Git working-tree changes are separate from index freshness/)).toBeVisible();
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("metadata-only freshness checks never claim content verification", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-freshness-stat-only-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/stale-check\?/, (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        status: "ok",
        state: "fresh",
        mode: "stat-manifest",
        fresh: 8,
        changed: 0,
        missing: 0,
        added: 0,
        uninspectable: 0,
        metadata_only: 0,
      }),
    }));

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.getByTitle("Inspect evidence and freshness").click();

    await expect(page.getByText(/paths, sizes, and modification times match the index/i)).toBeVisible();
    await expect(page.getByText(/deep SHA-256 verification was not run/i)).toBeVisible();
    await expect(page.getByText(/content-verified files match the index/i)).toHaveCount(0);
    await expect(page.getByText(/content hashes reused/i)).toHaveCount(0);
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("unknown freshness states never claim that repository content matches the index", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-freshness-error-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route(/\/api\/stale-check\?/, (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ status: "ok", state: "partial", fresh: 9 }),
    }));

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.getByTitle("Inspect evidence and freshness").click();

    await expect(page.getByText(/Repository freshness could not be verified/)).toBeVisible();
    await expect(page.getByText(/content-verified files match the index/)).toHaveCount(0);
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("project switch clears graph filters that belong to the previous brain", async ({ page }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-project-filter-isolation-"));
  const { child, ready } = startFixtureServer(tempRoot);
  try {
    const fixture = await ready;
    const addSecondProject = async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects?.[0];
      const second = first ? { ...first, project: "second-demo", ready: true, scan_state: "ready" } : null;
      await route.fulfill({ response, json: { ...payload, projects: second ? [...payload.projects, second] : payload.projects } });
    };
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return addSecondProject(route);
    });
    await page.route(/\/api\/projects(?:\?|$)/, addSecondProject);
    await page.route(/\/api\/graph\?/, async (route) => {
      const requestUrl = new URL(route.request().url());
      if (requestUrl.searchParams.get("project") === "second-demo") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ status: "ok", project: "second-demo", nodes: [], edges: [] }),
        });
        return;
      }
      await route.continue();
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.locator('main button[aria-label="Search"]').click();
    await page.getByRole("textbox", { name: "Search graph nodes", exact: true }).fill("previous-project-only");
    await expect(page.getByText("No matching nodes", { exact: true })).toBeVisible();

    await page.locator(".activeProjectButton").click();
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();

    await expect(page.getByRole("textbox", { name: "Search graph nodes", exact: true })).toHaveValue("");
    await expect(page.getByText("No matching nodes", { exact: true })).toBeVisible();
    await expect(page.getByText("run_queue", { exact: true })).toHaveCount(0);
  } finally {
    await page.unrouteAll({ behavior: "wait" });
    await page.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("project switch stops the previous brain from issuing queued detail requests", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-project-request-cancel-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let releaseOldRequests;
  const oldRequestsReleased = new Promise((resolve) => { releaseOldRequests = resolve; });
  let resolveFifthOldRequest;
  const fifthOldRequest = new Promise((resolve) => { resolveFifthOldRequest = resolve; });
  let oldRequestCount = 0;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    const addSecondProject = async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects?.[0];
      const second = first ? { ...first, project: "second-demo", ready: true, scan_state: "ready" } : null;
      await route.fulfill({ response, json: { ...payload, projects: second ? [...payload.projects, second] : payload.projects } });
    };
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return addSecondProject(route);
    });
    await page.route(/\/api\/projects(?:\?|$)/, addSecondProject);
    await page.route(/\/api\/(?:memories|graph|stale-check|settings|checkpoint|watcher|governance|continuity|lifecycle|truth|cognition|federation)\?/, async (route) => {
      const requestUrl = new URL(route.request().url());
      if (requestUrl.searchParams.get("project") === "operator-demo") {
        oldRequestCount += 1;
        if (oldRequestCount === 5) resolveFifthOldRequest();
        await oldRequestsReleased;
      }
      await route.continue();
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await expect.poll(() => oldRequestCount).toBe(4);
    await page.locator(".activeProjectButton").click();
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");

    releaseOldRequests();
    const launchedAnotherOldRequest = await Promise.race([
      fifthOldRequest.then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 1_500)),
    ]);
    expect(launchedAnotherOldRequest).toBe(false);
    expect(oldRequestCount).toBe(4);
  } finally {
    releaseOldRequests?.();
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("continuity action completion cannot overwrite a newly selected project", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-continuity-action-isolation-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let releaseAction;
  const actionReleased = new Promise((resolve) => { releaseAction = resolve; });
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    const addSecondProject = async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects?.[0];
      const second = first ? { ...first, project: "second-demo", ready: true, scan_state: "ready" } : null;
      await route.fulfill({ response, json: { ...payload, projects: second ? [...payload.projects, second] : payload.projects } });
    };
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return addSecondProject(route);
    });
    await page.route(/\/api\/projects(?:\?|$)/, addSecondProject);
    await page.route("**/api/continuity", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      await actionReleased;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ state: "running", events_inserted: 99, checkpoints_created: 7 }),
      });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.getByRole("navigation", { name: "Operator console navigation" }).getByRole("button", { name: "Settings", exact: true }).click();
    await page.getByRole("button", { name: "Start Capture", exact: true }).click();
    await page.locator(".activeProjectButton").click();
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();
    releaseAction();

    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");
    await page.getByTitle("Review authorized agent continuity events").click();
    await expect(page.getByText(/99 events/)).toHaveCount(0);
  } finally {
    releaseAction?.();
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("project switch never renders continuity counters from the previous brain", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-continuity-view-isolation-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let page;
  let releaseSecond;
  const secondReleased = new Promise((resolve) => { releaseSecond = resolve; });
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    page = await context.newPage();
    const addSecondProject = async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects?.[0];
      const second = first ? { ...first, project: "second-demo", ready: true, scan_state: "ready" } : null;
      await route.fulfill({ response, json: { ...payload, projects: second ? [...payload.projects, second] : payload.projects } });
    };
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return addSecondProject(route);
    });
    await page.route(/\/api\/projects(?:\?|$)/, addSecondProject);
    await page.route(/\/api\/continuity\?/, async (route) => {
      const requestUrl = new URL(route.request().url());
      const second = requestUrl.searchParams.get("project") === "second-demo";
      if (second) await secondReleased;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          state: "running",
          events_inserted: second ? 2 : 99,
          checkpoints_created: second ? 1 : 7,
        }),
      });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.getByTitle("Review authorized agent continuity events").click();
    await expect(page.getByText(/running \/ 99 events \/ 7 checkpoints/)).toBeVisible();

    await page.locator(".activeProjectButton").click();
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");
    await expect(page.getByText(/99 events/)).toHaveCount(0);

    releaseSecond();
    await expect(page.getByText(/running \/ 2 events \/ 1 checkpoints/)).toBeVisible();
  } finally {
    releaseSecond?.();
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("installed operators do not see maintainer-only release controls", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-installed-surface-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.route("**/api/publish-readiness", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ status: "ok", source_checkout: false, ready: false, checks: [] }),
      });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.waitForResponse((response) => response.url().includes("/api/publish-readiness"));

    await expect(page.getByRole("button", { name: "Publish", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^Rta-Smriti Release/ })).toHaveCount(0);
    await page.getByRole("button", { name: "Cmd Palette", exact: true }).click();
    await expect(page.getByRole("button", { name: "Check Rta-Smriti release", exact: true })).toHaveCount(0);
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("retrieval diagnostics name semantic index coverage precisely", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-retrieval-label-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    const navigation = page.getByRole("navigation", { name: "Operator console navigation" });
    await navigation.getByRole("button", { name: /^Intelligence(?:\s|$)/ }).click();
    await page.getByLabel("Question to explain").fill("operator dashboard");
    await page.getByRole("button", { name: "Explain retrieval", exact: true }).click();

    await expect(page.getByText("Embedding coverage", { exact: true })).toBeVisible();
    await expect(page.getByText("Coverage", { exact: true })).toHaveCount(0);
  } finally {
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("late file preview from the prior project is discarded", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-preview-race-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let page;
  let releasePreview;
  const previewReleased = new Promise((resolve) => { releasePreview = resolve; });
  try {
    const fixture = await ready;
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    page = await context.newPage();
    const addSecondProject = async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const first = payload.projects?.[0];
      const second = first ? { ...first, project: "second-demo", ready: true, scan_state: "ready" } : null;
      await route.fulfill({ response, json: { ...payload, projects: second ? [...payload.projects, second] : payload.projects } });
    };
    await page.route("**/api/bootstrap", async (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return addSecondProject(route);
    });
    await page.route(/\/api\/projects(?:\?|$)/, addSecondProject);
    await page.route(/\/api\/file-preview\?/, async (route) => {
      const requestUrl = new URL(route.request().url());
      if (requestUrl.searchParams.get("project") !== "second-demo") {
        await previewReleased;
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ status: "ok", file: { name: "README.md", relative_path: "README.md", content: "PROJECT A PRIVATE PREVIEW" } }),
        });
        return;
      }
      await route.continue();
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    const navigation = page.getByRole("navigation", { name: "Operator console navigation" });
    await navigation.getByRole("button", { name: "Files", exact: true }).click();
    await page.getByRole("button", { name: /README\.md/ }).first().click();
    await page.locator(".activeProjectButton").click();
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");

    releasePreview();
    await expect(page.getByText("PROJECT A PRIVATE PREVIEW", { exact: true })).toHaveCount(0);
  } finally {
    releasePreview?.();
    await closeRoutedContext(context);
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
