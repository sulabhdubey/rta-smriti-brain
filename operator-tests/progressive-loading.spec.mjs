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
    await context?.close();
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
    await page.route("**/api/projects", addSecondProject);
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
    await context?.close();
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
    await page.route(/\/api\/project-health\?/, async (route) => {
      await registryReleased;
      const requestUrl = new URL(route.request().url());
      if (requestUrl.searchParams.get("project") === "second-demo") {
        expect(requestUrl.searchParams.get("db_path")).toBe(secondDatabase);
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          json: {
            status: "ok",
            project: {
              status: "ok",
              scan_state: "ready",
              project: "second-demo",
              db_path: secondDatabase,
              db_file: "second-demo.sqlite",
              root_path: secondRoot,
              canonical_root: secondRoot,
              repository_identity: "second-repository",
              checkout_identity: "second-checkout",
              ready: true,
              integrity: {
                status: "ok",
                operationally_ready: true,
                binding: { state: "exact", ready: true },
              },
            },
          },
        });
        return;
      }
      const response = await route.fetch();
      await route.fulfill({ response, json: await response.json() });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.locator(".activeProjectButton").click();
    await expect(
      page.locator(".compactProject").filter({ has: page.getByText("operator-demo", { exact: true }) }).locator("i"),
    ).toHaveAttribute("title", "Repository and database health are still being verified");
    await page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) }).click();
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");

    const secondHealthResponse = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/api/project-health"
        && url.searchParams.get("project") === "second-demo";
    });
    const operatorHealthResponse = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/api/project-health"
        && url.searchParams.get("project") === "operator-demo";
    });
    releaseRegistry();
    const [secondResponse] = await Promise.all([
      secondHealthResponse,
      operatorHealthResponse,
    ]);
    const secondHealth = await secondResponse.json();
    expect(secondHealth.project).toMatchObject({
      project: "second-demo",
      db_path: secondDatabase,
      root_path: secondRoot,
      repository_identity: "second-repository",
    });
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("second-demo");
    await expect(page.locator("footer.statusBar").getByRole("status")).not.toContainText("verified / checking");
  } finally {
    releaseRegistry?.();
    await context?.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("project health completes independently when another brain fails", async ({ browser }) => {
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
    await page.route("**/api/projects", (route) => route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ status: "error", error: { message: "aggregate registry must not be used" } }),
    }));
    await page.route(/\/api\/project-health\?/, async (route) => {
      const url = new URL(route.request().url());
      if (url.searchParams.get("project") === "second-demo") {
        await route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({ status: "error", error: { message: "selected repository unavailable" } }),
        });
        return;
      }
      const response = await route.fetch();
      await route.fulfill({ response });
    });

    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await page.locator(".activeProjectButton").click();
    const firstProject = page.locator(".compactProject").filter({ has: page.getByText("operator-demo", { exact: true }) });
    const secondProject = page.locator(".compactProject").filter({ has: page.getByText("second-demo", { exact: true }) });
    await expect(firstProject.locator("i")).toHaveAttribute("title", "Repository binding and SQLite integrity verified", { timeout: 10_000 });
    await expect(secondProject.locator("i")).toHaveAttribute("title", "Project health needs attention");
    await expect(page.getByText("1/2 verified", { exact: true })).toBeVisible();
  } finally {
    await context?.close();
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
    await context?.close();
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
    await context?.close();
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
    await context?.close();
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
    await page.route("**/api/projects", addSecondProject);
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
    await page.route("**/api/projects", addSecondProject);
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
    await context?.close();
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
    await page.route("**/api/projects", addSecondProject);
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
    await context?.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("project switch never renders continuity counters from the previous brain", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-continuity-view-isolation-"));
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
    await page.route("**/api/projects", addSecondProject);
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
    await context?.close();
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
    await context?.close();
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
    await context?.close();
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
    await page.route("**/api/projects", addSecondProject);
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
    await page?.unrouteAll({ behavior: "ignoreErrors" });
    await context?.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
