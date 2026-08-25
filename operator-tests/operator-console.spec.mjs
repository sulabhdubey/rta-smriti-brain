import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const captureLaunchAssets = process.env.RTA_CAPTURE_LAUNCH_ASSETS === "1";
const captureOutputDir = process.env.RTA_CAPTURE_OUTPUT_DIR || path.join(root, "launch-assets", "screenshots");

async function captureLaunchScreenshot(page, name) {
  if (!captureLaunchAssets) return;
  await page.screenshot({
    path: path.join(captureOutputDir, name),
    animations: "disabled",
  });
}

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

async function runCleanupCommand(args, timeoutMs = 12_000) {
  const python = process.env.PYTHON || (process.platform === "win32" ? "python" : "python3");
  const child = spawn(python, args, { cwd: root, stdio: "ignore" });
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, timeoutMs)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function stopBootstrappedDaemons(tempRoot) {
  const database = path.join(tempRoot, "brains", "bootstrapped-project.sqlite");
  const projectRoot = path.join(tempRoot, "bootstrapped-project");
  await runCleanupCommand([
    path.join(root, "rta-brain.py"), "capture", "--db", database,
    "--project", "bootstrapped-project", "--root", projectRoot,
    "daemon", "stop",
  ]);
  await runCleanupCommand([
    path.join(root, "rta-brain.py"), "--db", database,
    "continuity", "stop", "--project", "bootstrapped-project",
  ]);
  await runCleanupCommand([
    path.join(root, "rta-brain.py"), "--db", database,
    "watcher", "stop", "--project", "bootstrapped-project",
  ]);
}

async function unnamedControls(page) {
  return page.locator("input, textarea, select, button").evaluateAll((elements) => elements.filter((element) => {
    const text = (element.textContent || "").trim();
    const aria = element.getAttribute("aria-label") || element.getAttribute("aria-labelledby");
    const title = element.getAttribute("title");
    const labels = element.labels ? [...element.labels].map((label) => (label.textContent || "").trim()).filter(Boolean) : [];
    return !text && !aria && !title && !labels.length;
  }).map((element) => element.outerHTML));
}

async function expectNoAxeViolations(page, label, disabledRules = []) {
  let builder = new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]);
  if (disabledRules.length) builder = builder.disableRules(disabledRules);
  const result = await builder.analyze();
  const violations = result.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    targets: violation.nodes.map((node) => node.target),
  }));
  expect(violations, `${label} has WCAG violations`).toEqual([]);
}

async function clickForJsonResponse(page, buttonName, endpoint) {
  const responsePromise = page.waitForResponse((response) => (
    new URL(response.url()).pathname === endpoint
    && response.request().method() === "POST"
  ));
  await page.getByRole("button", { name: buttonName, exact: true }).click();
  const response = await responsePromise;
  const body = await response.text();
  expect(
    response.ok(),
    `${endpoint} returned HTTP ${response.status()}: ${body.slice(0, 2_000)}`,
  ).toBeTruthy();
  let payload;
  try {
    payload = JSON.parse(body);
  } catch {
    throw new Error(`${endpoint} returned non-JSON content: ${body.slice(0, 2_000)}`);
  }
  expect(payload.status, `${endpoint} returned an error payload`).not.toBe("error");
  return payload;
}

test("real operator can inspect, govern, continue, and move a project brain", async ({ browser }) => {
  test.setTimeout(180_000);
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-operator-qa-"));
  const { child, ready } = startFixtureServer(tempRoot);
  const errors = [];
  let context;
  let releaseReloadCognition;
  try {
    const fixture = await ready;
    const bootstrapRepo = path.join(tempRoot, "bootstrapped-project");
    await mkdir(bootstrapRepo);
    await writeFile(path.join(bootstrapRepo, "README.md"), "# Bootstrapped project\n", "utf8");
    context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      permissions: ["clipboard-read", "clipboard-write"],
    });
    const page = await context.newPage();
    page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
    page.on("console", (message) => {
      if (["error", "warning"].includes(message.type())) errors.push(`${message.type()}: ${message.text()}`);
    });

    const fixtureToken = new URL(fixture.url).hash.replace(/^#token=/, "");
    expect(fixtureToken.length).toBeGreaterThanOrEqual(32);
    expect(fixtureToken).not.toBe("operator-qa-capability");
    const retiredFixtureTokenStatus = await fetch(new URL("/api/health", fixture.url), {
      headers: { "X-Rta-Smriti-Token": "operator-qa-capability" },
    }).then((response) => response.status);
    expect(retiredFixtureTokenStatus).toBe(403);
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await expect(page).toHaveTitle("Rta-Smriti Brain");
    await expect(page.getByText("operator-demo", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Brain Status: Healthy", { exact: true })).toBeVisible();
    await captureLaunchScreenshot(page, "operator-console-v0.6.png");
    const operatorNavigation = page.getByRole("navigation", { name: "Operator console navigation" });

    const navigation = [
      ["Graph", () => page.getByRole("region", { name: "Interactive project brain graph" })],
      ["Canvas", () => page.getByRole("region", { name: "Spatial project canvas" })],
      ["Bases", () => page.getByRole("region", { name: "Typed project data tables" })],
      ["Files", () => page.getByRole("region", { name: "Indexed project file explorer" })],
      ["Symbols", () => page.getByRole("region", { name: "Typed project data tables" })],
      ["Imports", () => page.getByRole("region", { name: "Typed project data tables" })],
      ["Memories", () => page.getByRole("region", { name: "Typed project data tables" })],
      ["Evidence", () => page.getByRole("heading", { name: "Evidence Inspector", exact: true })],
      ["Capture", () => page.getByRole("region", { name: "Universal capture console" })],
      ["Search", () => page.getByLabel("Search graph nodes")],
      ["Action Gate", () => page.getByRole("heading", { name: "Action Gate", exact: true })],
      ["Intelligence", () => page.getByRole("heading", { name: "Project Intelligence", exact: true })],
      ["Memory Ledger", () => page.getByRole("heading", { name: "Memory Ledger", exact: true })],
      ["Continue Work", () => page.getByRole("heading", { name: "Continue Work", exact: true })],
      ["Context Packs", () => page.getByRole("heading", { name: "Context-Pack Receipts", exact: true })],
      ["Rta-Smriti Release", () => page.getByRole("heading", { name: "Rta-Smriti Release", exact: true })],
      ["Settings", () => page.locator(".graphSettings")],
    ];
    for (const [label, destination] of navigation) {
      const navigationButton = operatorNavigation.getByRole("button", { name: new RegExp(`^${label}(?:\\s|$)`) });
      await navigationButton.click();
      await expect(navigationButton).toHaveClass(/active/);
      await expect(navigationButton).toHaveAttribute("aria-current", "page");
      await expect(operatorNavigation.locator('[aria-current="page"]')).toHaveCount(1);
      await expect(destination()).toBeVisible();
      expect(await unnamedControls(page), `${label} contains unnamed controls`).toEqual([]);
      await expectNoAxeViolations(page, label);
    }
    await operatorNavigation.getByRole("button", { name: "Bases", exact: true }).click();
    const memoriesBaseTab = page.getByRole("tab", { name: "Memories", exact: true });
    await memoriesBaseTab.focus();
    await memoriesBaseTab.press("ArrowRight");
    await expect(page.getByRole("tab", { name: "Sources", exact: true })).toHaveAttribute("aria-selected", "true");
    await page.getByRole("tab", { name: "Memories", exact: true }).click();
    const memoryTable = page.getByRole("table", { name: "Project memories" });
    await expect(memoryTable.getByRole("columnheader")).toHaveCount(4);
    expect(await memoryTable.getByRole("row").count()).toBeGreaterThan(1);
    await expect(memoryTable.getByRole("rowgroup")).toHaveCount(2);
    await expect(page.locator("#base-panel-memory").getByRole("button")).toHaveCount(0);
    await expect(page.getByRole("status").last()).toBeAttached();
    await operatorNavigation.getByRole("button", { name: "Settings", exact: true }).click();
    await expect(page.getByText("Checkout integrity", { exact: true })).toBeVisible();
    await expect(page.getByText("Verified", { exact: true })).toBeVisible();
    const largeFilePolicy = page.getByLabel("Oversized source handling");
    const parserAdapter = page.getByLabel("Parser adapter");
    const compactionProvider = page.getByLabel("Thread compaction");
    await expect(largeFilePolicy).toHaveValue("metadata");
    await expect(parserAdapter.getByRole("option", { name: "Auto (bundled Tree-sitter)" })).toHaveCount(1);
    await parserAdapter.selectOption("lsp");
    await expect(page.getByLabel("Auto-detect supported language servers")).toBeChecked();
    await expect(page.getByText(/language server detected|Detected:/)).toBeVisible();
    await parserAdapter.selectOption("auto");
    await compactionProvider.selectOption("ollama");
    await expect(page.getByLabel("Local model")).toBeVisible();
    await expect(page.getByLabel("Loopback endpoint")).toHaveValue("http://127.0.0.1:11434");
    await compactionProvider.selectOption("none");
    await largeFilePolicy.selectOption("block");
    await page.getByRole("button", { name: "Save Policy", exact: true }).click();
    await expect(page.getByRole("status").last()).toContainText("Indexing policy saved");
    await page.reload();
    await operatorNavigation.getByRole("button", { name: "Settings", exact: true }).click();
    await expect(page.getByLabel("Oversized source handling")).toHaveValue("block");
    await page.getByRole("button", { name: "Start Sync", exact: true }).click();
    await expect(page.getByRole("button", { name: "Stop Sync", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Stop Sync", exact: true })).toHaveAttribute("aria-busy", "false");
    await page.getByRole("button", { name: "Stop Sync", exact: true }).click();
    await expect(page.getByRole("button", { name: "Start Sync", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Start Sync", exact: true })).toHaveAttribute("aria-busy", "false");

    await operatorNavigation.getByRole("button", { name: "Search", exact: true }).click();
    await operatorNavigation.getByRole("button", { name: "Graph", exact: true }).click();
    const stageToolbar = page.locator(".stageToolbar");
    const searchToggle = stageToolbar.getByRole("button", { name: "Search", exact: true });
    await expect(searchToggle).toHaveAttribute("aria-pressed", "true");
    await searchToggle.click();
    await expect(searchToggle).toHaveAttribute("aria-pressed", "false");
    const typesToggle = stageToolbar.getByRole("button", { name: "Types", exact: true });
    await expect(typesToggle).toHaveAttribute("aria-pressed", "false");
    await typesToggle.click();
    await expect(typesToggle).toHaveAttribute("aria-pressed", "true");
    await typesToggle.click();
    const settingsToggle = stageToolbar.getByRole("button", { name: "Settings", exact: true });
    await expect(settingsToggle).toHaveAttribute("aria-pressed", "false");
    await settingsToggle.click();
    await expect(settingsToggle).toHaveAttribute("aria-pressed", "true");
    await settingsToggle.click();
    await expect(operatorNavigation.locator('[aria-current="page"]')).toHaveCount(1);
    const graph = page.getByRole("region", { name: "Interactive project brain graph" });
    await expect(graph.getByRole("button")).not.toHaveCount(0);
    const graphHub = graph.getByRole("button", { name: /^Imports, \d+ nodes\./ });
    await graphHub.click();
    await expect(graphHub).toHaveAttribute("aria-pressed", "true");
    await graphHub.press("Enter");
    await expect(graphHub).toHaveAttribute("aria-pressed", "false");
    await graph.getByRole("button", { name: "Zoom in", exact: true }).click();
    await expect(graph.getByText("110%", { exact: true })).toBeVisible();
    const graphDownload = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export current view", exact: true }).click();
    expect((await graphDownload).suggestedFilename()).toContain("operator-demo-graph.json");

    await graph.getByRole("button", { name: /queue_budget, call/ }).click();
    const openInspector = stageToolbar.getByRole("button", { name: "Open detail panel", exact: true });
    if (await openInspector.isVisible()) await openInspector.click();
    await page.getByRole("button", { name: "Refs", exact: true }).click();
    await expect(page.getByRole("heading", { name: "References & Backlinks", exact: true })).toBeVisible();
    const referencePanel = page.locator(".drawerContent").filter({ has: page.getByRole("heading", { name: "References & Backlinks" }) });
    const reference = referencePanel.locator(".referenceList button").first();
    await expect(reference).toBeVisible();
    await reference.click();
    const back = referencePanel.getByRole("button", { name: /^Back/ });
    await expect(back).toBeEnabled();
    await back.click();

    await operatorNavigation.getByRole("button", { name: "Canvas", exact: true }).click();
    const canvas = page.getByRole("region", { name: "Spatial project canvas" });
    const canvasNode = canvas.locator(".canvasCard").first();
    await canvasNode.click();
    await expect(canvasNode).toHaveAttribute("aria-pressed", "true");
    await canvasNode.press("Enter");
    await expect(page.getByRole("heading", { name: "Evidence Inspector", exact: true })).toBeVisible();
    const canvasDownload = page.waitForEvent("download");
    await canvas.getByRole("button", { name: "Export JSON", exact: true }).click();
    expect((await canvasDownload).suggestedFilename()).toContain("operator-demo-canvas.json");

    await page.getByRole("button", { name: "New Task Prompt", exact: true }).click();
    await expect(page.getByRole("button", { name: "Prompt Copied", exact: true })).toBeVisible();
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain("Validate the queue release");
    await page.getByRole("main").getByRole("button", { name: "Copy Command", exact: true }).click();
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain("context-pack");
    await page.getByRole("button", { name: "Generate Context Pack", exact: true }).click();
    await expect(page.getByRole("button", { name: /1 receipt/ })).toBeVisible();
    await page.getByRole("button", { name: "Governed Compiler", exact: true }).click();
    await expect(page.getByText("Authorized, receipted, explainable", { exact: true })).toBeVisible();
    const firstCompilation = await clickForJsonResponse(page, "Authorize & Compile", "/api/context-compiler");
    expect(firstCompilation.compilation_receipt?.compilation_id).toContain("ctxc-");
    await expect(page.locator(".compilerReceiptSummary code")).toContainText("ctxc-");
    await page.getByRole("button", { name: "Explain", exact: true }).click();
    await expect(page.getByText(/Explanation verified/)).toBeVisible();
    await page.getByRole("button", { name: "Audit", exact: true }).click();
    await expect(page.getByText(/Audit verified/)).toBeVisible();
    await expectNoAxeViolations(page, "Governed Context Compiler");
    const governedObjective = page.getByLabel("Objective");
    await governedObjective.fill(`${await governedObjective.inputValue()} with a changed objective`);
    await expect(page.locator(".compilerReceiptSummary")).toHaveCount(0);
    await expect(page.getByRole("main").getByRole("button", { name: "Copy Command", exact: true })).toBeVisible();
    const secondCompilation = await clickForJsonResponse(page, "Authorize & Compile", "/api/context-compiler");
    expect(secondCompilation.compilation_receipt?.compilation_id).toContain("ctxc-");
    await expect(page.locator(".compilerReceiptSummary code")).toContainText("ctxc-");

    await operatorNavigation.getByRole("button", { name: "Files", exact: true }).click();
    await page.getByRole("button", { name: /README\.md/ }).first().click();
    await page.getByRole("button", { name: "Add to Task", exact: true }).click();
    await expect(page.getByLabel("Objective")).toContainText("Relevant file: README.md");
    await page.locator(".inspectorTabs").getByRole("button", { name: "Evidence", exact: true }).click();
    await page.evaluate(() => window.scrollTo(0, 0));
    await captureLaunchScreenshot(page, "operator-files-v0.6.png");

    await operatorNavigation.getByRole("button", { name: /^Action Gate/ }).click();
    await page.getByLabel("Intended action").fill("Publish release");
    await page.getByRole("button", { name: "Evaluate action", exact: true }).click();
    await expect(page.locator(".gateDecision strong")).toHaveText("block");
    await page.getByLabel("Override reason").fill("Operator-approved fixture override");
    await page.getByRole("button", { name: "Record override receipt", exact: true }).click();
    await expect(page.getByText("Operator-approved fixture override", { exact: true })).toBeVisible();

    await operatorNavigation.getByRole("button", { name: "Intelligence", exact: true }).click();
    const retrievalTab = page.getByRole("tab", { name: "Retrieval", exact: true });
    await retrievalTab.click();
    await retrievalTab.press("ArrowRight");
    await expect(page.getByRole("tab", { name: "Impact", exact: true })).toHaveAttribute("aria-selected", "true");
    await page.getByRole("tab", { name: "Workspaces", exact: true }).click();
    await page.getByLabel("New workspace name").fill("release-workspace");
    await page.getByRole("button", { name: "Create", exact: true }).click();
    await page.getByLabel("Member brain").selectOption({ label: "operator-demo" });
    await page.getByRole("button", { name: "Add to workspace", exact: true }).click();
    await page.getByLabel("Search workspace brains").fill("retry budget");
    await page.getByRole("button", { name: "Search", exact: true }).last().click();
    await expect(page.getByText(/project brains searched/)).toBeVisible();
    await expect(page.getByText("All members available", { exact: true })).toBeVisible();

    await page.getByRole("tab", { name: "Agent Link", exact: true }).click();
    await page.getByRole("button", { name: "Test MCP connection", exact: true }).click();
    await expect(page.getByText("Connection ready", { exact: true })).toBeVisible();
    await expect(page.getByText(/\d+ tools \/ \d+(?:\.\d+)? ms/)).toBeVisible();
    await page.getByRole("button", { name: "Copy host config", exact: true }).click();
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain("rta-brain-mcp.py");

    await page.getByRole("tab", { name: "Vault", exact: true }).click();
    await page.getByRole("button", { name: "Preview export", exact: true }).click();
    await expect(page.getByText(/Preview ready:/)).toBeVisible();
    await page.getByRole("button", { name: "Export", exact: true }).click();
    await expect(page.getByText("Redacted selective bundle written.", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Generate private key file", exact: true }).click();
    await expect(page.getByText(/Private 256-bit snapshot key created/)).toBeVisible();
    await page.getByRole("button", { name: "Create", exact: true }).last().click();
    await expect(page.getByText("Encrypted private snapshot created.", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(page.getByText("Snapshot authentication and database integrity verified.", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Restore", exact: true }).click();
    await expect(page.getByText(/Verified brain restored to/)).toBeVisible();
    await page.getByRole("button", { name: "Hook on", exact: true }).click();
    await expect(page.getByText(/checkpoint hook installed/)).toBeVisible();
    await page.getByRole("button", { name: "Hook off", exact: true }).click();
    await expect(page.getByText(/checkpoint hook removed/)).toBeVisible();
    await page.getByRole("button", { name: "Run decay", exact: true }).click();
    await expect(page.getByText(/eligible memories conservatively aged/)).toBeVisible();

    let markReloadCognitionStarted;
    const reloadCognitionStarted = new Promise((resolve) => {
      markReloadCognitionStarted = resolve;
    });
    const reloadCognitionGate = new Promise((resolve) => {
      releaseReloadCognition = resolve;
    });
    let heldReloadCognition = false;
    await page.route("**/api/cognition?*", async (route) => {
      if (heldReloadCognition) return route.continue();
      heldReloadCognition = true;
      markReloadCognitionStarted();
      await reloadCognitionGate;
      await route.continue();
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await reloadCognitionStarted;
    await expect(page.getByText("Brain Status: Healthy", { exact: true })).toBeVisible();
    const reloadedNavigation = page.getByRole("navigation", { name: "Operator console navigation" });
    await reloadedNavigation.getByRole("button", { name: "Intelligence", exact: true }).click();
    await page.getByRole("tab", { name: "Workspaces", exact: true }).click();
    await expect(page.getByRole("button", { name: /release-workspace/ })).toBeVisible();
    await page.getByRole("button", { name: "Remove operator-demo", exact: true }).click();
    await expect(page.getByText("0/0 healthy", { exact: true })).toBeVisible();
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Delete workspace", exact: true }).click();
    await expect(page.getByRole("button", { name: /release-workspace/ })).toHaveCount(0);

    await page.evaluate(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText: async () => { throw new Error("permission denied"); } },
      });
      document.execCommand = () => false;
    });
    await page.getByRole("main").getByRole("button", { name: "Copy Command", exact: true }).click();
    await expect(page.getByRole("button", { name: "Copy Failed", exact: true })).toBeVisible();
    const copyFailureStatus = page.locator("footer.statusBar").getByRole("status");
    await expect(copyFailureStatus).toContainText(
      "Copy failed: clipboard permission was denied",
    );
    const reloadCognitionResponse = page.waitForResponse((response) => (
      new URL(response.url()).pathname === "/api/cognition"
    ));
    releaseReloadCognition();
    await reloadCognitionResponse;
    await page.waitForTimeout(100);
    await expect(copyFailureStatus).toContainText("Copy failed: clipboard permission was denied");
    await page.unroute("**/api/cognition?*");
    releaseReloadCognition = undefined;
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByText("Brain Status: Healthy", { exact: true })).toBeVisible();

    expect(errors).toEqual([]);
    const expectedFailureOffset = errors.length;
    const forbidden = await page.evaluate(() => fetch("/api/health").then((response) => response.status));
    expect(forbidden).toBe(403);
    await expect.poll(() => errors.length).toBeGreaterThan(expectedFailureOffset);
    expect(errors.slice(expectedFailureOffset).every((entry) => entry.includes("403") || entry.includes("Forbidden"))).toBe(true);
    errors.length = 0;

    const commandPaletteButton = reloadedNavigation.getByRole("button", { name: "Command Palette", exact: true });
    await commandPaletteButton.click();
    await expect(page.getByRole("dialog", { name: "Command palette" })).toBeVisible();
    await page.keyboard.press("Shift+Tab");
    await expect(page.getByRole("button", { name: "Check Rta-Smriti release", exact: true })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog", { name: "Command palette" })).toHaveCount(0);
    await expect(commandPaletteButton).toBeFocused();

    expect(await unnamedControls(page)).toEqual([]);

    await page.emulateMedia({ reducedMotion: "reduce" });
    await reloadedNavigation.getByRole("button", { name: "Graph", exact: true }).click();
    const animated = await page.locator(".graphCanvas *").evaluateAll((elements) => elements
      .map((element) => ({
        tag: element.tagName,
        className: element.getAttribute("class") || "",
        animationName: getComputedStyle(element).animationName,
        animationDuration: getComputedStyle(element).animationDuration,
      }))
      .filter((value) => value.animationName.split(",").some((name) => name.trim() !== "none")));
    expect(animated).toEqual([]);

    await page.emulateMedia({ reducedMotion: "reduce", forcedColors: "active" });
    await expect(page.getByRole("region", { name: "Interactive project brain graph" })).toBeVisible();
    // Chromium remaps author colors to system colors in this mode; axe cannot
    // resolve that remapping, so contrast remains covered by every normal-mode scan.
    await expectNoAxeViolations(page, "forced-colors Graph", ["color-contrast"]);
    await page.emulateMedia({ reducedMotion: "reduce", forcedColors: "none" });

    await page.setViewportSize({ width: 720, height: 450 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);

    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByText("Brain Status: Healthy", { exact: true })).toBeVisible();
    await reloadedNavigation.getByRole("button", { name: "Graph", exact: true }).click();
    await page.evaluate(() => window.scrollTo(0, 0));
    const mobileToolbarHeight = await page.locator(".stageToolbar").evaluate((toolbar) => toolbar.getBoundingClientRect().height);
    expect(mobileToolbarHeight).toBeLessThanOrEqual(70);
    await captureLaunchScreenshot(page, "operator-console-mobile-v0.6.png");
    await reloadedNavigation.getByRole("button", { name: "Canvas", exact: true }).click();
    const mobileCanvas = page.getByRole("region", { name: "Spatial project canvas" });
    await expect(mobileCanvas.locator(".canvasCard").first()).toBeVisible();
    const overlaps = await mobileCanvas.locator(".canvasCard").evaluateAll((cards) => {
      const rects = cards.map((card) => card.getBoundingClientRect());
      const pairs = [];
      for (let left = 0; left < rects.length; left += 1) {
        for (let right = left + 1; right < rects.length; right += 1) {
          const width = Math.min(rects[left].right, rects[right].right) - Math.max(rects[left].left, rects[right].left);
          const height = Math.min(rects[left].bottom, rects[right].bottom) - Math.max(rects[left].top, rects[right].top);
          if (width > 1 && height > 1) pairs.push([left, right]);
        }
      }
      return pairs;
    });
    expect(overlaps).toEqual([]);
    await mobileCanvas.locator(".canvasCard").first().press("Enter");
    await expect(page.getByRole("heading", { name: "Evidence Inspector", exact: true })).toBeVisible();
    const mobileInspector = page.locator('aside[aria-label="Project detail inspector"]');
    await expect(mobileInspector).toBeFocused();
    await expect(mobileInspector).toBeInViewport();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);

    await page.setViewportSize({ width: 1440, height: 900 });
    await page.getByRole("button", { name: "New Brain", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Bootstrap Brain", exact: true })).toBeVisible();
    await page.getByLabel("Project Folder").fill(bootstrapRepo);
    await page.getByLabel("Project Name").fill("bootstrapped-project");
    let ambiguousBootstrapHealthServed = false;
    await page.route("**/api/bootstrap", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const created = (payload.projects || []).find((project) => project.project === "bootstrapped-project");
      if (!created) {
        await route.fulfill({ response, json: payload });
        return;
      }
      ambiguousBootstrapHealthServed = true;
      const wrongRoot = { ...created, db_path: fixture.database, root_path: fixture.repo, root_conflict: true };
      await route.fulfill({ response, json: { ...payload, projects: [wrongRoot, ...(payload.projects || [])] } });
    });
    await page.getByRole("button", { name: "Set Up & Start", exact: true }).click();
    await expect(page.locator(".miniOutput")).toContainText("Brain ready: bootstrapped-project", { timeout: 30_000 });
    await expect.poll(() => ambiguousBootstrapHealthServed).toBe(true);
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("bootstrapped-project");
    await expect(page.locator(".taskComposer code")).toContainText("bootstrapped-project.sqlite");
    await expect(page.locator(".taskComposer code")).not.toContainText("operator-demo.sqlite");
    await page.unroute("**/api/bootstrap");
    await reloadedNavigation.getByRole("button", { name: "Settings", exact: true }).click();
    const bootstrappedStopSync = page.getByRole("button", { name: "Stop Sync", exact: true });
    if (await bootstrappedStopSync.isVisible()) {
      await bootstrappedStopSync.click();
      await expect(page.getByRole("button", { name: "Start Sync", exact: true })).toBeVisible();
    } else {
      await expect(page.getByRole("button", { name: "Start Sync", exact: true })).toBeVisible();
    }
    await expect(page.getByRole("button", { name: "Start Sync", exact: true })).toHaveAttribute("aria-busy", "false");

    let healthMode = "conflict";
    await page.route("**/api/bootstrap", async (route) => {
      const response = await route.fetch();
      const payload = await response.json();
      const projects = healthMode === "empty"
        ? []
        : (payload.projects || []).map((project) => ({ ...project, root_conflict: true }));
      await route.fulfill({ response, json: { ...payload, projects } });
    });
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("Canonical-root conflict");
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page.getByRole("alert").getByText("Canonical-root conflict.", { exact: true })).toBeVisible();
    await expect(page.getByRole("alert").locator(".rootConflictDetail")).toBeHidden();
    await expect(page.getByRole("alert").getByRole("button", { name: "Review", exact: true })).toBeVisible();
    await page.setViewportSize({ width: 1440, height: 900 });
    healthMode = "empty";
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await page.getByRole("button", { name: /Projects Choose a brain/ }).click();
    await expect(page.getByRole("button", { name: "Bootstrap the first project", exact: true })).toBeVisible();
    await page.unroute("**/api/bootstrap");
    await page.getByRole("button", { name: "Refresh projects", exact: true }).click();
    await expect(page.getByText("Scanning local brains...", { exact: true })).toBeHidden({ timeout: 30_000 });
    await expect(page.getByText("bootstrapped-project", { exact: true }).first()).toBeVisible();
    expect(errors).toEqual([]);
  } finally {
    releaseReloadCognition?.();
    await stopBootstrappedDaemons(tempRoot);
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("failed post-bootstrap identity verification clears the stale project", async ({ browser }) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-bootstrap-failure-qa-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let page;
  let releaseRegistry;
  let markRegistryRequested;
  let releaseProjectDetails;
  let markProjectDetailsRequested;
  const registryReleased = new Promise((resolve) => { releaseRegistry = resolve; });
  const registryRequested = new Promise((resolve) => { markRegistryRequested = resolve; });
  const projectDetailsReleased = new Promise((resolve) => { releaseProjectDetails = resolve; });
  const projectDetailsRequested = new Promise((resolve) => { markProjectDetailsRequested = resolve; });
  try {
    const fixture = await ready;
    const bootstrapRepo = path.join(tempRoot, "bootstrapped-project");
    await mkdir(bootstrapRepo);
    await writeFile(path.join(bootstrapRepo, "README.md"), "# Bootstrapped project\n", "utf8");
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    page = await context.newPage();
    await page.route("**/api/projects", async (route) => {
      markRegistryRequested();
      await registryReleased;
      await route.continue();
    });
    await page.route(/\/api\/cognition\?/, async (route) => {
      markProjectDetailsRequested();
      await projectDetailsReleased;
      await route.continue();
    });
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("operator-demo");
    await registryRequested;
    await projectDetailsRequested;

    await page.getByRole("button", { name: "New Brain", exact: true }).click();
    await page.getByLabel("Project Folder").fill(bootstrapRepo);
    await page.getByLabel("Project Name").fill("bootstrapped-project");
    await page.route("**/api/bootstrap", (route) => {
      if (route.request().method() !== "GET") return route.continue();
      return route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ status: "error", error: { message: "simulated identity verification failure" } }),
      });
    });
    await page.getByRole("button", { name: "Set Up & Start", exact: true }).click();
    await expect(page.locator(".miniOutput")).toContainText("Brain ready: bootstrapped-project", { timeout: 30_000 });
    await expect(page.locator(".miniOutput")).toContainText("VERIFY: Dashboard refresh failed after setup");
    const registryResponse = page.waitForResponse((response) => response.url().includes("/api/projects"));
    releaseRegistry();
    await registryResponse;
    await expect(page.locator(".activeProjectCopy strong")).toHaveText("Choose a brain");
    const projectDetailsResponse = page.waitForResponse((response) => response.url().includes("/api/cognition?"));
    releaseProjectDetails();
    await projectDetailsResponse;
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(page.locator(".statusBar [role='status']")).toContainText("simulated identity verification failure");
  } finally {
    releaseRegistry?.();
    releaseProjectDetails?.();
    await page?.unrouteAll({ behavior: "ignoreErrors" });
    await stopBootstrappedDaemons(tempRoot);
    await context?.close();
    await stopFixtureServer(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
