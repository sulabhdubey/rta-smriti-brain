import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const execute = promisify(execFile);

async function removeFixture(directory) {
  if (path.dirname(path.resolve(directory)) !== path.resolve(os.tmpdir()) || !path.basename(directory).startsWith("rta-pilot-")) throw new Error("Unsafe fixture cleanup path");
  await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "rta-pilot-"));
  const repo = path.join(directory, "pilot-atlas");
  await mkdir(repo);
  await writeFile(path.join(repo, "README.md"), "# Pilot Atlas\nDecisions use UTC timestamps.\n");
  if (process.env.RTA_PILOT_NATIVE) {
    const brains = path.join(directory, "brains");
    const initial = path.join(directory, "operator-demo");
    await mkdir(initial);
    await writeFile(path.join(initial, "README.md"), "# Operator demo\nA synthetic pilot project.\n");
    const run = async args => JSON.parse((await execute(process.env.RTA_PILOT_NATIVE, args, { cwd: directory, windowsHide: true, timeout: 30000 })).stdout);
    let started = false;
    try {
      const setup = await run(["--json", "bootstrap-project", initial, "--project", "operator-demo", "--brain-dir", brains]);
      await run(["console", "start", "--brain-dir", brains, "--db", setup.db_path, "--project", "operator-demo", "--port", "0", "--no-open", "--json"]);
      started = true;
      const opened = await run(["console", "open", "--brain-dir", brains, "--no-open", "--json"]);
      return { url: opened.url, repo, directory, async close() {
        await run(["console", "stop", "--brain-dir", brains, "--json"]);
        await removeFixture(directory);
      } };
    } catch (error) {
      if (started) await run(["console", "stop", "--brain-dir", brains, "--json"]);
      throw error;
    }
  }
  const child = spawn(process.env.PYTHON || (process.platform === "win32" ? "python" : "python3"),
    [path.join(root, "scripts/operator_qa_server.py"), directory],
    { cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, PYTHONUNBUFFERED: "1" } });
  try {
    const info = await new Promise((resolve, reject) => {
      let output = "", errors = "";
      const timer = setTimeout(() => reject(new Error(`Fixture timeout: ${errors}`)), 30000);
      child.stderr.on("data", chunk => { errors += chunk; });
      child.stdout.on("data", chunk => {
        output += chunk;
        const line = output.split(/\r?\n/).find(value => value.startsWith("{"));
        if (line) { clearTimeout(timer); resolve(JSON.parse(line)); }
      });
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("exit", code => { clearTimeout(timer); reject(new Error(`Fixture exited ${code}: ${errors}`)); });
    });
    return { ...info, repo, directory, async close() {
      if (child.exitCode === null) {
        const exited = new Promise(resolve => child.once("exit", resolve));
        child.kill();
        await exited;
      }
      await removeFixture(directory);
    } };
  } catch (error) { child.kill(); throw error; }
}

test("pilot operator saves and recovers a decision in a new browser session", async ({ browser }) => {
  const f = await fixture();
  let context;
  try {
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    let page = await context.newPage();
    await page.goto(f.url);
    await page.getByRole("button", { name: /^Projects / }).click();
    await page.getByRole("button", { name: "Add project brain", exact: true }).click({ timeout: 10000 });
    await expect(page.getByRole("heading", { name: "First project", exact: true })).toBeVisible();
    await expect(page.getByLabel("Capture Codex sessions for this project")).not.toBeChecked();
    await expect(page.getByLabel("Run capture normalization")).not.toBeChecked();
    await page.getByLabel("Project Folder").fill(f.repo);
    await page.getByLabel("Keep repository index current").uncheck();
    await page.getByRole("button", { name: "Set Up & Start", exact: true }).click();
    await expect(page.getByText("Local project ready", { exact: true })).toBeVisible({ timeout: 30000 });
    await expect(page.getByText("Host activation unverified", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Test local MCP server", exact: true }).click();
    await expect(page.getByText("Local MCP server reachable", { exact: true })).toBeVisible({ timeout: 20000 });
    await expect(page.getByText("Host activation unverified", { exact: true })).toBeVisible();
    const decision = "Pilot Atlas uses UTC timestamps for every decision.";
    await page.getByLabel("Decision to remember").fill(decision);
    await page.getByRole("button", { name: "Save decision", exact: true }).click();
    await expect(page.getByText("Saved as an unverified operator decision", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Recover decision", exact: true }).click();
    await expect(page.getByText("Saved decision recovered", { exact: true })).toBeVisible();
    await expect(page.getByText("Read-only recovery", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Build context pack", exact: true }).click();
    await expect(page.getByRole("button", { name: "Copy context pack", exact: true })).toBeVisible();
    await expect(page.locator(".emptyGraph")).toBeVisible();
    await expect(page.locator(".projectCore")).toHaveCount(0);
    await expect(page.locator(".emptyGraph")).not.toContainText("Enable at least one graph type");
    const violations = (await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze()).violations;
    expect(violations).toEqual([]);
    if (process.env.RTA_PILOT_SCREENSHOT_DIR) {
      await page.screenshot({ path: path.join(process.env.RTA_PILOT_SCREENSHOT_DIR, "pilot-desktop.png") });
    }
    expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain(decision);
    await context.close();
    context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    page = await context.newPage();
    await page.goto(f.url);
    await page.getByRole("button", { name: /^Projects / }).click();
    await page.getByRole("button", { name: /^pilot-atlas, / }).click();
    await page.getByRole("button", { name: /^Projects / }).click();
    await page.getByRole("button", { name: "Add project brain", exact: true }).click({ timeout: 10000 });
    await page.getByRole("button", { name: "Use selected project", exact: true }).click();
    await page.getByLabel("Recovery query").fill("Pilot Atlas UTC timestamps");
    await page.getByRole("button", { name: "Recover decision", exact: true }).click();
    await expect(page.getByText(decision, { exact: true })).toBeVisible();
    await expect(page.getByText("Read-only recovery", { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (process.env.RTA_PILOT_SCREENSHOT_DIR) {
      await page.screenshot({ path: path.join(process.env.RTA_PILOT_SCREENSHOT_DIR, "pilot-mobile.png") });
    }
  } finally { try { await context?.close(); } finally { await f.close(); } }
});

test("pilot operations reject duplicate saves and show retrieval failures", async ({ page }) => {
  const f = await fixture();
  try {
    await page.goto(f.url);
    await page.getByRole("button", { name: "New Brain", exact: true }).click();
    await page.getByRole("button", { name: "Use selected project", exact: true }).click();
    await page.getByLabel("Decision to remember").fill("One explicit pilot decision.");
    let requests = 0;
    await page.route("**/api/memory", async route => {
      requests += 1;
      await new Promise(resolve => setTimeout(resolve, 150));
      await route.continue();
    });
    await page.getByRole("button", { name: "Save decision", exact: true }).evaluate(button => { button.click(); button.click(); });
    await expect(page.getByText("Saved as an unverified operator decision", { exact: true })).toBeVisible();
    expect(requests).toBe(1);
    await page.route("**/api/search", route => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { message: "Recovery temporarily unavailable" } }) }));
    await page.getByRole("button", { name: "Recover decision", exact: true }).click();
    await expect(page.locator(".pilotError")).toContainText("Recovery temporarily unavailable");
    await expect(page.getByText("Saved decision recovered", { exact: true })).toBeHidden();
    await expect(page.getByRole("button", { name: "Recover decision", exact: true })).toBeEnabled();
  } finally { await f.close(); }
});

test("pilot setup failures stay actionable and empty recovery is not success", async ({ page }) => {
  const f = await fixture();
  try {
    await page.goto(f.url);
    await page.getByRole("button", { name: /^Projects / }).click();
    await page.getByRole("button", { name: "Add project brain", exact: true }).click({ timeout: 10000 });
    await page.getByLabel("Project Folder").fill(path.join(f.directory, "missing"));
    await page.getByRole("button", { name: "Set Up & Start", exact: true }).click();
    await expect(page.locator(".pilotError")).toBeVisible();
    await expect(page.getByText("Local project ready", { exact: true })).toBeHidden();
    await page.getByRole("button", { name: "Use selected project", exact: true }).click();
    await page.getByLabel("Recovery query").fill("nonexistent-quartz-pilot-claim");
    await page.getByRole("button", { name: "Recover decision", exact: true }).click();
    await expect(page.getByText("No matching decision recovered", { exact: true })).toBeVisible();
    await expect(page.getByText("Saved decision recovered", { exact: true })).toBeHidden();
  } finally { await f.close(); }
});
