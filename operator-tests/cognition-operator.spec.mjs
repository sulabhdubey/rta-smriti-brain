import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
    const timer = setTimeout(() => reject(new Error(`cognition fixture timed out: ${stderr}`)), 30_000);
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

async function post(origin, token, pathName, body) {
  const response = await fetch(`${origin}${pathName}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: origin,
      "X-Rta-Smriti-Token": token,
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(JSON.stringify(payload));
  return payload;
}

test("operator can inspect and reconcile project reality without losing provenance", async ({ browser }) => {
  test.setTimeout(120_000);
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-cognition-operator-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  try {
    const fixture = await ready;
    const origin = new URL(fixture.url).origin;
    const token = new URL(fixture.url).hash.replace(/^#token=/, "");
    await writeFile(path.join(fixture.repo, "proof.png"), Buffer.from("89504e470d0a1a0a66697874757265", "hex"));
    await post(origin, token, "/api/cognition", {
      db_path: fixture.database,
      project: "operator-demo",
      action: "observe",
      observation_id: "release-reality",
      subsystem: "release",
      entity_key: "candidate-state",
      expected_state: "qualified",
      observed_state: "awaiting operator review",
      status: "conflicting",
      source_identifier: "operator-fixture",
      evidence: { command: "fixture-observation" },
    });

    context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      acceptDownloads: true,
    });
    const page = await context.newPage();
    const failures = [];
    page.on("pageerror", (error) => failures.push(`pageerror: ${error.message}`));
    page.on("console", (message) => {
      if (["error", "warning"].includes(message.type())) failures.push(`${message.type()}: ${message.text()}`);
    });
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    const navigation = page.getByRole("navigation", { name: "Operator console navigation" });
    const cognitionStartedAt = Date.now();
    await navigation.getByRole("button", { name: /^Project Reality/ }).click();
    const cockpit = page.getByRole("region", { name: "Project cognition cockpit" });
    await expect(cockpit).toBeVisible();
    await expect(cockpit.getByRole("heading", { name: "Project Reality", exact: true })).toBeVisible();
    expect(Date.now() - cognitionStartedAt).toBeLessThanOrEqual(2_000);
    await expect(cockpit.getByText("Readiness", { exact: true })).toBeVisible();

    await cockpit.getByRole("button", { name: "Project Twin", exact: true }).click();
    const observation = cockpit.getByRole("listitem").filter({ hasText: "candidate-state" });
    await expect(observation).toBeVisible();
    await observation.getByRole("button").click();
    await cockpit.getByLabel("Status").selectOption("observed");
    await cockpit.getByLabel("Reason").fill("Operator verified the release fixture state.");
    await cockpit.getByRole("button", { name: "Apply reconciliation", exact: true }).click();
    await expect(page.locator("footer.statusBar").getByRole("status")).toContainText("reconciled as observed");
    await expect(observation.getByText("observed", { exact: true })).toBeVisible();

    await cockpit.getByRole("button", { name: "Coverage", exact: true }).click();
    await expect(cockpit.getByRole("table", { name: "Knowledge coverage by subsystem" })).toBeVisible();
    await cockpit.getByRole("button", { name: "Change Impact", exact: true }).click();
    await expect(cockpit.getByText(/working-tree impact|changed paths/i).first()).toBeVisible();

    await cockpit.getByRole("button", { name: "Media", exact: true }).click();
    await cockpit.getByLabel("Project-relative source").fill("proof.png");
    await cockpit.getByLabel("Privacy").selectOption("public");
    await cockpit.getByRole("button", { name: "Add source", exact: true }).click();
    const mediaRow = cockpit.getByRole("listitem").filter({ hasText: "proof.png" });
    await expect(mediaRow).toBeVisible();
    await mediaRow.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(mediaRow.getByText("current", { exact: true })).toBeVisible();
    const downloadPromise = page.waitForEvent("download");
    await cockpit.getByRole("button", { name: "Export manifest", exact: true }).click();
    const download = await downloadPromise;
    const exported = JSON.parse(await readFile(await download.path(), "utf8"));
    expect(exported.items).toHaveLength(1);
    expect(JSON.stringify(exported)).not.toContain(fixture.repo);

    const axe = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(axe.violations.map((item) => item.id)).toEqual([]);

    for (const viewport of [
      { width: 1206, height: 816 },
      { width: 768, height: 1024 },
      { width: 390, height: 844 },
    ]) {
      await page.setViewportSize(viewport);
      await expect(cockpit).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
    }
    await page.emulateMedia({ reducedMotion: "reduce" });
    expect(await cockpit.locator("*").evaluateAll((elements) => elements.filter((element) => {
      const style = getComputedStyle(element);
      return style.animationName !== "none" || style.transitionDuration !== "0s";
    }).length)).toBe(0);
    expect(failures).toEqual([]);
  } finally {
    await context?.close();
    await stopProcess(child);
    await rm(tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});
