import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "rta-passport-"));
  const child = spawn(process.env.PYTHON || "python", ["scripts/operator_qa_server.py", directory], {
    windowsHide: true, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });
  const close = async () => {
    if (child.exitCode === null) { const ended = new Promise(resolve => child.once("exit", resolve)); child.kill(); await ended; }
    if (path.dirname(path.resolve(directory)) !== path.resolve(os.tmpdir()) || !path.basename(directory).startsWith("rta-passport-")) throw new Error("Unsafe cleanup");
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  };
  try {
    const info = await new Promise((resolve, reject) => {
      let stdout = "", stderr = "";
      const timer = setTimeout(() => reject(new Error(stderr || "Fixture timeout")), 30000);
      child.stderr.on("data", data => { stderr += data; });
      child.stdout.on("data", data => {
        stdout += data;
        const line = stdout.split(/\r?\n/).find(s => s.startsWith("{"));
        if (line) { clearTimeout(timer); resolve(JSON.parse(line)); }
      });
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("exit", code => { clearTimeout(timer); reject(new Error(`Fixture exited ${code}: ${stderr}`)); });
    });
    return { ...info, close };
  } catch (error) { await close(); throw error; }
}

for (const width of [1440, 390]) {
  test(`Passport saves, recovers and exports selected evidence at ${width}px`, async ({ browser }) => {
    const f = await fixture();
    const context = await browser.newContext({ viewport: { width, height: 960 }, reducedMotion: "reduce" });
    try {
      const page = await context.newPage();
      const errors = [];
      page.on("pageerror", e => errors.push(e.message));
      const url = new URL(f.url); url.searchParams.set("view", "passport");
      await page.goto(url.href);
      const passport = page.getByRole("region", { name: "Project Passport", exact: true });
      await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("Validate the queue release");
      await passport.getByLabel("Objective", { exact: true }).fill("Ship a reliable timestamp migration");
      await passport.getByLabel("Next action", { exact: true }).fill("Run UTC boundary tests");
      await passport.getByRole("button", { name: "Save checkpoint", exact: true }).click();
      await expect(passport.getByRole("status")).toContainText("Checkpoint saved");
      await page.reload();
      await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("Ship a reliable timestamp migration");
      await passport.getByRole("tab", { name: "Decisions", exact: true }).click();
      await passport.getByLabel("Decision and reason").fill("Use UTC because customers work across time zones.");
      await passport.getByRole("button", { name: "Save decision", exact: true }).click();
      await expect(passport.getByRole("status")).toContainText("Decision saved");
      await expect(passport.getByText("Use UTC because customers work across time zones.", { exact: true })).toBeVisible();
      await passport.getByRole("tab", { name: "Changes", exact: true }).click();
      await expect(passport.getByText(/Deletions, unindexed edits/)).toBeVisible();
      await passport.getByRole("tab", { name: "Handoff", exact: true }).click();
      await expect(passport.getByRole("button", { name: "Preview handoff", exact: true })).toBeDisabled();
      await passport.getByLabel("Export label").fill("Client workspace");
      await passport.getByLabel("Include next action", { exact: true }).check();
      await passport.getByRole("button", { name: "Preview handoff", exact: true }).click();
      await expect(passport.getByLabel("Handoff preview")).toContainText("Run UTC boundary tests");
      await expect(passport.getByLabel("Handoff preview")).not.toContainText("Ship a reliable timestamp migration");
      await expect(passport.getByRole("button", { name: "Download JSON", exact: true })).toBeDisabled();
      await passport.getByLabel("I reviewed this handoff for sensitive information").check();
      const downloaded = page.waitForEvent("download");
      await passport.getByRole("button", { name: "Download JSON", exact: true }).click();
      const file = await downloaded;
      const bytes = await readFile(await file.path());
      const document = JSON.parse(bytes.toString("utf8"));
      expect(document.project_label).toBe("Client workspace");
      expect(document.checkpoint).toEqual({ next_action: "Run UTC boundary tests" });
      expect(document.decisions).toEqual([]);
      await passport.getByText("JSON checksum (SHA-256, not a signature)", { exact: true }).click();
      await expect(passport.getByText(createHash("sha256").update(bytes).digest("hex"), { exact: true })).toBeVisible();
      const markdownDownload = page.waitForEvent("download");
      await passport.getByRole("button", { name: "Download Markdown", exact: true }).click();
      const markdownBytes = await readFile(await (await markdownDownload).path());
      expect(markdownBytes.toString("utf8")).toBe(await passport.getByLabel("Handoff preview").textContent());
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await passport.getByRole("button", { name: "Copy handoff", exact: true }).click();
      await expect(passport.getByRole("status")).toContainText("Handoff copied");
      // Windows text clipboards normalize newlines; downloaded bytes remain exact.
      expect((await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, "\n")).toBe(markdownBytes.toString("utf8"));
      await page.evaluate(() => { navigator.clipboard.writeText = async () => { throw new Error("Clipboard denied"); }; });
      await passport.getByRole("button", { name: "Copy handoff", exact: true }).click();
      await expect(passport.getByRole("alert")).toContainText("Clipboard denied");
      await passport.getByRole("button", { name: "Preview handoff", exact: true }).click();
      await passport.getByLabel("I reviewed this handoff for sensitive information").check();
      expect((await new AxeBuilder({ page }).include(".projectPassport").analyze()).violations).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
      expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain("Run UTC boundary tests");
      expect(errors).toEqual([]);
      await page.screenshot({ path: `output/project-passport/passport-${width}.png`, fullPage: true });
      for (const section of ["Resume", "Changes", "Decisions"]) {
        await passport.getByRole("tab", { name: section, exact: true }).click();
        expect((await new AxeBuilder({ page }).include(".projectPassport").analyze()).violations).toEqual([]);
        await page.screenshot({ path: `output/project-passport/passport-${section.toLowerCase()}-${width}.png`, fullPage: true });
      }
    } finally { await context.close(); await f.close(); }
  });
}

test("Passport preserves drafts on failed save and retries failed reads", async ({ page }) => {
  const f = await fixture();
  try {
    const url = new URL(f.url); url.searchParams.set("view", "passport");
    await page.route("**/api/passport", route => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { message: "Temporary read failure" } }) }));
    await page.goto(url.href);
    const passport = page.getByRole("region", { name: "Project Passport", exact: true });
    await expect(passport.getByRole("alert")).toContainText("Temporary read failure");
    await page.unroute("**/api/passport");
    await passport.getByRole("button", { name: "Refresh Passport", exact: true }).click();
    await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("Validate the queue release");
    await page.route("**/api/checkpoint", route => route.fulfill({ status: 400, contentType: "application/json", body: JSON.stringify({ error: { message: "checkpoint version conflict" } }) }));
    await passport.getByLabel("Objective", { exact: true }).fill("Keep my unsaved plan");
    await passport.getByRole("button", { name: "Save checkpoint", exact: true }).click();
    await expect(passport.getByRole("alert")).toContainText("version conflict");
    await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("Keep my unsaved plan");
  } finally { await f.close(); }
});

test("Passport preserves a draft while recording a decision and rejects concurrent checkpoint edits", async ({ page }) => {
  const f = await fixture();
  try {
    const url = new URL(f.url); url.searchParams.set("view", "passport");
    await page.goto(url.href);
    const passport = page.getByRole("region", { name: "Project Passport", exact: true });
    await passport.getByLabel("Objective", { exact: true }).fill("My unsaved checkpoint");
    const token = new URL(f.url).hash.slice(1).split("token=")[1];
    const posted = await page.request.post(new URL("/api/checkpoint", url).href, { headers: { "X-Rta-Smriti-Token": decodeURIComponent(token) }, data: { db_path: f.database, project: "operator-demo", objective: "Another operator's checkpoint", expected_version: 1 } });
    expect(posted.ok()).toBe(true);
    await passport.getByRole("tab", { name: "Decisions", exact: true }).click();
    await passport.getByLabel("Decision and reason").fill("Keep decisions separate from checkpoint drafts.");
    await passport.getByRole("button", { name: "Save decision", exact: true }).click();
    await expect(passport.getByRole("status")).toContainText("Decision saved");
    await passport.getByRole("tab", { name: "Resume", exact: true }).click();
    await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("My unsaved checkpoint");
    await passport.getByRole("button", { name: "Save checkpoint", exact: true }).click();
    await expect(passport.getByRole("alert")).toContainText("version conflict");
    page.once("dialog", dialog => dialog.accept());
    await passport.getByRole("button", { name: "Refresh Passport", exact: true }).click();
    await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("Another operator's checkpoint");
    await passport.getByRole("tab", { name: "Resume", exact: true }).focus();
    await page.keyboard.press("ArrowRight");
    await expect(passport.getByRole("tab", { name: "Changes", exact: true })).toBeFocused();
  } finally { await f.close(); }
});

test("Passport first-project setup is opt-in and switching clears handoff selection", async ({ page }) => {
  const f = await fixture();
  try {
    const second = path.join(path.dirname(f.repo), "second-project");
    await mkdir(second);
    await writeFile(path.join(second, "README.md"), "# Second project\nA fictional client brief.\n");
    const url = new URL(f.url); url.searchParams.set("view", "passport");
    await page.goto(url.href);
    const passport = page.getByRole("region", { name: "Project Passport", exact: true });
    await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("Validate the queue release");
    await passport.getByRole("tab", { name: "Handoff", exact: true }).click();
    await passport.getByLabel("Include objective", { exact: true }).check();
    await page.getByRole("button", { name: "Add project", exact: true }).click();
    await page.getByLabel("Project folder", { exact: true }).fill(second);
    await page.getByLabel("Project name (optional)").fill("second-project");
    await expect(page.getByLabel("Keep this folder indexed automatically")).not.toBeChecked();
    await expect(page.getByLabel("Allow local capture of matching Codex sessions, including their text")).not.toBeChecked();
    const setupRequest = page.waitForRequest(request => request.url().endsWith("/api/bootstrap") && request.method() === "POST");
    await page.getByRole("button", { name: "Create project", exact: true }).click();
    const body = (await setupRequest).postDataJSON();
    expect(body.start_sync).toBe(false);
    expect(body.start_universal_capture).toBe(false);
    expect(body.start_continuity_capture).toBe(false);
    expect(body.write_agents).toBe(false);
    await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("");
    await passport.getByRole("tab", { name: "Handoff", exact: true }).click();
    await expect(passport.getByLabel("Include objective", { exact: true })).not.toBeChecked();
    await expect(passport.getByLabel("Include objective", { exact: true })).toBeDisabled();
    await page.getByRole("combobox", { name: "Project", exact: true }).selectOption({ label: "operator-demo" });
    await expect(passport.getByLabel("Objective", { exact: true })).toHaveValue("Validate the queue release");
    await passport.getByRole("tab", { name: "Handoff", exact: true }).click();
    await expect(passport.getByLabel("Include objective", { exact: true })).not.toBeChecked();
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  } finally { await f.close(); }
});

test("Passport rejects a stale handoff at download time and refreshes changed source", async ({ page }) => {
  const f = await fixture();
  try {
    const url = new URL(f.url); url.searchParams.set("view", "passport");
    await page.goto(url.href);
    const passport = page.getByRole("region", { name: "Project Passport", exact: true });
    await passport.getByRole("tab", { name: "Handoff", exact: true }).click();
    await passport.getByLabel("Include next action", { exact: true }).check();
    await passport.getByRole("button", { name: "Preview handoff", exact: true }).click();
    await passport.getByLabel("I reviewed this handoff for sensitive information").check();
    await page.route("**/api/passport", route => route.fulfill({ status: 400, contentType: "application/json", body: JSON.stringify({ error: { message: "project changed; refresh Passport" } }) }));
    let downloaded = false;
    page.on("download", () => { downloaded = true; });
    await passport.getByRole("button", { name: "Download JSON", exact: true }).click();
    await expect(passport.getByRole("alert")).toContainText("project changed");
    await expect(passport.getByLabel("Handoff preview")).toHaveCount(0);
    expect(downloaded).toBe(false);
    await page.unroute("**/api/passport");
    await writeFile(path.join(f.repo, "README.md"), "# Operator demo\nThe launch date changed.\n");
    await passport.getByRole("tab", { name: "Changes", exact: true }).click();
    await passport.getByRole("button", { name: "Refresh folder index", exact: true }).click();
    await expect(passport.getByRole("status")).toContainText("Folder index refreshed");
    await expect(passport.getByText("README.md", { exact: true })).toBeVisible();
  } finally { await f.close(); }
});

test("Passport explains expired authorization and uncertain decision saves", async ({ page }) => {
  const f = await fixture();
  try {
    const url = new URL(f.url); url.searchParams.set("view", "passport");
    await page.route("**/api/passport", route => route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: { type: "Forbidden", message: "valid local capability required" } }) }));
    await page.goto(url.href);
    const passport = page.getByRole("region", { name: "Project Passport", exact: true });
    await expect(passport.getByRole("alert")).toContainText("private console URL");
    await page.unroute("**/api/passport");
    await page.goto("about:blank");
    await page.goto(url.href);
    await passport.getByRole("tab", { name: "Decisions", exact: true }).click();
    await passport.getByLabel("Decision and reason").fill("Preserve this draft when the save acknowledgement is missing.");
    await page.route("**/api/memory", route => route.abort("failed"));
    await passport.getByRole("button", { name: "Save decision", exact: true }).click();
    await expect(passport.getByRole("alert")).toContainText("may have been saved");
    await expect(passport.getByLabel("Decision and reason")).toHaveValue("Preserve this draft when the save acknowledgement is missing.");
  } finally { await f.close(); }
});
