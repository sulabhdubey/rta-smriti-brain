import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { spawn } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
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
    const timer = setTimeout(() => reject(new Error(`capture fixture timed out: ${stderr}`)), 30_000);
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

async function axe(page, label) {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(result.violations.map((item) => ({ id: item.id, targets: item.nodes.map((node) => node.target) })), label).toEqual([]);
}

test("operator can govern, replay, recover, and delete captured continuity", async ({ browser }) => {
  test.setTimeout(120_000);
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "rta-capture-operator-"));
  const { child, ready } = startFixtureServer(tempRoot);
  let context;
  let fixture;
  let token;
  let permissionProbeActive = false;
  let permissionDenials = 0;
  const consoleFailures = [];
  try {
    fixture = await ready;
    token = new URL(fixture.url).hash.replace(/^#token=/, "");
    const captureQuery = new URLSearchParams({
      db_path: fixture.database,
      project: "operator-demo",
      mode: "replay",
      replay_mode: "chronological",
      limit: "100",
    });
    const captured = await fetch(`${new URL(fixture.url).origin}/api/capture?${captureQuery}`, {
      headers: { "X-Rta-Smriti-Token": token },
    }).then((response) => response.json());
    const eventId = captured.events[0].event_id;

    context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      permissions: ["clipboard-read", "clipboard-write"],
      acceptDownloads: true,
    });
    const page = await context.newPage();
    page.on("pageerror", (error) => consoleFailures.push(`pageerror: ${error.message}`));
    page.on("console", (message) => {
      if (!["error", "warning"].includes(message.type())) return;
      if (permissionProbeActive && message.type() === "error" && message.text().includes("403 (Forbidden)")) {
        permissionDenials += 1;
        return;
      }
      consoleFailures.push(`${message.type()}: ${message.text()}`);
    });
    await page.goto(fixture.url, { waitUntil: "domcontentloaded" });
    const navigation = page.getByRole("navigation", { name: "Operator console navigation" });
    await navigation.getByRole("button", { name: /^Capture/ }).click();
    await expect(page.getByRole("region", { name: "Universal capture console" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Agent Flight Recorder", exact: true })).toBeVisible();
    await expect(page.getByText("interrupted", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Gaps", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: /Inspect event 2: capture gap/ })).toBeVisible();
    expect(await page.locator(".captureEvent").count()).toBeLessThanOrEqual(28);

    const inspected = page.getByRole("button", { name: /Inspect event 3: turn interrupted/ });
    await inspected.focus();
    await inspected.press("Enter");
    await expect(page.getByRole("article", { name: "Captured event detail" })).toBeVisible();
    await page.getByRole("button", { name: "Back to timeline", exact: true }).click();
    await expect(inspected).toBeFocused();

    await page.getByRole("button", { name: "Causal", exact: true }).click();
    await expect(page.getByRole("button", { name: "Causal", exact: true })).toHaveAttribute("aria-pressed", "true");
    const timelineTab = page.getByRole("tab", { name: "timeline", exact: true });
    await timelineTab.focus();
    await timelineTab.press("ArrowRight");
    await expect(page.getByRole("tab", { name: "sources", exact: true })).toBeFocused();
    await expect(page.getByRole("tab", { name: "sources", exact: true })).toHaveAttribute("aria-selected", "true");

    const pause = page.getByRole("button", { name: "Pause codex-operator", exact: true });
    await pause.click();
    await expect(page.getByRole("button", { name: "Resume codex-operator", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Resume codex-operator", exact: true }).click();
    await expect(page.getByRole("button", { name: "Pause codex-operator", exact: true })).toBeVisible();
    await page.getByLabel("Session ID").fill("rendered-operator-session");
    await page.getByLabel("Start cursor").fill("3");
    await page.getByRole("button", { name: "Bind session", exact: true }).click();
    await expect(page.getByText("Binding active", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Close binding", exact: true }).click();
    await expect(page.getByText("Binding active", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Preview policy", exact: true }).click();
    await expect(page.getByText("No state written", { exact: true })).toBeVisible();

    await page.getByRole("tab", { name: "privacy", exact: true }).click();
    await page.getByLabel("Privacy ceiling").selectOption("internal");
    await page.getByRole("button", { name: "Preview redaction", exact: true }).click();
    await expect(page.getByText("Redaction verified", { exact: true })).toBeVisible();
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export JSON", exact: true }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("operator-demo-capture.json");
    const downloadPath = await download.path();
    const exported = JSON.parse(await readFile(downloadPath, "utf8"));
    const exportedText = JSON.stringify(exported);
    expect(exported.schema_version).toBe("rta-smriti.capture-export/v1");
    expect(exported.redaction_verified).toBe(true);
    expect(exported.journal_verified).toBe(true);
    expect(exported.payloads_included).toBe(false);
    expect(exported.events.length).toBeGreaterThan(0);
    expect(exportedText).not.toContain("payload_blob");
    expect(exportedText).not.toContain(fixture.repo);
    expect(exportedText).not.toMatch(/AIza[A-Za-z0-9_-]{35}/);
    expect(exportedText).not.toMatch(/(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/);
    await page.getByRole("button", { name: "Run retention", exact: true }).click();
    await expect(page.getByText("Retention preview", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Confirm retention", exact: true }).click();
    await expect(page.locator("footer.statusBar").getByRole("status")).toContainText("Retention policy applied");
    await page.getByLabel("Scope identifier").fill(eventId);
    await page.getByRole("button", { name: "Preview deletion", exact: true }).click();
    await expect(page.getByText(/events affected/)).toBeVisible();
    await page.getByRole("button", { name: "Confirm delete", exact: true }).click();
    await expect(page.locator("footer.statusBar").getByRole("status")).toContainText("logically deleted");

    await page.getByRole("tab", { name: "diagnostics", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Journal integrity verified", exact: true })).toBeVisible();
    await expect(page.getByText("Replay is read-only.", { exact: true })).toBeVisible();
    await axe(page, "capture diagnostics");

    const serviceButton = page.getByRole("button", { name: "Start", exact: true });
    if (await serviceButton.isVisible()) {
      let releaseServiceRefresh;
      let markServiceStarted;
      let holdServiceRefresh = false;
      const serviceRefreshHeld = new Promise((resolve) => { releaseServiceRefresh = resolve; });
      const serviceStarted = new Promise((resolve) => { markServiceStarted = resolve; });
      await page.route("**/api/capture*", async (route) => {
        const request = route.request();
        if (request.method() === "POST") {
          const payload = request.postDataJSON();
          if (payload?.action === "daemon-start") {
            const response = await route.fetch();
            const body = await response.json();
            expect(body.state).toBe("running");
            holdServiceRefresh = true;
            markServiceStarted();
            return route.fulfill({ response, contentType: "application/json", body: JSON.stringify(body) });
          }
        }
        if (holdServiceRefresh && request.method() === "GET") await serviceRefreshHeld;
        return route.continue();
      });
      await serviceButton.click();
      await serviceStarted;
      try {
        await expect(page.getByText("running", { exact: true }).first()).toBeVisible({ timeout: 3_000 });
      } finally {
        holdServiceRefresh = false;
        releaseServiceRefresh();
      }
      await expect(page.getByRole("button", { name: "Stop", exact: true })).toBeEnabled({ timeout: 15_000 });
      await page.unroute("**/api/capture*");
      await page.getByRole("button", { name: "Stop", exact: true }).click();
      await expect(page.getByText("stopped", { exact: true }).first()).toBeVisible({ timeout: 15_000 });
    }

    await page.getByRole("tab", { name: "timeline", exact: true }).click();
    let releaseEmptyReplay;
    let markReplayRequested;
    const emptyReplayHeld = new Promise((resolve) => { releaseEmptyReplay = resolve; });
    const replayRequested = new Promise((resolve) => { markReplayRequested = resolve; });
    await page.route("**/api/capture?*", async (route) => {
      const url = new URL(route.request().url());
      if (url.searchParams.get("mode") !== "replay") return route.continue();
      markReplayRequested();
      await emptyReplayHeld;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ events: [], coverage: {}, interruption_snapshot: { status: "clear" }, executes_actions: false }),
      });
    });
    await page.getByRole("button", { name: "Refresh capture state", exact: true }).click();
    await replayRequested;
    await expect(page.getByRole("region", { name: "Universal capture console" })).toHaveAttribute("aria-busy", "true");
    releaseEmptyReplay();
    await expect(page.getByText("No captured activity yet", { exact: true })).toBeVisible();
    await page.unroute("**/api/capture?*");
    await page.getByRole("tab", { name: "privacy", exact: true }).click();
    await page.getByLabel("Privacy ceiling").selectOption("internal");
    await page.getByRole("tab", { name: "timeline", exact: true }).click();
    await expect(page.getByRole("button", { name: /Inspect event/ }).first()).toBeVisible();

    let denied = true;
    await page.route("**/api/capture?*", async (route) => {
      if (!denied) return route.continue();
      denied = false;
      return route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: { message: "operator capability expired" } }) });
    });
    permissionProbeActive = true;
    await page.getByRole("button", { name: "Refresh capture state", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("operator capability expired");
    await page.unroute("**/api/capture?*");
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Inspect event/ }).first()).toBeVisible();
    permissionProbeActive = false;
    expect(permissionDenials).toBe(1);

    for (const viewport of [
      { width: 1206, height: 816 },
      { width: 768, height: 1024 },
      { width: 390, height: 844 },
    ]) {
      await page.setViewportSize(viewport);
      await expect(page.getByRole("region", { name: "Universal capture console" })).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `${viewport.width}x${viewport.height} horizontal overflow`).toBeLessThanOrEqual(1);
      await page.screenshot({ path: path.join(tempRoot, `capture-${viewport.width}x${viewport.height}.png`), animations: "disabled" });
    }

    await page.setViewportSize({ width: 1440, height: 900 });
    await page.evaluate(() => { document.documentElement.style.zoom = "2"; });
    await expect(page.getByRole("heading", { name: "Agent Flight Recorder", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
    await page.evaluate(() => { document.documentElement.style.zoom = ""; });
    await page.emulateMedia({ reducedMotion: "reduce" });
    expect(await page.locator(".captureWorkspace *").evaluateAll((elements) => elements.filter((element) => {
      const style = getComputedStyle(element);
      return style.animationName !== "none" || style.transitionDuration !== "0s";
    }).length)).toBe(0);
    expect(consoleFailures).toEqual([]);
  } finally {
    if (fixture && token) {
      await fetch(`${new URL(fixture.url).origin}/api/capture`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Origin": new URL(fixture.url).origin,
          "X-Rta-Smriti-Token": token,
        },
        body: JSON.stringify({
          action: "daemon-stop",
          db_path: fixture.database,
          project: "operator-demo",
        }),
      }).catch(() => {});
    }
    await context?.close();
    await stopProcess(child);
  }
});
