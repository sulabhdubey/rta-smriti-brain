import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const baseUrl = process.env.RTA_DEMO_CONSOLE_URL;
const token = process.env.RTA_DEMO_CONSOLE_TOKEN;
const demoProject = process.env.RTA_DEMO_PROJECT || "rta-smriti-demo";
const captureLegacyViews = process.env.RTA_CAPTURE_LEGACY_VIEWS !== "0";
const demoDbPath = process.env.RTA_DEMO_DB_PATH || "";
const outputDir = process.env.RTA_SCREENSHOT_OUTPUT_DIR
  ? path.resolve(process.env.RTA_SCREENSHOT_OUTPUT_DIR)
  : path.join(root, "launch-assets", "screenshots");

if (!baseUrl || !token) {
  throw new Error("RTA_DEMO_CONSOLE_URL and RTA_DEMO_CONSOLE_TOKEN are required");
}

await mkdir(outputDir, { recursive: true });

const browser = await chromium.launch();
const errors = [];

async function seedProjectReality() {
  if (!demoDbPath) return;
  const origin = new URL(baseUrl).origin;
  const response = await fetch(`${origin}/api/cognition`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: origin,
      "X-Rta-Smriti-Token": token,
    },
    body: JSON.stringify({
      db_path: demoDbPath,
      project: demoProject,
      action: "observe",
      observation_id: "public-v1.0.2-release-verified",
      subsystem: "release",
      entity_key: "v1.0.2-release-state",
      expected_state: "published and technically qualified",
      observed_state: "published and technically qualified; independent daily-use evidence remains open",
      status: "observed",
      source_identifier: "synthetic-public-fixture",
      evidence: { kind: "operator-fixture", privacy: "public" },
    }),
  });
  if (!response.ok) throw new Error(`Project Reality seed failed: ${response.status} ${await response.text()}`);
}

async function openConsole(viewport) {
  const context = await browser.newContext({ viewport, deviceScaleFactor: 1 });
  const page = await context.newPage();
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) {
      errors.push(`${message.type()}: ${message.text()}`);
    }
  });
  await page.goto(`${baseUrl.replace(/\/$/, "")}/#token=${encodeURIComponent(token)}`, {
    waitUntil: "domcontentloaded",
  });
  await page.getByText(demoProject, { exact: true }).first().waitFor({ timeout: 60_000 });
  await page.waitForFunction(() => document.fonts.status === "loaded");
  await page.getByText(/^Brain Path /).evaluate((element) => {
    element.textContent = "Brain Path %USERPROFILE%\\Documents\\Rta-Smriti\\brains";
  });
  return { context, page };
}

async function selectNavigation(page, label) {
  const button = page
    .getByRole("navigation", { name: "Operator console navigation" })
    .getByRole("button", { name: new RegExp(`^${label}(?:\\s+\\d+)?$`) });
  await button.click();
}

try {
  await seedProjectReality();
  const desktop = await openConsole({ width: 1440, height: 900 });
  const { page } = desktop;

  await page.locator(".graphCanvas").waitFor({ timeout: 60_000 });
  await page.waitForFunction(() => document.querySelectorAll(".graphNode").length > 0);
  await page.screenshot({
    path: path.join(outputDir, "operator-graph-v1.0.2.png"),
    animations: "disabled",
  });

  if (captureLegacyViews) {
    await selectNavigation(page, "Files");
    await page.locator(".fileExplorer").waitFor();
    await page.locator('.fileTreeRow[title="README.md"]').click();
    await page.locator(".filePreviewHeader").waitFor();
    await page.screenshot({
      path: path.join(outputDir, "operator-files-v1.0.2.png"),
      animations: "disabled",
    });

    await selectNavigation(page, "Truth Timeline");
    await page.locator(".truthWorkspace").waitFor();
    await page.waitForFunction(() => Number(document.querySelector(".truthMetrics strong")?.textContent) > 0);
    await page.getByRole("tab", { name: "Claims", exact: true }).click();
    await page.locator(".truthClaimList button").first().waitFor();
    await page.screenshot({
      path: path.join(outputDir, "operator-truth-v1.0.2.png"),
      animations: "disabled",
    });

    await selectNavigation(page, "Capture");
    await page.getByRole("region", { name: "Universal capture console" }).waitFor();
    await page.waitForFunction(() => Number(document.querySelector(".captureMetrics strong")?.textContent) > 0);
    await page.screenshot({
      path: path.join(outputDir, "operator-capture-v1.0.2.png"),
      animations: "disabled",
    });
  }

  await selectNavigation(page, "Project Reality");
  const cognition = page.getByRole("region", { name: "Project cognition cockpit" });
  await cognition.waitFor({ timeout: 60_000 });
  await cognition.getByRole("heading", { name: "Project Reality", exact: true }).waitFor();
  await cognition.getByRole("button", { name: "Project Twin", exact: true }).click();
  await cognition.getByRole("list", { name: "Project twin observations" }).waitFor();
  await page.screenshot({
    path: path.join(outputDir, "operator-cognition-v1.0.2.png"),
    animations: "disabled",
  });
  await desktop.context.close();

  const mobile = await openConsole({ width: 390, height: 844 });
  await mobile.page.locator(".graphCanvas").waitFor({ timeout: 60_000 });
  await mobile.page.waitForFunction(() => document.querySelectorAll(".graphNode").length > 0);
  await mobile.page.screenshot({
    path: path.join(outputDir, "operator-graph-mobile-v1.0.2.png"),
    animations: "disabled",
  });
  await mobile.context.close();

  if (errors.length) {
    throw new Error(`console emitted errors during capture:\n${errors.join("\n")}`);
  }
  process.stdout.write(`Captured public-safe v1.0.2 product screenshots in ${outputDir}\n`);
} finally {
  await browser.close();
}
