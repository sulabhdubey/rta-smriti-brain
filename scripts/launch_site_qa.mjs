import AxeBuilder from "@axe-core/playwright";
import { chromium } from "@playwright/test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const port = 4176;
const baseUrl = `http://127.0.0.1:${port}`;
const viteCli = fileURLToPath(new URL("../node_modules/vite/bin/vite.js", import.meta.url));
const qaTimeoutMs = 120_000;
let serverStdout = "";
let serverStderr = "";
const server = spawn(process.execPath, [
  viteCli, "preview", "--config", "vite.launch.config.js",
  "--host", "127.0.0.1", "--port", String(port),
], { stdio: ["ignore", "pipe", "pipe"] });
server.stdout.on("data", (chunk) => {
  serverStdout = `${serverStdout}${chunk.toString()}`.slice(-8_000);
});
server.stderr.on("data", (chunk) => {
  serverStderr = `${serverStderr}${chunk.toString()}`.slice(-8_000);
});

const qaTimer = setTimeout(() => {
  process.stderr.write(`launch-site QA timed out after ${qaTimeoutMs}ms\n`);
  process.stderr.write(`vite stdout tail:\n${serverStdout}\n`);
  process.stderr.write(`vite stderr tail:\n${serverStderr}\n`);
  server.kill();
  process.exit(124);
}, qaTimeoutMs);
qaTimer.unref?.();

async function withTimeout(promise, ms, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitForServer() {
  let lastError;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(baseUrl);
      if (response.ok) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`launch preview did not start: ${lastError?.message || "unknown error"}\n${serverStderr}`);
}

async function stopServer() {
  if (server.exitCode !== null) return;
  server.kill();
  await Promise.race([
    new Promise((resolve) => server.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (server.exitCode === null) server.kill("SIGKILL");
}

let browser;
let context;
try {
  await waitForServer();
  browser = await chromium.launch();
  context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) errors.push(`${message.type()}: ${message.text()}`);
  });

  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.fonts.status === "loaded");
  assert.match(await page.title(), /Rta-Smriti Brain/);
  await page.getByRole("heading", { name: "Rta-Smriti Brain", exact: true }).waitFor();
  assert.equal(await page.locator(".heroImage").evaluate((image) => image.naturalWidth > 0), true);
  const bodyText = await page.locator("body").innerText();
  assert.match(bodyText, /v1\.0\.0-alpha/i);
  const releaseLink = page.getByRole("link", { name: "Get v1.0", exact: true });
  assert.match(await releaseLink.getAttribute("href"), /\/releases\/tag\/v1\.0\.0-alpha$/);
  assert.match(bodyText, /Universal Capture/);
  assert.match(bodyText, /Bitemporal/);
  assert.match(bodyText, /Context Compiler/i);

  assert.match(bodyText, /Conceived and researched by Sulabh Dubey/);
  assert.match(bodyText, /Built with OpenAI Codex/);
  const codexLink = page.getByRole("link", { name: "OpenAI Codex", exact: true }).first();
  assert.equal(await codexLink.getAttribute("href"), "https://openai.com/codex/");
  const productViews = [
    ["Graph", /dashboard-hero-v0\.9\.png$/],
    ["Files", /file-explorer-v0\.9\.png$/],
    ["Truth", /truth-timeline-v0\.9\.png$/],
    ["Capture", /universal-capture-v0\.9\.png$/],
  ];
  for (const [label, expectedSource] of productViews) {
    await page.getByRole("tab", { name: label, exact: true }).click();
    const productImage = page.locator(".productFrame img");
    assert.match(await productImage.getAttribute("src"), expectedSource);
    await productImage.evaluate((image) => image.complete && image.naturalWidth > 0 ? true : new Promise((resolve, reject) => { image.addEventListener("load", () => resolve(true), { once: true }); image.addEventListener("error", () => reject(new Error("product image failed to load")), { once: true }); }));
  }

  await page.getByRole("tab", { name: "kalpana", exact: true }).click();
  await page.getByText("Hypothesized", { exact: true }).waitFor();

  await page.getByRole("tab", { name: "macOS", exact: true }).click();
  assert.match(await page.locator(".terminalBlock").innerText(), /\.\/\.venv\/bin\/python -m pip install \./);
  await page.getByRole("tab", { name: "Linux", exact: true }).click();
  assert.match(await page.locator(".terminalBlock").innerText(), /python3 -m venv \.venv/);
  await page.getByRole("tab", { name: "Windows", exact: true }).click();
  assert.equal((await page.locator(".terminalBlock").innerText()).includes("& .\\.venv\\Scripts\\python.exe -m pip install ."), true);

  const unloadedImages = await page.locator("img").evaluateAll((images) =>
    images.filter((image) => !image.complete || image.naturalWidth === 0).map((image) => image.src),
  );
  assert.deepEqual(unloadedImages, []);

  const duration = await withTimeout(page.locator("video").evaluate((video) => new Promise((resolve, reject) => {
    if (video.readyState >= 1) resolve(video.duration);
    else {
      video.addEventListener("loadedmetadata", () => resolve(video.duration), { once: true });
      video.addEventListener("error", () => reject(new Error("launch video failed to load")), { once: true });
      video.load();
    }
  })), 20_000, "launch video metadata");
  assert.ok(duration >= 59 && duration <= 61, `unexpected video duration: ${duration}`);

  const localLinks = await page.locator('a[href^="./"]').evaluateAll((links) => links.map((link) => link.href));
  for (const href of localLinks) {
    const response = await withTimeout(fetch(href), 10_000, `local link fetch ${href}`);
    assert.equal(response.ok, true, `broken local link: ${href}`);
  }
  assert.ok((await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)) <= 1);
  const desktopAxe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const desktopViolations = desktopAxe.violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target),
  }));
  assert.deepEqual(desktopViolations, []);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open menu", exact: true }).click();
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Install", exact: true }).waitFor();
  assert.ok((await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)) <= 1);
  const mobileAxe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  const mobileViolations = mobileAxe.violations.map((violation) => ({
    id: violation.id,
    targets: violation.nodes.map((node) => node.target),
  }));
  assert.deepEqual(mobileViolations, []);
  assert.deepEqual(errors, []);
  process.stdout.write("Launch-site operator QA passed: desktop, mobile, interactions, media, links, accessibility.\n");
} finally {
  await context?.close();
  await browser?.close();
  await stopServer();
  clearTimeout(qaTimer);
}
