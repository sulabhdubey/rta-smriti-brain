import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const baseUrl = process.env.RTA_LAUNCH_URL || "http://127.0.0.1:4175";
const productHunt = path.join(root, "launch-assets", "product-hunt");
const social = path.join(root, "launch-assets", "social");

const captures = [
  ["thumbnail", 240, 240, path.join(productHunt, "thumbnail-240.png")],
  ["gallery-1", 1270, 760, path.join(productHunt, "gallery-01-project-memory.png")],
  ["gallery-2", 1270, 760, path.join(productHunt, "gallery-02-any-agent.png")],
  ["gallery-3", 1270, 760, path.join(productHunt, "gallery-03-evidence.png")],
  ["gallery-4", 1270, 760, path.join(productHunt, "gallery-04-focused-pack.png")],
  ["social", 1280, 640, path.join(social, "github-social-preview.png")],
];
const assetFilter = process.env.RTA_ASSET_FILTER;
const selectedCaptures = assetFilter
  ? captures.filter(([name]) => name === assetFilter)
  : captures;

if (assetFilter && selectedCaptures.length === 0) {
  throw new Error(`Unknown RTA_ASSET_FILTER: ${assetFilter}`);
}

await mkdir(productHunt, { recursive: true });
await mkdir(social, { recursive: true });

const browser = await chromium.launch();
try {
  for (const [name, width, height, output] of selectedCaptures) {
    const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
    await page.goto(`${baseUrl}/?asset=${name}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => document.fonts.ready);
    await page.waitForFunction(() => [...document.images].every((image) => image.complete && image.naturalWidth > 0));
    await page.screenshot({ path: output, animations: "disabled" });
    console.log(`Captured ${name}: ${output}`);
    await page.close();
  }
} finally {
  await browser.close();
}
