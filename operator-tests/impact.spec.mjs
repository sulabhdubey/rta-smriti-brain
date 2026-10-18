import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import AxeBuilder from '@axe-core/playwright';

for (const width of [1440, 390]) {
  test(`Impact evidence, graph and reviewed export at ${width}`, async ({ browser }) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'rta-impact-'));
    const child = spawn(process.env.PYTHON || 'python', ['scripts/operator_qa_server.py', directory],
      { windowsHide: true, env: { ...process.env, PYTHONUNBUFFERED: '1' }, stdio: ['ignore','pipe','pipe'] });
    const context = await browser.newContext({ viewport: { width, height: 960 } });
    try {
      const info = await new Promise((resolve, reject) => {
        let buffer = '', errors = '';
        const timeout = setTimeout(() => reject(new Error(errors || 'fixture timeout')), 30000);
        child.stderr.on('data', d => { errors += d; });
        child.stdout.on('data', d => { buffer += d; const line = buffer.split(/\r?\n/).find(x => x.startsWith('{')); if (line) { clearTimeout(timeout); resolve(JSON.parse(line)); } });
        child.once('error', e => { clearTimeout(timeout); reject(e); });
        child.once('exit', code => { clearTimeout(timeout); reject(new Error(`fixture exit ${code}: ${errors}`)); });
      });
      const page = await context.newPage();
      page.setDefaultTimeout(10000);
      const errors = [];
      page.on('pageerror', e => errors.push(e.message));
      await page.goto(info.url);
      await page.getByRole('button', { name: 'Intelligence', exact: true }).click();
      await page.getByRole('tab', { name: 'Impact', exact: true }).click();
      const panel = page.getByRole('region', { name: 'Change impact' });
      await panel.getByLabel('Symbol or file', { exact: true }).fill('queue_budget');
      await panel.getByRole('button', { name: 'Trace relationships', exact: true }).click();
      await expect(panel.getByText('Indexed evidence only', { exact: true })).toBeVisible();
      await panel.getByRole('button', { name: 'List view', exact: true }).click();
      await panel.getByRole('button', { name: /^Inspect / }).last().focus();
      await page.keyboard.press('Enter');
      await panel.getByRole('button', { name: 'Graph view', exact: true }).click();
      await expect(panel.getByRole('group', { name: 'Relationship graph' })).toBeVisible();
      await panel.getByRole('button', { name: /^Inspect / }).last().click();
      await expect(panel.getByRole('region', { name: 'Selected relationship path' })).toBeVisible();
      await panel.getByLabel(/^Include /).first().check();
      await panel.getByRole('button', { name: 'Preview handoff', exact: true }).click();
      await expect(panel.getByLabel('Handoff preview')).toContainText('Change impact handoff');
      await expect(panel.getByRole('button', { name: 'Download handoff', exact: true })).toBeDisabled();
      await panel.getByLabel('I reviewed this selection for sensitive information').check();
      const download = page.waitForEvent('download');
      await panel.getByRole('button', { name: 'Download handoff', exact: true }).click();
      expect(await readFile(await (await download).path(), 'utf8')).toContain('Indexed relationships');
      await page.screenshot({ path: `output/impact/impact-${width}.png`, fullPage: true });
      await panel.screenshot({ path: `output/impact/impact-panel-${width}.png` });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
      expect(errors).toEqual([]);
      expect((await new AxeBuilder({ page }).include('.impactExplorer').analyze()).violations).toEqual([]);
      await page.route('**/api/impact', route => route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ status: 'error', error: { type: 'ValueError', message: 'evidence changed; refresh and review again' } }) }));
      await panel.getByRole('button', { name: 'Download handoff', exact: true }).click();
      await expect(panel.getByRole('alert')).toContainText('changed');
      await expect(panel.getByLabel('Handoff preview')).toHaveCount(0);
      await page.unroute('**/api/impact');
      await panel.getByLabel('Symbol or file', { exact: true }).fill('missing');
      await expect(panel.getByLabel('Handoff preview')).toHaveCount(0);
      await panel.getByRole('button', { name: 'Trace relationships', exact: true }).click();
      await expect(panel.getByText('No eligible indexed relationships found.', { exact: true })).toBeVisible();
      const passportUrl = new URL(info.url); passportUrl.searchParams.set('view', 'passport');
      await page.goto(passportUrl.href);
      await page.getByRole('tab', { name: 'Changes', exact: true }).click();
      await page.getByText('Explore change impact', { exact: true }).click();
      await page.getByRole('region', { name: 'Change impact' }).getByLabel('Symbol or file', { exact: true }).fill('queue_budget');
      await page.getByRole('region', { name: 'Change impact' }).getByRole('button', { name: 'Trace relationships', exact: true }).click();
      await expect(page.getByText('Indexed evidence only', { exact: true })).toBeVisible();
    } finally {
      try { await context.close(); }
      finally { if (child.exitCode === null) { const ended = new Promise(resolve => child.once('exit', resolve)); child.kill(); await ended; } }
    }
  });
}
