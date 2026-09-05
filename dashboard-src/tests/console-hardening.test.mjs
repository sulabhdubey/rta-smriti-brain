import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../src/main.jsx", import.meta.url), "utf8");

function functionBody(name) {
  const start = source.indexOf(`async function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist`);
  const next = source.indexOf("\n  async function ", start + 1);
  return source.slice(start, next === -1 ? source.length : next);
}

test("lifecycle execution submits every preview confirmation field", () => {
  const body = functionBody("confirmLifecyclePlan");
  assert.match(body, /plan_digest:\s*lifecyclePlan\.plan_digest/);
  assert.match(body, /observed_state_digest:\s*lifecyclePlan\.observed_state_digest/);
  assert.match(body, /desired_state_digest:\s*lifecycleHealth\?\.desired_state_digest/);
  assert.match(functionBody("reviewLifecyclePlan"), /plan_action:\s*action/);
});

test("checkpoint responses are bound to the selected project and request generation", () => {
  const body = functionBody("saveCheckpoint");
  assert.match(body, /const project = selectedProject/);
  assert.match(body, /checkpointRequestRef\.current/);
  assert.match(body, /isCurrentProject\(project\)/);
  assert.match(source, /checkpointRequestRef\.current \+= 1/);
});

test("bundle execution resubmits the preview-bound destination confirmation", () => {
  const body = functionBody("runBundle");
  assert.match(body, /destination_confirmation:\s*bundlePreview\?\.destination_confirmation/);
});

test("API errors retain structured destination previews for a second confirmation", () => {
  const body = functionBody("api");
  assert.match(body, /error\.payload = payload/);
  const snapshot = functionBody("runSnapshot");
  const passphrase = functionBody("generateSnapshotPassphrase");
  assert.match(snapshot, /DestinationConfirmationRequired/);
  assert.match(snapshot, /destination_confirmation/);
  assert.match(passphrase, /DestinationConfirmationRequired/);
  assert.match(passphrase, /destination_confirmation/);
});
