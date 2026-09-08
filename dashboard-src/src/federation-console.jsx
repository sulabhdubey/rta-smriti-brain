import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Network,
  Play,
  RadioTower,
  RefreshCw,
  RotateCw,
  ShieldCheck,
  Square,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react";

const CAPABILITIES = ["read", "write", "review", "index", "context", "sync", "export", "diagnose", "admin"];

function StateBadge({ state }) {
  const value = state || "unknown";
  const tone = ["healthy", "ready", "idle"].includes(value)
    ? "ok"
    : value === "not_configured"
      ? "muted"
      : "warn";
  const label = value.replaceAll("_", " ");
  return <span className={"federationBadge " + tone}>{label.charAt(0).toUpperCase() + label.slice(1)}</span>;
}

function ManagedSync({ data, busy, onOperation }) {
  const sync = data?.managed_sync || { state: "not_configured", status: "ok" };
  const enabled = Boolean(data?.mutations_enabled);
  const state = sync.state || "unknown";
  const syncState = sync.sync_state || (state === "not_configured" ? "not_configured" : "pending");
  const [plan, setPlan] = useState(null);
  const [actionError, setActionError] = useState("");
  const running = ["starting", "running", "stopping"].includes(state);
  const configured = state !== "not_configured";
  const actions = running
    ? [{ action: "stop", label: "Stop", Icon: Square }]
    : configured
      ? [
          { action: "start", label: "Start", Icon: Play },
          { action: "cycle", label: "Run one cycle", Icon: RotateCw },
          { action: "remove", label: "Remove enrollment", Icon: Trash2, destructive: true },
        ]
      : [];

  async function preview(action) {
    setActionError("");
    try {
      const result = await onOperation({ action: "sync-plan", operation: action });
      if (result) setPlan(result);
    } catch (error) {
      setActionError(error.message);
    }
  }

  async function apply() {
    if (!plan) return;
    try {
      await onOperation({
        action: "sync-apply",
        operation: plan.action,
        confirmation_digest: plan.confirmation_digest,
      });
      setPlan(null);
    } catch (error) {
      setActionError(error.message);
    }
  }

  const guidance = state === "not_configured"
    ? "Managed sync is not enrolled. Configure an exact scope and relay from the local CLI before enabling background sync."
    : syncState === "offline"
      ? "The local brain remains available, but the relay could not be reached. Check relay availability, then run one bounded cycle or restart managed sync."
      : syncState === "degraded" || ["stale", "invalid_configuration", "error"].includes(state)
        ? "Managed sync needs attention. Inspect local diagnostics and repair the enrollment before trusting federation freshness."
        : running
          ? "The quiet worker is reconciling this authorized scope in the background."
          : "Enrollment is ready. Start the quiet worker or run one bounded synchronization cycle.";

  return (
    <section className="federationManagedSync" aria-label="Managed federation sync">
      <div className="federationSectionTitle">
        <div><RadioTower size={17} /><h3>Managed sync</h3></div>
        <StateBadge state={syncState === "pending" ? state : syncState} />
      </div>
      <div className="federationManagedBody">
        <div className="federationManagedSummary">
          <p>{guidance}</p>
          {configured && <dl>
            <div><dt>Worker</dt><dd>{state.replaceAll("_", " ")}</dd></div>
            <div><dt>Cycles</dt><dd>{sync.successful_cycles || 0} / {sync.cycles || 0}</dd></div>
            <div><dt>Local / relay events</dt><dd>{sync.local_event_count ?? "-"} / {sync.relay_event_count ?? "-"}</dd></div>
            <div><dt>Last successful sync</dt><dd>{sync.last_success_at || "Not yet verified"}</dd></div>
          </dl>}
        </div>
        {actions.length > 0 && !plan && <div className="federationManagedActions">
          {actions.map(({ action, label, Icon, destructive }) => <button
            key={action}
            type="button"
            className={destructive ? "secondaryButton dangerButton" : action === "start" ? "primaryButton" : "secondaryButton"}
            onClick={() => preview(action)}
            disabled={!enabled || busy}
            aria-label={`Preview ${action}`}
          ><Icon size={16} />{label}</button>)}
        </div>}
      </div>
      {actionError && <div className="federationInlineAlert" role="alert"><AlertTriangle size={16} /><span>{actionError}</span></div>}
      {plan && <div className="federationPlan" role="region" aria-label="Managed sync change preview">
        <div><strong>{plan.action.replaceAll("-", " ")}</strong><code>{plan.confirmation_digest.slice(0, 10)}</code></div>
        <p>This operation applies only while the inspected worker state remains unchanged.</p>
        {(plan.warnings || []).map((warning) => <p key={warning}><AlertTriangle size={15} />{warning}</p>)}
        <div className="federationPlanActions">
          <button type="button" className="secondaryButton" onClick={() => setPlan(null)} disabled={busy}>Cancel</button>
          <button type="button" className="primaryButton" onClick={apply} disabled={busy} aria-label={`Confirm ${plan.action}`}><CheckCircle2 size={16} /> Confirm</button>
        </div>
      </div>}
      {!enabled && configured && <div className="federationPermission" role="status">
        <KeyRound size={17} />
        <span>Worker controls are locked until the console starts with the enrolled private identity.</span>
      </div>}
    </section>
  );
}

function ActionCenter({ data, busy, onOperation }) {
  const spaces = data?.spaces || [];
  const scopes = data?.scopes || [];
  const peers = data?.peers || [];
  const quarantine = data?.quarantine || [];
  const enabled = Boolean(data?.mutations_enabled);
  const [operation, setOperation] = useState(spaces.length ? "scope-create" : "space-create");
  const [spaceId, setSpaceId] = useState(spaces[0]?.space_id || "");
  const selectedScopes = useMemo(
    () => scopes.filter((scope) => scope.space_id === spaceId),
    [scopes, spaceId],
  );
  const selectedPeers = useMemo(
    () => peers.filter((peer) => peer.space_id === spaceId),
    [peers, spaceId],
  );
  const [scopeId, setScopeId] = useState("");
  const [peerId, setPeerId] = useState("");
  const [label, setLabel] = useState("");
  const [scopeKind, setScopeKind] = useState("team");
  const [peerManifest, setPeerManifest] = useState("");
  const [capabilities, setCapabilities] = useState(["read", "review", "sync"]);
  const [plan, setPlan] = useState(null);
  const [actionError, setActionError] = useState("");
  const [quarantineId, setQuarantineId] = useState("");

  useEffect(() => {
    if (spaces.length && operation === "space-create") setOperation("scope-create");
    if (!spaces.length && operation !== "space-create") setOperation("space-create");
    if (!spaceId && spaces[0]?.space_id) setSpaceId(spaces[0].space_id);
  }, [operation, spaceId, spaces]);

  const activeScope = scopeId || selectedScopes[0]?.scope_id || "";
  const activePeer = peerId || selectedPeers[0]?.peer_id || "";
  const capabilityAction = operation.startsWith("capability-");
  const needsCapabilities = ["capability-grant", "capability-resolve"].includes(operation);

  function resetPreview() {
    setPlan(null);
    setActionError("");
  }

  function parameters() {
    if (operation === "space-create") return {};
    if (["quarantine-promote", "quarantine-reject"].includes(operation)) {
      return { quarantine_id: Number(quarantineId || quarantine[0]?.quarantine_id), reason: label.trim() };
    }
    if (operation === "scope-create") {
      return { space_id: spaceId, kind: scopeKind, label: label.trim() };
    }
    if (operation === "peer-add") {
      let manifest;
      try {
        manifest = JSON.parse(peerManifest);
      } catch {
        throw new Error("Public identity manifest must be valid JSON.");
      }
      if (!manifest?.identity_id) throw new Error("Public identity manifest has no identity ID.");
      return { space_id: spaceId, peer_id: manifest.identity_id, label: label.trim() };
    }
    if (operation === "scope-rotate") {
      return { space_id: spaceId, scope_id: activeScope };
    }
    const value = {
      space_id: spaceId,
      scope_id: activeScope || null,
      subject_peer_id: activePeer,
    };
    if (operation !== "capability-revoke") value.capabilities = capabilities;
    return value;
  }

  async function preview() {
    resetPreview();
    try {
      const result = await onOperation({ action: "plan", operation, parameters: parameters() });
      if (result) setPlan(result);
    } catch (error) {
      setActionError(error.message);
    }
  }

  async function apply() {
    if (!plan) return;
    try {
      await onOperation({
        action: "apply",
        operation,
        parameters: plan.parameters,
        confirmation_digest: plan.confirmation_digest,
        ...(operation === "peer-add" ? { peer_manifest: peerManifest } : {}),
      });
      setPlan(null);
      setLabel("");
      setPeerManifest("");
    } catch (error) {
      setActionError(error.message);
    }
  }

  const canPreview = enabled && !busy
    && (operation === "space-create" || spaceId)
    && (operation !== "scope-create" || label.trim())
    && (operation !== "peer-add" || (label.trim() && peerManifest.trim()))
    && (!["quarantine-promote", "quarantine-reject"].includes(operation) || (quarantine.length && label.trim()))
    && (!["scope-rotate"].includes(operation) || activeScope)
    && (!capabilityAction || (activePeer && activeScope))
    && (!needsCapabilities || capabilities.length);

  return (
    <section className="federationActionCenter" aria-label="Federation action center">
      <div className="federationSectionTitle">
        <div><ShieldCheck size={17} /><h3>Action center</h3></div>
        <StateBadge state={enabled ? "ready" : "read_only"} />
      </div>
      <div className="federationFormGrid">
        <label>Action
          <select value={operation} onChange={(event) => { setOperation(event.target.value); resetPreview(); }} disabled={busy}>
            {!spaces.length && <option value="space-create">Create team brain</option>}
            {spaces.length > 0 && <>
              <option value="scope-create">Create protection scope</option>
              <option value="peer-add">Add authorized device</option>
              <option value="capability-grant">Grant access</option>
              <option value="capability-revoke">Revoke access</option>
              <option value="capability-resolve">Resolve access conflict</option>
              <option value="scope-rotate">Rotate scope key</option>
              {quarantine.length > 0 && <option value="quarantine-promote">Promote quarantined event</option>}
              {quarantine.length > 0 && <option value="quarantine-reject">Reject quarantined event</option>}
            </>}
          </select>
        </label>
        {operation !== "space-create" && <label>Team brain
          <select value={spaceId} onChange={(event) => { setSpaceId(event.target.value); setScopeId(""); setPeerId(""); resetPreview(); }} disabled={busy}>
            {spaces.map((space) => <option key={space.space_id} value={space.space_id}>{space.space_id.slice(0, 10)}</option>)}
          </select>
        </label>}
        {operation === "scope-create" && <>
          <label>Scope type
            <select value={scopeKind} onChange={(event) => { setScopeKind(event.target.value); resetPreview(); }} disabled={busy}>
              <option value="team">Team</option>
              <option value="review">Review</option>
              <option value="custom">Custom</option>
            </select>
          </label>
          <label>Label
            <input value={label} onChange={(event) => { setLabel(event.target.value); resetPreview(); }} maxLength={256} disabled={busy} />
          </label>
        </>}
        {operation === "peer-add" && <>
          <label>Device label
            <input value={label} onChange={(event) => { setLabel(event.target.value); resetPreview(); }} maxLength={256} disabled={busy} />
          </label>
          <label className="federationWideField">Public identity manifest
            <textarea value={peerManifest} onChange={(event) => { setPeerManifest(event.target.value); resetPreview(); }} rows={4} spellCheck="false" disabled={busy} />
          </label>
        </>}
        {["quarantine-promote", "quarantine-reject"].includes(operation) && <>
          <label>Quarantined event
            <select value={quarantineId || quarantine[0]?.quarantine_id || ""} onChange={(event) => { setQuarantineId(event.target.value); resetPreview(); }} disabled={busy}>
              {quarantine.map((item) => <option key={item.quarantine_id} value={item.quarantine_id}>{item.reason_code} / {String(item.claimed_event_id || "unknown").slice(0, 10)}</option>)}
            </select>
          </label>
          <label>Decision reason
            <input value={label} onChange={(event) => { setLabel(event.target.value); resetPreview(); }} maxLength={512} disabled={busy} />
          </label>
        </>}
        {(operation === "scope-rotate" || capabilityAction) && <label>Protection scope
          <select value={activeScope} onChange={(event) => { setScopeId(event.target.value); resetPreview(); }} disabled={busy}>
            {selectedScopes.map((scope) => <option key={scope.scope_id} value={scope.scope_id}>{scope.label}</option>)}
          </select>
        </label>}
        {capabilityAction && <label>Authorized device
          <select value={activePeer} onChange={(event) => { setPeerId(event.target.value); resetPreview(); }} disabled={busy}>
            {selectedPeers.map((peer) => <option key={peer.peer_id} value={peer.peer_id}>{peer.label}</option>)}
          </select>
        </label>}
        {needsCapabilities && <fieldset className="federationCapabilities federationWideField">
          <legend>Capabilities</legend>
          {CAPABILITIES.map((capability) => <label key={capability}>
            <input
              type="checkbox"
              checked={capabilities.includes(capability)}
              onChange={(event) => {
                setCapabilities((current) => event.target.checked
                  ? [...current, capability]
                  : current.filter((item) => item !== capability));
                resetPreview();
              }}
              disabled={busy}
            />
            {capability}
          </label>)}
        </fieldset>}
      </div>
      {actionError && <div className="federationAlert" role="alert"><AlertTriangle size={16} /><span>{actionError}</span></div>}
      {!enabled && <div className="federationPermission" role="status">
        <KeyRound size={17} />
        <span>Changes are locked until the console starts with a private local identity.</span>
      </div>}
      {plan ? <div className="federationPlan" role="region" aria-label="Federation change preview">
        <div><strong>{plan.action.replaceAll("-", " ")}</strong><code>{plan.confirmation_digest.slice(0, 10)}</code></div>
        {(plan.warnings || []).map((warning) => <p key={warning}><AlertTriangle size={15} />{warning}</p>)}
        <div className="federationPlanActions">
          <button type="button" className="secondaryButton" onClick={() => setPlan(null)} disabled={busy}>Cancel</button>
          <button type="button" className="primaryButton" onClick={apply} disabled={busy}><CheckCircle2 size={16} /> Confirm</button>
        </div>
      </div> : <button type="button" className="primaryButton" onClick={preview} disabled={!canPreview}>
        {operation === "peer-add" ? <UserPlus size={16} /> : <ShieldCheck size={16} />}
        Preview change
      </button>}
    </section>
  );
}

export default function FederationConsole({ data, busy, error, onRefresh, onOperation }) {
  const status = data?.status;
  const axes = status?.axes || {};
  const configured = status?.state && status.state !== "not_configured";
  const axisRows = [
    ["Governance", axes.governance, ShieldCheck],
    ["Encryption", axes.encryption, KeyRound],
    ["Projection", axes.projection, Network],
    ["Synchronization", axes.sync, RadioTower],
    ["Relay", axes.relay, RadioTower],
  ];

  return (
    <section className="federationWorkspace" aria-label="Governed federation console" aria-busy={busy}>
      <header className="federationHeader">
        <div><span className="sectionEyebrow">Governed federation</span><h2>Team Brain Control Plane</h2></div>
        <div className="federationHeaderActions">
          <StateBadge state={status?.state} />
          <button className="iconButton" onClick={onRefresh} disabled={busy} title="Refresh federation state" aria-label="Refresh federation state">
            <RefreshCw className={busy ? "spin" : ""} size={16} />
          </button>
        </div>
      </header>
      {error && <div className="federationAlert" role="alert"><AlertTriangle size={17} /><span>{error}</span></div>}
      {!configured ? <div className="federationEmpty" role="status">
        <Network size={25} /><strong>Local-only brain</strong><span>No team brain configured.</span>
      </div> : <>
        <div className="federationMetrics" aria-label="Federation summary">
          <div><strong>{status.space_count}</strong><span>Spaces</span></div>
          <div><strong>{status.scope_count}</strong><span>Scopes</span></div>
          <div><strong>{status.peer_count}</strong><span>Peers</span></div>
          <div><strong>{data?.counts?.encrypted_events || 0}</strong><span>Encrypted events</span></div>
          <div className={data?.counts?.quarantined ? "warn" : "ok"}><strong>{data?.counts?.quarantined || 0}</strong><span>Quarantined</span></div>
        </div>
        <div className="federationGrid">
          <section><h3>Health axes</h3><div className="federationAxisList">
            {axisRows.map(([label, state, Icon]) => <div key={label}><Icon size={16} /><span>{label}</span><StateBadge state={state} /></div>)}
          </div></section>
          <section><h3>Protection scopes</h3><div className="federationList">
            {(data?.scopes || []).map((scope) => <div key={scope.scope_id}><ShieldCheck size={16} /><span><strong>{scope.label}</strong><small>{scope.scope_kind} / epoch {scope.current_epoch || "missing"}</small></span><code>{scope.scope_id.slice(0, 10)}</code></div>)}
            {!data?.scopes?.length && <span className="federationMuted">No protection scopes.</span>}
          </div></section>
          <section><h3>Authorized devices</h3><div className="federationList">
            {(data?.peers || []).map((peer) => <div key={peer.space_id + ":" + peer.peer_id}><Users size={16} /><span><strong>{peer.label}</strong><small>device fingerprint</small></span><code>{peer.peer_id.slice(0, 10)}</code></div>)}
          </div></section>
          <section><h3>Operational boundary</h3><div className="federationBoundary">
            <CheckCircle2 size={18} /><p>{status.guidance}</p>
            {status.prior_plaintext_revocation_limit && <p className="warning">Revocation protects future key epochs; it cannot erase plaintext already received by a device.</p>}
          </div></section>
        </div>
      </>}
      <ManagedSync data={data} busy={busy} onOperation={onOperation} />
      <ActionCenter data={data} busy={busy} onOperation={onOperation} />
    </section>
  );
}
