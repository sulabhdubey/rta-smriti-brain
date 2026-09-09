import React, { useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock3,
  Download,
  Eye,
  Link2,
  Pause,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";

const TABS = ["timeline", "sources", "privacy", "diagnostics"];
const ROW_HEIGHT = 78;
const WINDOW_SIZE = 28;

function shortId(value, length = 10) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length)}...` : text || "none";
}

function eventLabel(name) {
  return String(name || "event").replace(/\.v\d+$/, "").replaceAll(".", " ");
}

function formatTime(value) {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function statusTone(value) {
  if (["running", "active", "ok", "clear", "valid"].includes(value)) return "ok";
  if (["paused", "stopped", "empty"].includes(value)) return "muted";
  return "warn";
}

function CaptureTimeline({ replay, busy, onInspect }) {
  const viewportRef = useRef(null);
  const [windowStart, setWindowStart] = useState(0);
  const events = replay?.events || [];
  const start = Math.min(windowStart, Math.max(0, events.length - WINDOW_SIZE));
  const visible = events.slice(start, start + WINDOW_SIZE);

  if (busy && !replay) {
    return <div className="captureState" role="status"><RefreshCw className="spin" size={20} /> Loading captured events...</div>;
  }
  if (!events.length) {
    return (
      <div className="captureState captureEmpty" role="status">
        <Activity size={22} />
        <strong>No captured activity yet</strong>
        <span>Bind an authorized agent session, then new activity will appear here.</span>
      </div>
    );
  }
  return (
    <div
      className="captureTimelineViewport"
      ref={viewportRef}
      onScroll={(event) => setWindowStart(Math.max(0, Math.floor(event.currentTarget.scrollTop / ROW_HEIGHT) - 4))}
      role="region"
      aria-label="Captured activity timeline"
      aria-busy={busy}
    >
      <div className="captureTimelineWindow" style={{ height: `${events.length * ROW_HEIGHT}px` }}>
        {visible.map((event, index) => {
          const absoluteIndex = start + index;
          const isGap = event.event_name === "capture.gap.v1" || event.gap_state === "detected";
          const isInterrupted = event.event_name === "turn.interrupted.v1";
          return (
            <button
              className={`captureEvent ${isGap ? "gap" : ""} ${isInterrupted ? "interrupted" : ""}`}
              key={event.event_id}
              data-capture-event-id={event.event_id}
              style={{ transform: `translateY(${absoluteIndex * ROW_HEIGHT}px)` }}
              onClick={(click) => onInspect(event, click.currentTarget)}
              aria-label={`Inspect event ${event.project_sequence}: ${eventLabel(event.event_name)}`}
            >
              <span className="captureEventRail"><i /></span>
              <span className="captureEventBody">
                <span className="captureEventTitle">
                  <strong>{eventLabel(event.event_name)}</strong>
                  <time>{formatTime(event.recorded_at)}</time>
                </span>
                <span className="captureEventMeta">
                  <code>#{event.project_sequence}</code>
                  <span>{event.source_id}</span>
                  <span className={`capturePill ${event.verification_status}`}>{event.verification_status}</span>
                  <span className="capturePill">{event.privacy_class}</span>
                </span>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default function CaptureConsole({
  project,
  overview,
  replay,
  diagnostics,
  continuity,
  busy,
  error,
  replayMode,
  privacyCeiling,
  onReplayMode,
  onPrivacyCeiling,
  onRefresh,
  onAction,
  onExport,
}) {
  const [tab, setTab] = useState("timeline");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const returnFocusRef = useRef(null);
  const [binding, setBinding] = useState({ source_id: "", external_session_id: "", start_cursor: "0" });
  const [bindingReceipt, setBindingReceipt] = useState(null);
  const [policy, setPolicy] = useState({ profile: "continuity", privacy_ceiling: "internal", retention_seconds: 2592000 });
  const [policyPreview, setPolicyPreview] = useState(null);
  const [privacyPreview, setPrivacyPreview] = useState(null);
  const [retentionPreview, setRetentionPreview] = useState(null);
  const [deletion, setDeletion] = useState({ scope: "event-content", scope_token: "", policy_digest: "" });
  const [deletionPreview, setDeletionPreview] = useState(null);

  const sources = overview?.sources || [];
  const policies = overview?.policies || [];
  const activePolicy = policies.find((item) => !item.retired_at) || policies[0];
  const activeSource = sources.find((item) => item.state === "active") || sources[0];
  const interruption = replay?.interruption_snapshot || {};
  const continuityEvents = Number(continuity?.events_inserted || 0);
  const continuityCheckpoints = Number(continuity?.checkpoints_created || 0);
  const metrics = useMemo(() => [
    ["Events", diagnostics?.events?.count ?? replay?.coverage?.selected_events ?? 0],
    ["Sources", sources.length],
      ["Queue", overview?.queue?.records ?? "Unknown"],
    ["Gaps", diagnostics?.events?.gaps ?? replay?.coverage?.gap_events ?? 0],
  ], [diagnostics, overview, replay, sources.length]);

  function inspectEvent(event, trigger) {
    returnFocusRef.current = event.event_id;
    setSelectedEvent(event);
  }

  function closeEvent() {
    setSelectedEvent(null);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const eventId = returnFocusRef.current;
      if (!eventId) return;
      document.querySelector(`[data-capture-event-id="${eventId}"]`)?.focus?.();
    }));
  }

  async function run(action, payload = {}, success) {
    const result = await onAction(action, payload, success);
    return result;
  }

  async function previewPolicy() {
    const result = await run("policy-preview", policy, "Capture policy preview is ready.");
    if (result) setPolicyPreview(result);
  }

  async function bindSession(event) {
    event.preventDefault();
    const result = await run("bind-session", {
      ...binding,
      source_id: binding.source_id || activeSource?.source_id,
      cursor_kind: "sequence",
    }, "Session capture binding created.");
    if (result) setBindingReceipt(result);
  }

  async function closeBinding() {
    if (!bindingReceipt) return;
    const result = await run("close-session", { binding_id: bindingReceipt.binding_id }, "Session capture binding closed.");
    if (result) setBindingReceipt(null);
  }

  async function previewRedaction() {
    const result = await run("redaction-preview", { privacy_ceiling: privacyCeiling, limit: 100 }, "Privacy preview completed.");
    if (result) setPrivacyPreview(result);
  }

  async function previewRetention() {
    const result = await run("retention-preview", {
      policy_digest: activePolicy?.policy_digest,
      run_id: `dashboard-${Date.now()}`,
      batch_size: 100,
    }, "Retention preview is ready. No content was changed.");
    if (result) setRetentionPreview(result);
  }

  async function confirmRetention() {
    if (!retentionPreview) return;
    const result = await run("retention-confirm", {
      policy_digest: retentionPreview.policy_digest,
      run_id: retentionPreview.run_id,
      batch_size: 100,
      confirmation_token: retentionPreview.confirmation_token,
    }, "Retention policy applied.");
    if (result) setRetentionPreview(null);
  }

  async function previewDeletion(event) {
    event.preventDefault();
    const result = await run("deletion-preview", {
      ...deletion,
      policy_digest: deletion.policy_digest || activePolicy?.policy_digest,
      reason_class: "operator-request",
    }, "Deletion preview completed. No content was changed.");
    if (result) setDeletionPreview(result);
  }

  async function confirmDeletion() {
    if (!deletionPreview) return;
    const result = await run("deletion-confirm", {
      ...deletion,
      policy_digest: deletion.policy_digest || activePolicy?.policy_digest,
      reason_class: "operator-request",
      confirmation_token: deletionPreview.confirmation_token,
    }, "Capture content was logically deleted and receipted.");
    if (result) {
      setDeletionPreview(null);
      setDeletion((current) => ({ ...current, scope_token: "" }));
    }
  }

  return (
    <section className="captureWorkspace" aria-label="Universal capture console" aria-busy={busy}>
      <header className="captureHeader">
        <div>
          <span className="sectionEyebrow">Universal capture</span>
          <h2>Agent Flight Recorder</h2>
          <p>Review explicitly authorized passive-capture events. Replay never executes captured actions.</p>
        </div>
        <div className="captureHeaderActions">
          <span className={`captureHealth ${statusTone(overview?.daemon?.state)}`}>
            <i /> {overview?.daemon?.state || "stopped"}
          </span>
          <button className="iconButton" onClick={onRefresh} disabled={busy} title="Refresh capture state" aria-label="Refresh capture state">
            <RefreshCw size={16} />
          </button>
          {overview?.daemon?.state === "running" ? (
            <button onClick={() => run("daemon-stop", {}, "Brain-wide capture service stopped.")} disabled={busy} title="Stop the capture service for this brain database"><Pause size={15} /> Stop</button>
          ) : (
            <button onClick={() => run("daemon-start", {}, "Brain-wide capture service started.")} disabled={busy} title="Start the capture service for this brain database"><Play size={15} /> Start</button>
          )}
        </div>
      </header>

      {error && <div className="captureAlert" role="alert"><AlertTriangle size={17} /><span><strong>Capture needs attention.</strong> {error}</span><button onClick={onRefresh}>Retry</button></div>}
      {(overview?.warnings || []).map((warning) => (
        <div className="captureAlert captureWarning" role="status" key={warning.code}>
          <AlertTriangle size={17} />
          <span><strong>Telemetry limited.</strong> {warning.message}</span>
        </div>
      ))}

      <div className="captureStreamSummary" role="status" aria-label="Capture stream status">
        <span><strong>Passive capture journal</strong>{diagnostics?.events?.count ?? 0} events</span>
        <span><strong>Codex task continuity</strong>{continuity?.state || "unknown"} / {continuityEvents} events / {continuityCheckpoints} checkpoints</span>
      </div>

      <div className="captureMetrics" aria-label="Capture summary">
        {metrics.map(([label, value]) => <div key={label}><strong>{value}</strong><span>{label}</span></div>)}
        <div className={interruption.status === "clear" ? "ok" : "warn"}>
          <strong>{interruption.status || "clear"}</strong><span>Continuity</span>
        </div>
      </div>

      <div className="captureTabs" role="tablist" aria-label="Capture views">
        {TABS.map((name) => (
          <button
            key={name}
            role="tab"
            data-capture-tab={name}
            aria-selected={tab === name}
            tabIndex={tab === name ? 0 : -1}
            className={tab === name ? "active" : ""}
            onClick={() => setTab(name)}
            onKeyDown={(event) => {
              if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
              event.preventDefault();
              const offset = event.key === "ArrowRight" ? 1 : -1;
              const next = TABS[(TABS.indexOf(name) + offset + TABS.length) % TABS.length];
              setTab(next);
              event.currentTarget.parentElement.querySelector(`[data-capture-tab="${next}"]`)?.focus?.();
            }}
          >
            {name}
          </button>
        ))}
      </div>

      <div className="captureBody">
        {tab === "timeline" && (
          <div className="captureTimelinePanel" role="tabpanel">
            <div className="capturePanelToolbar">
              <div className="captureSegment" aria-label="Replay order">
                <button aria-pressed={replayMode === "chronological"} className={replayMode === "chronological" ? "active" : ""} onClick={() => onReplayMode("chronological")}><Clock3 size={14} /> Timeline</button>
                <button aria-pressed={replayMode === "causal"} className={replayMode === "causal" ? "active" : ""} onClick={() => onReplayMode("causal")}><Link2 size={14} /> Causal</button>
              </div>
              <span>{replay?.events?.length || 0} events shown / bounded to 100</span>
            </div>
            {selectedEvent ? (
              <article className="captureEventDetail" aria-label="Captured event detail">
                <button className="captureBack" onClick={closeEvent}><ArrowLeft size={15} /> Back to timeline</button>
                <div className="captureDetailHeading">
                  <div><span>Event #{selectedEvent.project_sequence}</span><h3>{eventLabel(selectedEvent.event_name)}</h3></div>
                  <span className={`capturePill ${selectedEvent.verification_status}`}>{selectedEvent.verification_status}</span>
                </div>
                <dl>
                  <div><dt>Source</dt><dd>{selectedEvent.source_id}</dd></div>
                  <div><dt>Session</dt><dd>{shortId(selectedEvent.external_session_id, 18)}</dd></div>
                  <div><dt>Privacy</dt><dd>{selectedEvent.privacy_class}</dd></div>
                  <div><dt>Recorded</dt><dd>{formatTime(selectedEvent.recorded_at)}</dd></div>
                  <div><dt>Integrity</dt><dd><code>{shortId(selectedEvent.event_hash, 18)}</code></dd></div>
                  <div><dt>Content</dt><dd>{selectedEvent.content_state}</dd></div>
                </dl>
                <pre>{JSON.stringify(selectedEvent.attributes || {}, null, 2)}</pre>
              </article>
            ) : <CaptureTimeline replay={replay} busy={busy} onInspect={inspectEvent} />}
          </div>
        )}

        {tab === "sources" && (
          <div className="captureSources" role="tabpanel">
            <section>
              <div className="captureSectionTitle"><div><h3>Capture sources</h3><p>Only explicitly registered sources can write to this project.</p></div></div>
              <div className="captureSourceTable" role="table" aria-label="Capture sources">
                <div className="captureSourceRow header" role="row"><span>Source</span><span>Adapter</span><span>State</span><span>Action</span></div>
                {sources.map((source) => (
                  <div className="captureSourceRow" role="row" key={source.source_id}>
                    <span><strong>{source.source_id}</strong><small>{source.installation_scope}</small></span>
                    <span>{source.adapter}<small>v{source.adapter_version}</small></span>
                    <span className={`capturePill ${statusTone(source.state)}`}>{source.state}</span>
                    <button
                      aria-label={`${source.state === "active" ? "Pause" : "Resume"} ${source.source_id}`}
                      disabled={busy || source.state === "removed" || source.state === "error"}
                      onClick={() => run("source-state", { source_id: source.source_id, state: source.state === "active" ? "paused" : "active" }, `${source.source_id} ${source.state === "active" ? "paused" : "resumed"}.`)}
                    >
                      {source.state === "active" ? <Pause size={14} /> : <Play size={14} />}
                      {source.state === "active" ? "Pause" : "Resume"}
                    </button>
                  </div>
                ))}
                {!sources.length && <div className="captureState captureEmpty"><strong>No authorized sources</strong><span>Install an adapter or register an API source from the CLI.</span></div>}
              </div>
            </section>
            <section>
              <div className="captureSectionTitle"><div><h3>Bind a session</h3><p>Capture begins at the accepted cursor, never from hidden history.</p></div></div>
              <form className="captureForm" onSubmit={bindSession}>
                <label>Source<select value={binding.source_id || activeSource?.source_id || ""} onChange={(event) => setBinding({ ...binding, source_id: event.target.value })} required>{sources.filter((item) => item.state === "active").map((item) => <option key={item.source_id}>{item.source_id}</option>)}</select></label>
                <label>Session ID<input value={binding.external_session_id} onChange={(event) => setBinding({ ...binding, external_session_id: event.target.value })} required maxLength={512} /></label>
                <label>Start cursor<input type="number" min="0" value={binding.start_cursor} onChange={(event) => setBinding({ ...binding, start_cursor: event.target.value })} required /></label>
                <button type="submit" disabled={busy || !activeSource}><Link2 size={15} /> Bind session</button>
              </form>
              {bindingReceipt && <div className="captureReceipt" role="status"><CheckCircle2 size={16} /><span><strong>Binding active</strong><code>{shortId(bindingReceipt.binding_id, 16)}</code></span><button onClick={closeBinding}>Close binding</button></div>}
            </section>
            <section>
              <div className="captureSectionTitle"><div><h3>Policy preview</h3><p>Preview is deterministic and writes nothing.</p></div></div>
              <div className="captureForm">
                <label>Profile<select value={policy.profile} onChange={(event) => setPolicy({ ...policy, profile: event.target.value })}><option value="metadata-only">Metadata only</option><option value="continuity">Continuity</option><option value="forensic">Forensic</option></select></label>
                <label>Privacy ceiling<select value={policy.privacy_ceiling} onChange={(event) => setPolicy({ ...policy, privacy_ceiling: event.target.value })}><option>public</option><option>internal</option><option>sensitive</option><option>restricted</option></select></label>
                <label>Retention seconds<input type="number" min="0" value={policy.retention_seconds} onChange={(event) => setPolicy({ ...policy, retention_seconds: Number(event.target.value) })} /></label>
                <button type="button" onClick={previewPolicy} disabled={busy}><Eye size={15} /> Preview policy</button>
              </div>
              {policyPreview && <div className="captureReceipt" role="status"><ShieldCheck size={16} /><span><strong>{policyPreview.policy.profile}</strong><code>{shortId(policyPreview.policy_digest, 18)}</code></span><span>No state written</span></div>}
            </section>
          </div>
        )}

        {tab === "privacy" && (
          <div className="capturePrivacy" role="tabpanel">
            <section>
              <div className="captureSectionTitle"><div><h3>Privacy boundary</h3><p>Exports exclude retained payloads and pass a final secret-pattern check.</p></div></div>
              <div className="captureForm compact">
                <label>Privacy ceiling<select value={privacyCeiling} onChange={(event) => onPrivacyCeiling(event.target.value)}><option>public</option><option>internal</option><option>sensitive</option><option>restricted</option></select></label>
                <button onClick={previewRedaction} disabled={busy}><Eye size={15} /> Preview redaction</button>
                <button onClick={() => onExport(privacyCeiling)} disabled={busy}><Download size={15} /> Export JSON</button>
                <button disabled={busy || !activePolicy} onClick={previewRetention}><Clock3 size={15} /> Run retention</button>
              </div>
              {retentionPreview && <div className="captureDeletionPreview" role="alert"><AlertTriangle size={17} /><span><strong>Retention preview</strong><small>{retentionPreview.affected_content_records} content records and {retentionPreview.affected_payloads} payloads can expire.</small></span><button onClick={confirmRetention} disabled={busy}><Trash2 size={15} /> Confirm retention</button></div>}
              {privacyPreview && <div className="capturePrivacyProof" role="status"><CheckCircle2 size={17} /><div><strong>Redaction verified</strong><span>{privacyPreview.events.length} events, {privacyPreview.redaction_count} redactions, no payloads included</span></div></div>}
            </section>
            <section className="captureDangerZone">
              <div className="captureSectionTitle"><div><h3>Delete captured content</h3><p>The immutable integrity record remains; content is suppressed and payload material removed.</p></div></div>
              <form className="captureForm" onSubmit={previewDeletion}>
                <label>Scope<select value={deletion.scope} onChange={(event) => { setDeletion({ ...deletion, scope: event.target.value }); setDeletionPreview(null); }}><option value="event-content">Event</option><option value="session-content">Session</option><option value="source-content">Source</option><option value="project-content">Project</option></select></label>
                <label>Scope identifier<input value={deletion.scope_token} onChange={(event) => { setDeletion({ ...deletion, scope_token: event.target.value }); setDeletionPreview(null); }} required /></label>
                <label>Policy<select value={deletion.policy_digest || activePolicy?.policy_digest || ""} onChange={(event) => { setDeletion({ ...deletion, policy_digest: event.target.value }); setDeletionPreview(null); }}>{policies.map((item) => <option key={item.policy_digest} value={item.policy_digest}>{item.profile} v{item.policy_version}</option>)}</select></label>
                <button type="submit" disabled={busy || !activePolicy}><Eye size={15} /> Preview deletion</button>
              </form>
              {deletionPreview && <div className="captureDeletionPreview" role="alert"><AlertTriangle size={17} /><span><strong>{deletionPreview.affected_events} events affected</strong><small>This action cannot restore deleted payload material.</small></span><button onClick={confirmDeletion} disabled={busy}><Trash2 size={15} /> Confirm delete</button></div>}
            </section>
          </div>
        )}

        {tab === "diagnostics" && (
          <div className="captureDiagnostics" role="tabpanel">
            {!diagnostics ? (
              <div className="captureState" role="status">
                {busy ? <RefreshCw className="spin" size={20} /> : <AlertTriangle size={20} />}
                {busy ? "Loading capture diagnostics..." : "Capture diagnostics unavailable."}
              </div>
            ) : (
              <>
                <section className="captureDiagnosticHero">
                  {diagnostics.journal?.chain_valid ? <CheckCircle2 size={28} /> : <AlertTriangle size={28} />}
                  <div><h3>{diagnostics.journal?.chain_valid ? "Journal integrity verified" : "Journal needs attention"}</h3><p>Canonical checkout: {diagnostics.canonical_root_verified ? "verified" : "unverified"}</p></div>
                </section>
                <dl>
                  <div><dt>Journal events</dt><dd>{diagnostics.journal?.events_verified ?? 0}</dd></div>
                  <div><dt>Redactions</dt><dd>{diagnostics.events?.redactions ?? 0}</dd></div>
                  <div><dt>Truncations</dt><dd>{diagnostics.events?.truncations ?? 0}</dd></div>
                  <div><dt>Detected gaps</dt><dd>{diagnostics.events?.gaps ?? 0}</dd></div>
                  <div><dt>Queued records</dt><dd>{overview?.queue?.records ?? 0}</dd></div>
                  <div><dt>Spool bytes</dt><dd>{overview?.queue?.bytes ?? 0}</dd></div>
                </dl>
                <div className="captureTrustNote"><ShieldCheck size={17} /><p><strong>Replay is read-only.</strong> Captured commands and tool calls are evidence records; this console never re-executes them.</p></div>
              </>
            )}
          </div>
        )}
      </div>
      <span className="srOnly" role="status" aria-live="polite">{busy ? "Capture operation in progress" : `Capture workspace ready for ${project?.project || "project"}`}</span>
    </section>
  );
}
