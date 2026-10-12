import React, { useEffect, useRef, useState } from "react";
import { ArrowRight, BookOpen, Check, Clipboard, Download, FileClock, RefreshCw, Save, ShieldCheck } from "lucide-react";
import "./project-passport.css";

const fields = [["objective", "Objective"], ["next_action", "Next action"], ["verified_evidence", "Reported evidence"], ["remaining_gaps", "Open questions"], ["prohibited_repetition", "Avoid repeating"]];
const emptySelection = () => ({ label: "Project", checkpoint_fields: [], decision_ids: [], include_changes: false });
const date = value => value ? new Date(value).toLocaleString() : "Not recorded";

export default function ProjectPassport({ project, api, onSetup, onDirtyChange }) {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("Resume");
  const [form, setForm] = useState({});
  const [dirty, setDirty] = useState(false);
  const [checkpointVersion, setCheckpointVersion] = useState(0);
  const [decision, setDecision] = useState("");
  const [selection, setSelection] = useState(emptySelection);
  const [preview, setPreview] = useState(null);
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const mounted = useRef(false);
  const inFlight = useRef(false);
  const identity = { project: project?.project, db_path: project?.db_path };
  const request = (endpoint, body = {}) => api(endpoint, { method: "POST", body: JSON.stringify({ ...identity, ...body }) });
  const invalidate = () => { setPreview(null); setReviewed(false); setMessage(""); };
  async function refresh(preserveDraft = false) {
    const result = await request("/api/passport");
    if (!mounted.current) return;
    setData(result);
    if (!preserveDraft) {
      setForm(Object.fromEntries(fields.map(([key]) => [key, result.checkpoint?.[key] || ""])));
      setDirty(false);
      setCheckpointVersion(result.checkpoint?.version || 0);
    }
    setSelection(emptySelection()); invalidate();
  }
  async function run(operation) {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true); setError(""); setMessage("");
    try { await operation(); }
    catch (failure) { if (mounted.current) setError(failure.code === "authorization_required" ? "Authorization expired. Open the private console URL from the launcher in a new tab. Do not share that URL." : failure.message || "Operation failed. Try again."); }
    finally { if (mounted.current) { inFlight.current = false; setBusy(false); } }
  }
  useEffect(() => {
    mounted.current = true;
    if (project) run(refresh);
    return () => { mounted.current = false; };
  }, []);
  useEffect(() => {
    const unsaved = dirty || Boolean(decision.trim());
    onDirtyChange?.(unsaved);
    const guard = event => { if (unsaved) { event.preventDefault(); event.returnValue = ""; } };
    window.addEventListener("beforeunload", guard);
    return () => window.removeEventListener("beforeunload", guard);
  }, [dirty, decision]);
  function changeSelection(patch) { setSelection(value => ({ ...value, ...patch })); invalidate(); }
  function toggle(key, value) { changeSelection({ [key]: selection[key].includes(value) ? selection[key].filter(item => item !== value) : [...selection[key], value] }); }
  async function buildPreview() { return request("/api/passport", { action: "preview", revision: data.revision, selection }); }
  async function deliver(format) {
    if (!reviewed || !preview) return;
    let current;
    try { current = await buildPreview(); }
    catch (failure) { if (mounted.current) invalidate(); throw failure; }
    if (!mounted.current) return;
    if (current.sha256 !== preview.sha256 || current.markdown_sha256 !== preview.markdown_sha256) { invalidate(); throw new Error("Handoff changed. Preview and review it again."); }
    if (format === "copy") {
      await navigator.clipboard.writeText(preview.markdown);
      if (mounted.current) setMessage("Handoff copied. Nothing was sent to an assistant.");
      return;
    }
    const content = format === "json" ? preview.json : preview.markdown;
    const url = URL.createObjectURL(new Blob([content], { type: format === "json" ? "application/json;charset=utf-8" : "text/markdown;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url; link.download = `project-passport.${format === "json" ? "json" : "md"}`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setMessage("Handoff downloaded. Nothing was sent to an assistant.");
  }
  const selectedCount = selection.checkpoint_fields.length + selection.decision_ids.length + Number(selection.include_changes);
  return <section className="projectPassport" aria-label="Project Passport" aria-busy={busy}>
    <header className="passportHeader">
      <div><span className="passportEyebrow"><BookOpen size={15} /> Rta-Smriti</span><h1>Project Passport</h1><p>{project?.project || "No project selected"}</p></div>
      <div className="passportHeaderActions"><span><ShieldCheck size={15} /> Local workspace</span><button aria-label="Refresh Passport" title="Refresh Passport" disabled={!project || busy} onClick={() => { if (!dirty || window.confirm("Discard unsaved checkpoint edits and refresh?")) run(refresh); }}><RefreshCw size={17} /></button></div>
    </header>
    <p className="passportNotice" role="status">{busy ? "Working..." : message || ""}</p>
    {error && <p className="passportError" role="alert">{error}</p>}
    {!project && <div className="passportEmpty"><h2>No project yet</h2><button onClick={onSetup}><ArrowRight size={16} /> Add a project</button></div>}
    {project && !data && !error && <p>Loading project evidence...</p>}
    {data && <>
      <div className="passportSummary"><span>Checkpoint <strong>{data.checkpoint ? `v${data.checkpoint.version}` : "Not saved"}</strong></span><span>Decisions <strong>{data.decisions_total}</strong></span><span>Last index <strong>{date(data.changes.indexed_at)}</strong></span></div>
      <div className="passportTabs" role="tablist" aria-label="Passport sections">{["Resume", "Changes", "Decisions", "Handoff"].map((name, index, tabs) => <button key={name} id={`passport-tab-${name}`} role="tab" tabIndex={tab === name ? 0 : -1} aria-selected={tab === name} aria-controls="passport-panel" onClick={() => setTab(name)} onKeyDown={event => {
        const next = event.key === "ArrowRight" ? (index + 1) % tabs.length : event.key === "ArrowLeft" ? (index + tabs.length - 1) % tabs.length : event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : null;
        if (next !== null) { event.preventDefault(); setTab(tabs[next]); document.getElementById(`passport-tab-${tabs[next]}`)?.focus(); }
      }}>{name}{name === "Handoff" && selectedCount > 0 ? ` (${selectedCount})` : ""}</button>)}</div>
      <div id="passport-panel" role="tabpanel" aria-labelledby={`passport-tab-${tab}`} className="passportPanel">
        {tab === "Resume" && <>
          <div className="passportSectionHeading"><h2>Where did I leave off?</h2><span>{data.checkpoint ? `Saved ${date(data.checkpoint.updated_at)} by ${data.checkpoint.source}` : "No checkpoint saved"}</span></div>
          <form onSubmit={event => { event.preventDefault(); run(async () => {
            await request("/api/checkpoint", { ...form, expected_version: checkpointVersion });
            if (!mounted.current) return;
            setDirty(false); invalidate();
            try { await refresh(); }
            catch { throw new Error("Checkpoint saved, but the view could not refresh. Refresh Passport before editing again."); }
            if (mounted.current) setMessage("Checkpoint saved.");
          }); }}><fieldset disabled={busy} className="passportForm">
            {fields.map(([key, label]) => <label key={key}>{label}<textarea aria-label={label} value={form[key] || ""} required={key === "objective"} maxLength={20000} rows={key === "objective" ? 2 : 3} onChange={event => { setForm(value => ({ ...value, [key]: event.target.value })); setDirty(true); invalidate(); }} /></label>)}
            <div className="passportActions"><button type="submit" disabled={!form.objective?.trim()}><Save size={16} /> Save checkpoint</button><span>{dirty ? "Unsaved changes" : "Saved evidence is historical; verify before acting."}</span></div>
          </fieldset></form>
        </>}
        {tab === "Changes" && <>
          <div className="passportSectionHeading"><h2>What changed?</h2><span><FileClock size={15} /> Indexed activity</span></div>
          <p className="passportWarning">{data.changes.limitation}</p>
          {!data.changes.index_consistent && <p className="passportError">Index receipt is missing or inconsistent. Source verification is required.</p>}
          <p>{data.changes.indexed_files} indexed files. Checkpoint: {date(data.changes.since)}.</p>
          <button disabled={busy} onClick={() => run(async () => { invalidate(); await request("/api/ingest-repo"); await refresh(dirty); if (mounted.current) setMessage("Folder index refreshed. Review the indexed activity below."); })}><RefreshCw size={16} /> Refresh folder index</button>
          {!data.checkpoint ? <p>No checkpoint exists for comparison.</p> : !data.changes.items.length ? <p>No indexed activity since this checkpoint. This does not establish that the working folder is unchanged.</p> : <ul className="passportActivity">{data.changes.items.map((item, index) => <li key={index}><FileClock size={16} /><span>{item.path}</span><time>{date(item.indexed_at)}</time></li>)}</ul>}
          {data.changes.truncated && <p>Showing the latest 40 indexed entries. More activity is omitted.</p>}
        </>}
        {tab === "Decisions" && <>
          <div className="passportSectionHeading"><h2>Why did we decide that?</h2><span>{data.decisions_total} available decisions</span></div>
          <form onSubmit={event => { event.preventDefault(); run(async () => {
            try {
              await request("/api/memory", { text: decision, type: "decision", pramana: "sabda", confidence: 0.75, provenance: { verification_status: "unverified", metadata: { source: "passport-operator" } } });
            } catch (failure) {
              if (!failure.status) throw new Error("The decision may have been saved, but confirmation was lost. Refresh Passport and check the list before retrying. Your draft is preserved.");
              throw failure;
            }
            if (!mounted.current) return;
            setDecision("");
            try { await refresh(dirty); }
            catch { throw new Error("Decision saved, but the view could not refresh. Refresh Passport before adding it again."); }
            if (mounted.current) setMessage("Decision saved as unverified operator testimony.");
          }); }}><fieldset disabled={busy} className="passportForm"><label>Decision and reason<textarea aria-label="Decision and reason" required value={decision} onChange={event => setDecision(event.target.value)} maxLength={20000} rows={3} /></label><div><button type="submit" disabled={!decision.trim()}><Save size={16} /> Save decision</button></div></fieldset></form>
          <ul className="passportDecisions">{data.decisions.map(item => <li key={item.id}><p>{item.text}</p><span>Reported status: <strong>{item.verification}</strong> | {date(item.updated_at)}{item.truncated && " | Excerpt truncated"}</span></li>)}</ul>
          {!data.decisions.length && <p>No shareable decisions recorded. Private or restricted records are excluded.</p>}
          {data.decisions_truncated && <p>Showing the latest 40 eligible decisions.</p>}
        </>}
        {tab === "Handoff" && <>
          <div className="passportSectionHeading"><h2>What will this assistant receive?</h2><span>{selectedCount} selected items</span></div>
          <fieldset disabled={busy} className="passportSelection">
            <label className="passportAlias">Export label<input maxLength={100} value={selection.label} onChange={event => changeSelection({ label: event.target.value })} /></label>
            <div className="passportSelectionColumns"><div><h3>Checkpoint</h3>{fields.map(([key, label]) => <label className="passportCheck" key={key}><input type="checkbox" aria-label={`Include ${label.toLowerCase()}`} disabled={!data.checkpoint || dirty} checked={selection.checkpoint_fields.includes(key)} onChange={() => toggle("checkpoint_fields", key)} /><span>{label}</span></label>)}{dirty && <p>Save or discard your checkpoint edits before selecting it.</p>}
              <label className="passportCheck"><input type="checkbox" checked={selection.include_changes} onChange={event => changeSelection({ include_changes: event.target.checked })} /><span>Include index summary and relative paths</span></label></div>
              <div><h3>Decisions</h3>{data.decisions.map(item => <label className="passportCheck" key={item.id}><input type="checkbox" checked={selection.decision_ids.includes(item.id)} onChange={() => toggle("decision_ids", item.id)} /><span>{item.text}<small>{item.verification}{item.truncated ? " | Excerpt truncated" : ""}</small></span></label>)}{!data.decisions.length && <p>No eligible decisions.</p>}</div>
            </div>
            <button disabled={!selectedCount || !selection.label.trim() || dirty} onClick={() => run(async () => { invalidate(); const value = await buildPreview(); if (mounted.current) setPreview(value); })}><ArrowRight size={16} /> Preview handoff</button>
          </fieldset>
          {preview && <div className="passportPreview"><h3>Handoff preview</h3><p>{preview.redactions} known sensitive matches redacted. Review for private information the detector may miss.</p>
            <pre aria-label="Handoff preview" tabIndex={0}>{preview.markdown}</pre>
            <details><summary>JSON checksum (SHA-256, not a signature)</summary><code>{preview.sha256}</code></details>
            <label className="passportCheck"><input type="checkbox" disabled={busy} checked={reviewed} onChange={event => setReviewed(event.target.checked)} /><span>I reviewed this handoff for sensitive information</span></label>
            <div className="passportActions"><button disabled={!reviewed || busy} onClick={() => run(() => deliver("copy"))}><Clipboard size={16} /> Copy handoff</button><button disabled={!reviewed || busy} onClick={() => run(() => deliver("md"))}><Download size={16} /> Download Markdown</button><button disabled={!reviewed || busy} onClick={() => run(() => deliver("json"))}><Download size={16} /> Download JSON</button></div>
            <p className="passportLocal"><Check size={15} /> No assistant connection or automatic upload.</p>
          </div>}
        </>}
      </div>
    </>}
  </section>;
}
