import React, { useEffect, useRef, useState } from "react";
import { Download, List, Network, Search } from "lucide-react";
import "./impact-explorer.css";

export default function ImpactExplorer({ project, api }) {
  const [target, setTarget] = useState("");
  const [report, setReport] = useState(null);
  const [view, setView] = useState("graph");
  const [selected, setSelected] = useState(null);
  const [included, setIncluded] = useState([]);
  const [preview, setPreview] = useState(null);
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  useEffect(() => () => { generation.current += 1; }, []);
  function invalidate() {
    generation.current += 1;
    setReport(null); setPreview(null); setReviewed(false); setIncluded([]);
    setSelected(null); setBusy(false); setError("");
  }
  async function request(action) {
    const id = ++generation.current;
    setBusy(true); setError(""); setPreview(null); setReviewed(false);
    if (action === "inspect") { setReport(null); setIncluded([]); setSelected(null); }
    try {
      const payload = await api("/api/impact", { method: "POST", body: JSON.stringify({
        db_path: project.db_path, project: project.project, target: target.trim(), action,
        revision: report?.revision, source_ids: included,
      }) });
      if (id !== generation.current) return;
      if (action === "inspect") { setReport(payload); setSelected(payload.nodes[0]?.id ?? null); }
      else setPreview(payload);
    } catch (e) { if (id === generation.current) setError(e.message); }
    finally { if (id === generation.current) setBusy(false); }
  }
  function toggle(id) {
    generation.current += 1;
    setBusy(false); setPreview(null); setReviewed(false);
    setIncluded(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id]);
  }
  async function download() {
    if (!preview || !reviewed || busy) return;
    const id = ++generation.current;
    setBusy(true); setError("");
    try {
      const current = await api("/api/impact", { method: "POST", body: JSON.stringify({
        db_path: project.db_path, project: project.project, target: target.trim(), action: "preview",
        revision: report.revision, source_ids: included,
      }) });
      if (id !== generation.current) return;
      if (current.sha256 !== preview.sha256 || current.markdown !== preview.markdown) throw new Error("Evidence changed; refresh and review again.");
      const url = URL.createObjectURL(new Blob([current.markdown], { type: "text/markdown;charset=utf-8" }));
      const link = document.createElement("a"); link.href = url; link.download = "change-impact-handoff.md";
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      if (id === generation.current) { setPreview(null); setReviewed(false); setError(e.message); }
    } finally { if (id === generation.current) setBusy(false); }
  }
  const active = report?.nodes.find(node => node.id === selected);
  const path = active?.path_edge_ids || [];
  const pathEdges = report?.edges.filter(edge => path.includes(edge.id)) || [];
  const rows = {};
  const positioned = (report?.nodes || []).map(node => {
    const row = rows[node.distance] || 0; rows[node.distance] = row + 1;
    return { ...node, x: 16 + node.distance * 216, y: 40 + row * 96 };
  });
  const byId = new Map(positioned.map(node => [node.id, node]));
  const width = Math.max(240, ...positioned.map(node => node.x + 200));
  const height = Math.max(180, ...positioned.map(node => node.y + 90));
  return <section className="impactExplorer" aria-label="Change impact" aria-busy={busy}>
    <form onSubmit={event => { event.preventDefault(); if (target.trim() && !busy) request("inspect"); }}>
      <label>Symbol or file<input value={target} maxLength={500} onChange={event => { invalidate(); setTarget(event.target.value); }} placeholder="queue_budget" /></label>
      <button className="primarySmall" type="submit" disabled={busy || !target.trim()}><Search size={16} />{busy ? "Reading evidence..." : "Trace relationships"}</button>
    </form>
    {error && <p role="alert">{error}</p>}
    {report && <>
      <div className="impactSummary"><strong>Indexed evidence only</strong><span>{report.nodes.length} visible entities / {report.edges.length} relationships</span></div>
      {report.status === "no_match" ? <p role="status">No eligible indexed relationships found.</p> : <>
        <div className="impactViews" role="group" aria-label="Impact view">
          <button title="Graph view" aria-label="Graph view" aria-pressed={view === "graph"} onClick={() => setView("graph")}><Network size={17} /></button>
          <button title="List view" aria-label="List view" aria-pressed={view === "list"} onClick={() => setView("list")}><List size={17} /></button>
        </div>
        {view === "graph" ? <div className="impactGraphScroll" role="group" aria-label="Relationship graph">
          <div className="impactGraph" style={{ width, height }}>
            <svg width={width} height={height} aria-hidden="true">
              <defs><marker id="impact-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" /></marker></defs>
              {report.edges.map(edge => { const a = byId.get(edge.from_id), b = byId.get(edge.to_id); if (!a || !b) return null;
                return <path key={edge.id} className={path.includes(edge.id) ? "selected" : ""} markerEnd="url(#impact-arrow)" d={`M ${a.x} ${a.y + 35} C ${a.x - 35} ${a.y + 35}, ${b.x + 220} ${b.y + 35}, ${b.x + 184} ${b.y + 35}`} />;
              })}
            </svg>
            {positioned.map(node => <button key={node.id} className={`impactNode ${node.id === selected ? "selected" : ""}`} style={{ left: node.x, top: node.y }} aria-label={`Inspect ${node.name}`} aria-pressed={node.id === selected} onClick={() => setSelected(node.id)} title={node.name}>
              <span>{node.name}</span><small>{node.distance === 0 ? "Target" : `${node.distance} hop${node.distance === 1 ? "" : "s"}`}</small>
            </button>)}
          </div>
        </div> : <ul className="impactEntityList">{report.nodes.map(node => <li key={node.id}><button aria-label={`Inspect ${node.name}`} aria-pressed={node.id === selected} onClick={() => setSelected(node.id)}>{node.name}<small>{node.distance} hops</small></button></li>)}</ul>}
        {active && <section className="impactPath" aria-label="Selected relationship path"><h3>{active.name}</h3>
          {pathEdges.length ? <ol>{pathEdges.map(edge => <li key={edge.id}><code>{edge.from_name}</code> <strong>{edge.relation}</strong> <code>{edge.to_name}</code><small>Indexed relationship; correctness not independently verified</small></li>)}</ol> : <p>Selected target</p>}
        </section>}
        <section className="impactEvidence" aria-label="Source evidence"><h3>Source evidence</h3>
          {report.evidence.map(item => <div key={item.source_id} className={pathEdges.some(edge => edge.source_id === item.source_id) ? "onPath" : ""}>
            <label><input type="checkbox" checked={included.includes(item.source_id)} onChange={() => toggle(item.source_id)} aria-label={`Include ${item.path}`} />{item.path}</label>
            <details><summary>Indexed excerpt</summary><pre tabIndex={0}>{item.excerpt || "Excerpt omitted by context budget"}</pre><small>Indexed: {item.indexed_at}</small><code className="impactHash">{item.source_hash || "Hash unavailable"}</code></details>
          </div>)}
        </section>
        <button onClick={() => request("preview")} disabled={busy || !included.length}>Preview handoff</button>
        {preview && <section className="impactPreview"><pre tabIndex={0} aria-label="Handoff preview">{preview.markdown}</pre>
          <label><input type="checkbox" checked={reviewed} onChange={e => setReviewed(e.target.checked)} />I reviewed this selection for sensitive information</label>
          <button title="Download reviewed Markdown" onClick={download} disabled={!reviewed || busy}><Download size={16} />Download handoff</button>
        </section>}
      </>}
      <details className="impactCoverage"><summary>Coverage and limitations</summary><ul>{report.coverage.limitations.map(text => <li key={text}>{text}</li>)}</ul>{report.coverage.bounded && <p>Result limit reached.</p>}</details>
    </>}
  </section>;
}
