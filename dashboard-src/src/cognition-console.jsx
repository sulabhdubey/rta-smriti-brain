import React, { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Download,
  FileSearch,
  GitBranch,
  Image,
  Plus,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import "./cognition-console.css";


const TABS = [
  { id: "debt", label: "Decision Debt", icon: AlertTriangle },
  { id: "twin", label: "Project Twin", icon: BrainCircuit },
  { id: "coverage", label: "Coverage", icon: ShieldCheck },
  { id: "impact", label: "Change Impact", icon: GitBranch },
  { id: "media", label: "Media", icon: Image },
];

const STATUS_OPTIONS = ["observed", "missing", "stale", "conflicting", "blocked", "unknown"];

function classForState(value) {
  const state = String(value || "unknown").toLowerCase();
  if (["ready", "fresh", "observed", "current", "verified"].includes(state)) return "positive";
  if (["critical", "blocked", "conflicting", "changed", "disputed"].includes(state)) return "critical";
  if (["high", "stale", "missing", "operationally_not_ready"].includes(state)) return "warning";
  return "neutral";
}

function EmptyState({ title, detail }) {
  return (
    <div className="cognitionEmpty" role="status">
      <CheckCircle2 size={22} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function StatusPill({ children, state }) {
  return <span className={`cognitionPill ${classForState(state)}`}>{children}</span>;
}

function DebtView({ debt, onOpenTruth }) {
  const items = debt?.items || [];
  const [selectedId, setSelectedId] = useState(items[0]?.claim_id || "");
  const selected = items.find((item) => item.claim_id === selectedId) || items[0];
  if (!items.length) {
    return <EmptyState title="No active decision debt" detail="No unsupported, expired, contradicted, or failed accepted claims were found." />;
  }
  return (
    <div className="cognitionSplit">
      <div className="cognitionQueue" role="list" aria-label="Decision debt queue">
        {items.map((item) => (
          <div key={item.claim_id} role="listitem">
            <button
              className={selected?.claim_id === item.claim_id ? "cognitionRow selected" : "cognitionRow"}
              onClick={() => setSelectedId(item.claim_id)}
            >
              <span className={`severityMarker ${classForState(item.severity)}`} />
              <span className="cognitionRowCopy">
                <strong>{item.subject}</strong>
                <small>{item.predicate} · {item.reasons.join(" · ")}</small>
              </span>
              <StatusPill state={item.severity}>{item.severity}</StatusPill>
            </button>
          </div>
        ))}
      </div>
      {selected && (
        <aside className="cognitionDetail" aria-label="Selected decision debt">
          <div className="cognitionDetailHeader">
            <span>Claim {selected.claim_id}</span>
            <StatusPill state={selected.severity}>{selected.severity}</StatusPill>
          </div>
          <h3>{selected.subject}</h3>
          <dl className="cognitionFacts">
            <div><dt>State</dt><dd>{selected.epistemic_state}</dd></div>
            <div><dt>Evidence</dt><dd>{selected.supporting_evidence}</dd></div>
            <div><dt>Validator</dt><dd>{selected.validator_outcome || "not configured"}</dd></div>
            <div><dt>Blast radius</dt><dd>{selected.blast_radius}</dd></div>
          </dl>
          <div className="cognitionReasonList">
            <span>Open reasons</span>
            {selected.reasons.map((reason) => <div key={reason}><AlertTriangle size={14} /> {reason}</div>)}
          </div>
          <p>{selected.repair}</p>
          <button className="cognitionPrimary" onClick={onOpenTruth}><Activity size={15} /> Inspect truth evidence</button>
        </aside>
      )}
    </div>
  );
}

function TwinView({ twin, busy, onReconcile }) {
  const observations = twin?.observations || [];
  const [selectedId, setSelectedId] = useState(observations[0]?.observation_id || "");
  const selected = observations.find((item) => item.observation_id === selectedId) || observations[0];
  const [nextStatus, setNextStatus] = useState("observed");
  const [reason, setReason] = useState("");
  if (!observations.length) {
    return <EmptyState title="No project observations" detail="The project twin has no imported external observations." />;
  }
  return (
    <div className="cognitionSplit">
      <div className="cognitionQueue" role="list" aria-label="Project twin observations">
        {observations.map((item, index) => {
          const key = item.observation_id || `${item.subsystem}:${item.entity_key}:${index}`;
          return (
            <div key={key} role="listitem">
              <button
                className={selected === item ? "cognitionRow selected" : "cognitionRow"}
                onClick={() => setSelectedId(item.observation_id || "")}
              >
                <span className={`severityMarker ${classForState(item.status)}`} />
                <span className="cognitionRowCopy">
                  <strong>{item.entity_key}</strong>
                  <small>{item.subsystem} · {item.observed_state}</small>
                </span>
                <StatusPill state={item.status}>{item.status}</StatusPill>
              </button>
            </div>
          );
        })}
      </div>
      {selected && (
        <aside className="cognitionDetail" aria-label="Selected project observation">
          <div className="cognitionDetailHeader"><span>{selected.subsystem}</span><StatusPill state={selected.status}>{selected.status}</StatusPill></div>
          <h3>{selected.entity_key}</h3>
          <dl className="cognitionFacts">
            <div><dt>Expected</dt><dd>{selected.expected_state || "not declared"}</dd></div>
            <div><dt>Observed</dt><dd>{selected.observed_state}</dd></div>
            <div><dt>Source</dt><dd>{selected.source_identifier || "derived locally"}</dd></div>
            <div><dt>Observed at</dt><dd>{selected.observed_at || "current snapshot"}</dd></div>
          </dl>
          {selected.observation_id ? (
            <form
              className="reconcileForm"
              onSubmit={(event) => {
                event.preventDefault();
                if (reason.trim()) onReconcile(selected.observation_id, nextStatus, reason.trim());
              }}
            >
              <label>Status<select value={nextStatus} onChange={(event) => setNextStatus(event.target.value)}>{STATUS_OPTIONS.map((status) => <option key={status}>{status}</option>)}</select></label>
              <label>Reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Evidence-backed reconciliation reason" /></label>
              <button className="cognitionPrimary" disabled={busy || !reason.trim()}><ShieldCheck size={15} /> Apply reconciliation</button>
            </form>
          ) : (
            <p className="cognitionNote">Derived repository observations change only when their source evidence changes.</p>
          )}
        </aside>
      )}
    </div>
  );
}

function CoverageView({ coverage }) {
  const subsystems = coverage?.subsystems || {};
  const keys = ["verified", "known", "stale", "disputed", "blocked", "unknown"];
  if (!Object.keys(subsystems).length) return <EmptyState title="Coverage unavailable" detail="No bounded coverage projection is available for this project." />;
  return (
    <div className="coverageTable" role="table" aria-label="Knowledge coverage by subsystem">
      <div className="coverageHeader" role="row"><span>Subsystem</span>{keys.map((key) => <span key={key}>{key}</span>)}</div>
      {Object.entries(subsystems).map(([name, values]) => (
        <div className="coverageRow" role="row" key={name}>
          <strong>{name}</strong>
          {keys.map((key) => <span key={key} className={values[key] ? classForState(key) : "muted"}>{values[key] || 0}</span>)}
        </div>
      ))}
      <p>{(coverage?.summary?.limitations || []).join(" ")}</p>
    </div>
  );
}

function ImpactView({ impact }) {
  const items = impact?.items || [];
  if (!items.length) return <EmptyState title="No working-tree impact" detail={impact?.reason || "The current checkout has no changed paths."} />;
  return (
    <div className="impactList">
      {items.map((item) => (
        <article key={item.path} className="impactRow">
          <FileSearch size={17} />
          <div><strong>{item.path}</strong><span>{item.symbols.length} symbols · {item.related_tests.length} tests · {item.affected_claims.length} claims</span></div>
          <StatusPill state={item.confidence === "direct" ? "verified" : "unknown"}>{item.confidence}</StatusPill>
        </article>
      ))}
    </div>
  );
}

function MediaView({ media, busy, onAdd, onVerify, onExport }) {
  const [path, setPath] = useState("");
  const verification = media?.verification || {};
  const [privacy, setPrivacy] = useState("internal");
  const items = media?.items || [];
  return (
    <div className="mediaWorkspace">
      <form className="mediaAdd" onSubmit={(event) => { event.preventDefault(); if (path.trim()) onAdd(path.trim(), privacy); }}>
        <label>Project-relative source<input value={path} onChange={(event) => setPath(event.target.value)} placeholder="docs/proof.png" /></label>
        <label>Privacy<select value={privacy} onChange={(event) => setPrivacy(event.target.value)}><option>internal</option><option>sensitive</option><option>restricted</option><option>public</option></select></label>
        <button className="cognitionPrimary" disabled={busy || !path.trim()}><Plus size={15} /> Add source</button>
        <button type="button" onClick={() => onExport("local")} disabled={busy}><Download size={15} /> Export manifest</button>
      </form>
      {!items.length ? <EmptyState title="No media evidence" detail="Add a bounded PDF, image, audio, video, diagram, or document inside the canonical project root." /> : (
        <div className="mediaList" role="list" aria-label="Multimodal evidence sources">
          {items.map((item) => {
            const verificationState = verification[item.source_id];
            const displayState = verificationState || (item.verified_derivations ? "verified" : "unknown");
            return <div className="mediaRow" role="listitem" key={item.source_id}>
              <Image size={18} />
              <span><strong>{item.source_identifier}</strong><small>{item.media_kind} · {(item.byte_size / 1024).toFixed(1)} KB · {item.derivation_count} derivations</small></span>
              <StatusPill state={displayState}>{verificationState || (item.verified_derivations ? "verified" : "unverified")}</StatusPill>
              <button onClick={() => onVerify(item.source_id)} disabled={busy}><RefreshCw size={14} /> Verify</button>
            </div>
          })}
        </div>
      )}
    </div>
  );
}

export default function CognitionConsole({
  data,
  busy,
  error,
  onRefresh,
  onReconcile,
  onAddMedia,
  onVerifyMedia,
  onExportMedia,
  onOpenTruth,
}) {
  const [tab, setTab] = useState("debt");
  const readiness = data?.readiness;
  const coverage = data?.knowledge_coverage;
  const metrics = useMemo(() => [
    ["Readiness", readiness?.state || "loading"],
    ["Repository", data?.repository?.freshness || "loading"],
    ["Critical debt", data?.decision_debt?.critical || 0],
    ["Verified", `${Math.round((coverage?.summary?.verified_ratio || 0) * 100)}%`],
    ["Changed paths", data?.change_impact?.changed_paths?.length || 0],
  ], [data, readiness, coverage]);
  return (
    <section className="cognitionConsole" aria-label="Project cognition cockpit">
      <header className="cognitionHeader">
        <div><span className="cognitionKicker"><BrainCircuit size={15} /> Sovereign cognition</span><h2>Project Reality</h2></div>
        <div className="cognitionHeaderActions">
          <StatusPill state={readiness?.state}>{readiness?.state?.replaceAll("_", " ") || "loading"}</StatusPill>
          <button onClick={onRefresh} disabled={busy}><RefreshCw size={15} className={busy ? "spin" : ""} /> Refresh</button>
        </div>
      </header>
      {error && <div className="cognitionError" role="alert"><AlertTriangle size={16} /> {error}<button onClick={onRefresh}>Retry</button></div>}
      <div className="cognitionMetrics" aria-label="Cognition summary">
        {metrics.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
      </div>
      <nav className="cognitionTabs" aria-label="Cognition views">
        {TABS.map(({ id, label, icon: Icon }) => <button key={id} aria-pressed={tab === id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}><Icon size={15} /> {label}</button>)}
      </nav>
      <div className="cognitionBody" aria-busy={busy && !data}>
        {!data && !error ? <div className="cognitionLoading"><BrainCircuit size={24} /><span>Project cognition is loading...</span></div> : null}
        {data && tab === "debt" ? <DebtView debt={data.decision_debt} onOpenTruth={onOpenTruth} /> : null}
        {data && tab === "twin" ? <TwinView twin={data.project_twin} busy={busy} onReconcile={onReconcile} /> : null}
        {data && tab === "coverage" ? <CoverageView coverage={data.knowledge_coverage} /> : null}
        {data && tab === "impact" ? <ImpactView impact={data.change_impact} /> : null}
        {data && tab === "media" ? <MediaView media={data.multimodal} busy={busy} onAdd={onAddMedia} onVerify={onVerifyMedia} onExport={onExportMedia} /> : null}
      </div>
    </section>
  );
}
