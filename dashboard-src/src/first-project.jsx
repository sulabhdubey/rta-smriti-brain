import React, { useEffect, useRef, useState } from "react";
import "./first-project.css";
import { Cable, CheckCircle2, Clipboard, FileText, RefreshCw, Rocket, Save, Search } from "lucide-react";

export default function FirstProject({ api, onDone, shellKind, selectedProject, targetAgents }) {
  const [path, setPath] = useState("");
  const [project, setProject] = useState("");
  const [agent, setAgent] = useState("codex");
  const [provider, setProvider] = useState("hash");
  const [writeAgents, setWriteAgents] = useState(false);
  const [sync, setSync] = useState(true);
  const [capture, setCapture] = useState(false);
  const [continuity, setContinuity] = useState(false);
  const [binding, setBinding] = useState(null);
  const [receipt, setReceipt] = useState(null);
  const [decision, setDecision] = useState("");
  const [saved, setSaved] = useState(null);
  const [query, setQuery] = useState("");
  const [recovered, setRecovered] = useState(null);
  const [mcp, setMcp] = useState(null);
  const [pack, setPack] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const generation = useRef(0);
  const inFlight = useRef(false);
  useEffect(() => () => { generation.current += 1; }, []);
  useEffect(() => {
    if (binding && busy !== "setup" && (selectedProject?.project !== binding.project || selectedProject?.db_path !== binding.db_path)) {
      resetProof(); setBinding(null); setReceipt(null); setBusy("");
    }
  }, [selectedProject?.project, selectedProject?.db_path, binding, busy]);

  function resetProof() {
    generation.current += 1;
    setSaved(null); setRecovered(null); setMcp(null); setPack("");
    setDecision(""); setQuery(""); setError(""); setNotice("");
  }

  async function run(label, operation) {
    if (inFlight.current) return;
    inFlight.current = true;
    const current = generation.current;
    setBusy(label); setError(""); setNotice("");
    try { await operation(() => current === generation.current); }
    catch (failure) { if (current === generation.current) setError(failure.message); }
    finally { inFlight.current = false; if (current === generation.current) setBusy(""); }
  }

  const post = (endpoint, values) => api(endpoint, { method: "POST", body: JSON.stringify(values) });
  const identity = binding ? { db_path: binding.db_path, project: binding.project } : null;

  async function setup() {
    if (!path.trim()) { setError("Enter a project folder."); return; }
    await run("setup", async active => {
      const result = await post("/api/bootstrap", {
        path: path.trim(), project: project.trim() || null, target_agent: agent,
        embedding_provider: provider, write_agents: writeAgents,
        start_sync: sync, start_universal_capture: capture, start_continuity_capture: continuity,
      });
      if (!active()) return;
      setReceipt(result);
      if (!result.ready) throw new Error(`Setup needs attention at ${result.error?.stage || "verification"}: ${result.error?.message || "Verification incomplete"}`);
      const refreshed = await onDone({ project: result.project, db_path: result.db_path });
      if (!active()) return;
      if (!refreshed) throw new Error("Dashboard refresh failed after setup. The brain was created, but the operator console cleared selection until the exact project/database identity can be verified.");
      setBinding({ project: result.project, db_path: result.db_path });
    });
  }

  async function save() {
    if (!identity || !decision.trim()) return;
    await run("save", async active => {
      const result = await post("/api/memory", {
        ...identity, text: decision.trim(), type: "decision", pramana: "sabda", confidence: 0.75,
        provenance: { verification_status: "unverified", metadata: { source: "operator-first-project" } },
      });
      if (!active()) return;
      if (result.memory?.project !== identity.project || result.memory?.text !== decision.trim()) throw new Error("Saved decision identity could not be verified.");
      setSaved(result.memory); setQuery(result.memory.text); setRecovered(null); setPack("");
    });
  }

  async function recover() {
    if (!identity || !query.trim()) return;
    setRecovered(null); setPack("");
    await run("recover", async active => {
      const result = await post("/api/search", { ...identity, query: query.trim(), limit: 8 });
      if (!active()) return;
      if (result.access?.mode !== "read_only" || result.access?.writes_performed !== false) throw new Error("Read-only recovery was not confirmed by the server.");
      const memories = (result.memories || []).filter(memory => memory.project === identity.project && memory.type === "decision");
      setRecovered({ memories, exact: Boolean(saved && memories.some(memory => memory.id === saved.id && memory.text === saved.text)) });
    });
  }

  async function copy(text) {
    await run("copy", async active => { await navigator.clipboard.writeText(text); if (active()) setNotice("Copied"); });
  }

  return <div className="drawerContent pilotFlow">
    <h2>First project</h2>
    <ol className="pilotSteps" aria-label="First project progress">
      <li aria-current={!binding ? "step" : undefined}>Project</li>
      <li aria-current={binding && !saved ? "step" : undefined}>Decision</li>
      <li aria-current={saved ? "step" : undefined}>Recovery</li>
    </ol>
    {!binding ? <>
      {selectedProject && <button disabled={Boolean(busy)} onClick={() => { resetProof(); setBinding({ db_path: selectedProject.db_path, project: selectedProject.project }); }}><FileText size={15} /> Use selected project</button>}
      <fieldset disabled={Boolean(busy)}>
        <legend>Local project</legend>
        <label><span>Project Folder</span><input value={path} onChange={event => setPath(event.target.value)} placeholder={shellKind === "powershell" ? "C:\\path\\to\\project" : "/path/to/project"} /></label>
        <label><span>Target Agent</span><select value={agent} onChange={event => setAgent(event.target.value)}>{targetAgents.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
        <label className="checkLabel"><input type="checkbox" checked={sync} onChange={event => setSync(event.target.checked)} /><span>Keep repository index current</span></label>
        <label className="checkLabel"><input type="checkbox" checked={continuity} onChange={event => setContinuity(event.target.checked)} /><span>Capture Codex sessions for this project</span></label>
        <label className="checkLabel"><input type="checkbox" checked={capture} onChange={event => setCapture(event.target.checked)} /><span>Run capture normalization</span></label>
        <details><summary>Advanced settings</summary>
          <label><span>Project Name</span><input value={project} onChange={event => setProject(event.target.value)} placeholder="Derived from folder when blank" /></label>
          <label><span>Retrieval</span><select value={provider} onChange={event => setProvider(event.target.value)}><option value="hash">Local hybrid</option><option value="none">Lexical and structural</option></select></label>
          <label className="checkLabel"><input type="checkbox" checked={writeAgents} onChange={event => setWriteAgents(event.target.checked)} /><span>Write the optional AGENTS.md bridge into this project</span></label>
        </details>
      </fieldset>
      <div className="pilotConsent" aria-label="Setup changes">
        <strong>Local changes</strong>
        <ul><li>Index the canonical project into a local SQLite brain.</li><li>Repository sync: {sync ? "on" : "off"}. Codex session capture: {continuity ? "on" : "off"}. Capture normalization: {capture ? "on" : "off"}.</li><li>Project AGENTS.md: {writeAgents ? "write enabled" : "unchanged"}. Host configuration: unchanged.</li></ul>
      </div>
      <button className="primarySmall" onClick={setup} disabled={Boolean(busy)}><Rocket size={15} />{busy === "setup" ? "Starting..." : "Set Up & Start"}</button>
    </> : <>
      <section className="pilotSection" aria-label="Project setup result">
        <div className="pilotStatus"><CheckCircle2 size={16} /><strong>{receipt?.ready ? "Local project ready" : "Selected project"}</strong></div>
        <code>{binding.project}</code>
        <button disabled={Boolean(busy)} onClick={() => { resetProof(); setBinding(null); setReceipt(null); }}><RefreshCw size={14} /> Change project</button>
      </section>
      <section className="pilotSection" aria-label="Host connection">
        <h3>Host connection</h3><p>Host activation unverified</p>
        <button disabled={Boolean(busy)} onClick={() => run("mcp", async active => {
          const result = await post("/api/mcp-doctor", { ...identity, timeout: 10 });
          if (active()) setMcp(result);
        })}><Cable size={15} /> Test local MCP server</button>
        {mcp && <div role="status">{mcp.ready ? "Local MCP server reachable" : `Local MCP check incomplete: ${mcp.reason || "unavailable"}`}</div>}
        {mcp?.ready && mcp.config && <details><summary>MCP configuration</summary><pre tabIndex={0} aria-label="MCP configuration JSON">{JSON.stringify(mcp.config, null, 2)}</pre><button disabled={Boolean(busy)} onClick={() => copy(JSON.stringify(mcp.config, null, 2))}><Clipboard size={14} /> Copy MCP configuration</button></details>}
      </section>
      <section className="pilotSection" aria-label="Decision memory">
        <h3>Remember a decision</h3>
        <label><span>Decision to remember</span><textarea maxLength={2000} value={decision} disabled={Boolean(busy)} onChange={event => { setDecision(event.target.value); setSaved(null); setRecovered(null); setPack(""); }} placeholder="Atlas stores all decision timestamps in UTC." /></label>
        <button disabled={Boolean(busy) || !decision.trim() || Boolean(saved)} onClick={save}><Save size={15} /> Save decision</button>
        {saved && <p role="status">Saved as an unverified operator decision</p>}
      </section>
      <section className="pilotSection" aria-label="Memory recovery">
        <h3>Recover context</h3>
        <label><span>Recovery query</span><input value={query} disabled={Boolean(busy)} onChange={event => { setQuery(event.target.value); setRecovered(null); setPack(""); }} /></label>
        <button disabled={Boolean(busy) || !query.trim()} onClick={recover}><Search size={15} /> Recover decision</button>
        {recovered && <div className="pilotRecovery" role="status">
          <strong>{recovered.exact ? "Saved decision recovered" : recovered.memories.length ? "Decision matches found" : "No matching decision recovered"}</strong>
          <span>Read-only recovery</span>
          {recovered.memories.map(memory => <article key={memory.id}><p>{memory.text}</p><small>Memory #{memory.id} · {memory.project} · {memory.provenance?.verification_status || "unverified"}</small></article>)}
        </div>}
        <div className="pilotActions">
          <button disabled={Boolean(busy) || !query.trim()} onClick={() => copy(`In a fresh agent session, use Rta-Smriti brain_search for project ${JSON.stringify(binding.project)} and query ${JSON.stringify(query.trim())}. Return the matching decision with its memory ID and provenance. If the tool or evidence is unavailable, report that; do not infer a successful recovery.`)}><Clipboard size={15} /> Copy fresh-session prompt</button>
          <button disabled={Boolean(busy) || !query.trim()} onClick={() => run("pack", async active => { const result = await post("/api/context-pack", { ...identity, task: query.trim(), max_tokens: 1500 }); if (active()) setPack(result.pack); })}><FileText size={15} /> Build context pack</button>
        </div>
        {pack && <details open><summary>Context pack</summary><pre tabIndex={0} aria-label="Recovered context pack">{pack}</pre><button disabled={Boolean(busy)} onClick={() => copy(pack)}><Clipboard size={14} /> Copy context pack</button></details>}
      </section>
    </>}
    {busy && <p role="status">{busy === "setup" ? "Building local brain..." : "Working..."}</p>}
    {error && <p role="alert" className="pilotError">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {receipt && <details><summary>Setup receipt</summary><pre tabIndex={0} aria-label="Setup receipt details" className="miniOutput">{receipt.ready ? `Brain ready: ${receipt.project}\n` : ""}{(receipt.stages || []).map(stage => `${stage.state}: ${stage.name}: ${stage.detail}`).join("\n")}{error ? `\n${error}` : ""}</pre></details>}
  </div>;
}
