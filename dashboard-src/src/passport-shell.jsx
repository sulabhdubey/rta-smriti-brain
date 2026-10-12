import React, { useEffect, useRef, useState } from "react";
import { ArrowLeft, FolderPlus, RefreshCw } from "lucide-react";
import ProjectPassport from "./project-passport.jsx";
import { chooseProject, defaultProjectIdentity } from "./project-selection.js";

export default function PassportShell({ api }) {
  const [projects, setProjects] = useState([]);
  const [project, setProject] = useState(null);
  const [setup, setSetup] = useState(false);
  const [folder, setFolder] = useState("");
  const [name, setName] = useState("");
  const [sync, setSync] = useState(false);
  const [capture, setCapture] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const dirty = useRef(false);
  const flight = useRef(false);
  const mounted = useRef(false);
  const consoleUrl = new URL(window.location.href);
  consoleUrl.searchParams.delete("view");
  const key = item => item ? JSON.stringify([item.db_path, item.project]) : "";

  async function load(preferred) {
    const result = await api("/api/bootstrap");
    if (!mounted.current) return;
    const available = result.projects || [];
    const choice = chooseProject(available, project, preferred || (project ? null : defaultProjectIdentity(result)));
    setProjects(available); setProject(choice.selected);
    if (choice.reason) throw new Error("The exact project could not be recovered. Choose it explicitly before continuing.");
  }
  async function run(action) {
    if (flight.current) return;
    flight.current = true; setBusy(true); setError("");
    try { await action(); } catch (e) { if (mounted.current) setError(e.code === "authorization_required" ? "Authorization expired. Open the private console URL from the launcher in a new tab. Do not share that URL." : e.message); }
    finally { flight.current = false; if (mounted.current) setBusy(false); }
  }
  function canLeave() { return !dirty.current || window.confirm("Discard unsaved Passport edits and change project?"); }
  useEffect(() => { mounted.current = true; run(() => load()); return () => { mounted.current = false; }; }, []);

  return <div className="passportShell">
    <header className="passportShellHeader">
      <a href={consoleUrl.pathname + consoleUrl.search} onClick={event => { if (!canLeave()) event.preventDefault(); }}><ArrowLeft size={15} /> Operator console</a>
      <span>Project Passport / Local only</span>
    </header>
    <main className="passportShellMain">
      <div className="passportProjectBar">
        <label>Project<select aria-label="Project" value={key(project)} disabled={busy} onChange={event => { if (canLeave()) { dirty.current = false; setProject(projects.find(item => key(item) === event.target.value) || null); } }}>
          <option value="">Choose a project</option>
          {projects.map((item, index) => <option key={key(item)} value={key(item)}>{item.project}{projects.filter(other => other.project === item.project).length > 1 ? ` (brain ${index + 1})` : ""}</option>)}
        </select></label>
        <button title="Refresh project list" aria-label="Refresh project list" disabled={busy} onClick={() => { if (canLeave()) run(() => load()); }}><RefreshCw size={17} /></button>
        <button disabled={busy} onClick={() => setSetup(value => !value)}><FolderPlus size={16} /> {setup ? "Close setup" : "Add project"}</button>
      </div>
      {error && <p className="passportError" role="alert">{error}</p>}
      {busy && <p role="status">Working locally...</p>}
      {setup && <section className="passportSetup" aria-label="Add project">
        <h2>Add a project</h2>
        <form onSubmit={event => { event.preventDefault(); if (!canLeave()) return; run(async () => {
          const result = await api("/api/bootstrap", { method: "POST", body: JSON.stringify({ path: folder.trim(), project: name.trim() || null,
            target_agent: "codex", embedding_provider: "hash", write_agents: false, start_sync: sync,
            start_universal_capture: capture, start_continuity_capture: capture }) });
          if (!mounted.current) return;
          if (!result.ready) throw new Error(result.error?.message || "Setup needs attention. Check the operator console before retrying.");
          await load({ project: result.project, db_path: result.db_path });
          if (mounted.current) { dirty.current = false; setSetup(false); setFolder(""); setName(""); setSync(false); setCapture(false); }
        }); }}><fieldset disabled={busy} className="passportForm">
          <label>Project folder<input aria-label="Project folder" required value={folder} onChange={event => setFolder(event.target.value)} /></label>
          <label>Project name (optional)<input aria-label="Project name (optional)" value={name} onChange={event => setName(event.target.value)} /></label>
          <p>Only this folder is indexed. Standard source exclusions apply, including Git metadata and common secret files. No AGENTS file is written.</p>
          <label className="passportCheck"><input type="checkbox" checked={sync} onChange={event => setSync(event.target.checked)} /><span>Keep this folder indexed automatically</span></label>
          <label className="passportCheck"><input type="checkbox" checked={capture} onChange={event => setCapture(event.target.checked)} /><span>Allow local capture of matching Codex sessions, including their text</span></label>
          <button type="submit"><FolderPlus size={16} /> Create project</button>
        </fieldset></form>
      </section>}
      <div hidden={setup}><ProjectPassport key={key(project)} project={project} api={api} onSetup={() => setSetup(true)} onDirtyChange={value => { dirty.current = value; }} /></div>
    </main>
  </div>;
}
