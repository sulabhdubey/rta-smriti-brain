import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ArrowRight,
  BrainCircuit,
  Check,
  ChevronRight,
  CircleDot,
  Clipboard,
  Code2,
  Database,
  ExternalLink,
  FileCode2,
  Github,
  GitBranch,
  LockKeyhole,
  Menu,
  MessageCircle,
  Network,
  Play,
  Search,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  X,
  Zap,
} from "lucide-react";
import "./styles.css";

const repositoryUrl = import.meta.env.VITE_REPOSITORY_URL || "https://github.com/sulabhdubey/rta-smriti-brain";
const releaseUrl = `${repositoryUrl}/releases/tag/v0.9.1-alpha`;
const candidateUrl = `${repositoryUrl}/blob/main/docs/RELEASE_NOTES_v1.0.0-alpha.md`;
const ciRunUrl = `${repositoryUrl}/actions/workflows/ci.yml`;
const nativeRunUrl = `${repositoryUrl}/actions/workflows/binaries.yml`;
const productHuntUrl = "https://www.producthunt.com/products/rta-smriti-brain?launch=rta-smriti-brain&utm_source=website&utm_medium=referral&utm_campaign=v090_release";

const installCommands = {
  windows: [
    "git clone https://github.com/sulabhdubey/rta-smriti-brain.git",
    "cd .\\rta-smriti-brain",
    "python -m venv .venv",
    "& .\\.venv\\Scripts\\python.exe -m pip install .",
    '& .\\.venv\\Scripts\\rta-brain.exe start C:\\path\\to\\project --project my-project --brain-dir "$env:USERPROFILE\\Documents\\Rta-Smriti\\brains" --write-agents',
  ],
  macos: [
    "git clone https://github.com/sulabhdubey/rta-smriti-brain.git",
    "cd rta-smriti-brain",
    "python3 -m venv .venv",
    "./.venv/bin/python -m pip install .",
    './.venv/bin/rta-brain start /path/to/project --project my-project --brain-dir "$HOME/.local/share/rta-smriti/brains" --write-agents',
  ],
  linux: [
    "git clone https://github.com/sulabhdubey/rta-smriti-brain.git",
    "cd rta-smriti-brain",
    "python3 -m venv .venv",
    "./.venv/bin/python -m pip install .",
    './.venv/bin/rta-brain start /path/to/project --project my-project --brain-dir "$HOME/.local/share/rta-smriti/brains" --write-agents',
  ],
};
const agents = ["Codex", "Claude Code", "Cursor", "GitHub Copilot CLI", "Gemini CLI", "Aider", "Cline", "Any MCP agent"];
const pramana = {
  pratyaksha: ["Observed", "Code, tests, files, and tool output", "#5eead4"],
  sabda: ["Trusted", "Human instruction and authoritative documentation", "#38bdf8"],
  anumana: ["Inferred", "Reasoned conclusions with explicit uncertainty", "#fbbf24"],
  smriti: ["Remembered", "Prior project knowledge and session handoffs", "#a78bfa"],
  kalpana: ["Hypothesized", "Ideas and possibilities that still need proof", "#f472b6"],
};

function Brand({ compact = false }) {
  return (
    <a className="brand" href="#top" aria-label="Rta-Smriti Brain home">
      <span className="brandMark"><BrainCircuit size={compact ? 18 : 22} /></span>
      <span><strong>Rta-Smriti</strong>{!compact && <small>Local AI project brain</small>}</span>
    </a>
  );
}

function CopyButton({ value, label = "Copy install command" }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };
  return <button className="iconButton" onClick={copy} aria-label={label} title={label}>{copied ? <Check size={17} /> : <Clipboard size={17} />}</button>;
}

function HeroGraph() {
  const nodes = useMemo(() => [
    [13, 35, "file"], [24, 22, "memory"], [34, 43, "evidence"], [48, 18, "file"],
    [57, 37, "memory"], [69, 25, "evidence"], [81, 46, "file"], [91, 30, "memory"],
  ], []);
  return (
    <svg className="heroGraph" viewBox="0 0 100 60" aria-hidden="true">
      <path d="M13 35L24 22L34 43L48 18L57 37L69 25L81 46L91 30" />
      <path d="M13 35L34 43M24 22L48 18M48 18L69 25M57 37L81 46M69 25L91 30" />
      {nodes.map(([x, y, type], index) => <circle key={index} cx={x} cy={y} r={type === "evidence" ? 1.5 : 1} data-type={type} />)}
    </svg>
  );
}

function Hero() {
  return (
    <section className="hero" id="top">
      <img className="heroImage" src="./assets/project-reality-v1.png" alt="Rta-Smriti v1 Project Reality cockpit showing readiness, decision debt, coverage, and change impact" />
      <div className="heroScrim" />
      <HeroGraph />
      <div className="heroContent shell">
        <div className="eyebrow"><LockKeyhole size={14} /> v1.0.0-alpha candidate · Project Reality · Local-first</div>
        <h1>Rta-Smriti Brain</h1>
        <p className="heroLead">A sovereign project-memory layer that reconciles repository evidence, temporal truth, decisions, work state, and local media into an inspectable reality for the next AI task.</p>
        <p className="buildCredit">Conceived and researched by <a href="https://github.com/sulabhdubey">Sulabh Dubey</a>. Built with <a href="https://openai.com/codex/">OpenAI Codex</a> as the primary AI engineering agent under maintainer review.</p>
        <div className="heroActions">
          <a className="primaryAction" href={candidateUrl}><TerminalSquare size={18} /> Review v1 candidate <ArrowRight size={17} /></a>
          <a className="secondaryAction" href="#demo"><Play size={17} /> Watch the product</a>
        </div>
        <a className="launchConversation" href={productHuntUrl}><MessageCircle size={15} /> Live on Product Hunt <span>Join the conversation</span><ExternalLink size={13} /></a>
        <div className="heroProof" aria-label="Product proof points">
          <span><strong>8</strong> verified v0.9.1 assets</span>
          <span><strong>3 OS</strong> CI and native builds</span>
          <span><strong>0</strong> cloud accounts required</span>
        </div>
      </div>
      <a className="nextCue" href="#why" aria-label="Continue to product story"><span>Why it exists</span><ChevronRight size={15} /></a>
    </section>
  );
}

function Header() {
  const [open, setOpen] = useState(false);
  return (
    <header className="siteHeader">
      <div className="shell headerInner">
        <Brand />
        <nav className={open ? "siteNav open" : "siteNav"} aria-label="Main navigation">
          <a href="#release" onClick={() => setOpen(false)}>v1 candidate</a>
          <a href="#product" onClick={() => setOpen(false)}>Product</a>
          <a href="#architecture" onClick={() => setOpen(false)}>Architecture</a>
          <a href="#difference" onClick={() => setOpen(false)}>Why different</a>
          <a href="#install" onClick={() => setOpen(false)}>Install</a>
          {repositoryUrl && <a className="navGithub" href={repositoryUrl} onClick={() => setOpen(false)}><Github size={16} /> Get source</a>}
        </nav>
        <button className="menuButton" onClick={() => setOpen((value) => !value)} aria-label={open ? "Close menu" : "Open menu"}>{open ? <X /> : <Menu />}</button>
      </div>
    </header>
  );
}

function ProblemBand() {
  return (
    <section className="problemBand" id="why">
      <div className="shell problemGrid">
        <div>
          <span className="sectionIndex">01 / THE PROBLEM</span>
          <h2>Every new AI chat forgets the project.</h2>
        </div>
        <div className="problemCopy">
          <p>Architecture, release rules, prior failures, browser work, and human decisions disappear across sessions. Developers pay the tax in repeated explanations, broad repo scans, and tokens spent rebuilding context.</p>
          <p className="solutionLine"><Sparkles size={19} /> Rta-Smriti moves memory out of the chat and into the project.</p>
        </div>
      </div>
    </section>
  );
}

const featureTabs = [
  ["reality", "Project Reality", BrainCircuit, "Inspect readiness, decision debt, coverage, change impact, conflicts, and governed media evidence.", "./assets/project-reality-v1.png"],
  ["graph", "Graph", Network, "See files, imports, symbols, memories, and evidence as one inspectable project system.", "./assets/dashboard-hero-v0.9.png"],
  ["files", "Files", FileCode2, "Browse the indexed public release tree, preview exact source, and add paths to the next task.", "./assets/file-explorer-v0.9.png"],
  ["truth", "Truth", Database, "Inspect accepted claims, recorded time, valid time, provenance, contradictions, and validator health.", "./assets/truth-timeline-v0.9.png"],
  ["capture", "Capture", Zap, "Review bounded agent events, source authorization, replay order, privacy controls, and capture diagnostics.", "./assets/universal-capture-v0.9.png"],
];

function ProductSection() {
  const [active, setActive] = useState("reality");
  const current = featureTabs.find(([id]) => id === active);
  return (
    <section className="productSection" id="product">
      <div className="shell">
        <div className="sectionHeading">
          <span className="sectionIndex">03 / THE OPERATOR CONSOLE</span>
          <h2>Memory you can inspect, not magic you have to trust.</h2>
        </div>
        <div className="featureTabs" role="tablist" aria-label="Product views">
          {featureTabs.map(([id, label, Icon]) => <button key={id} role="tab" aria-selected={active === id} onClick={() => setActive(id)}><Icon size={16} /> {label}</button>)}
        </div>
        <div className="productFrame">
          <img src={current[4]} alt={`Rta-Smriti ${current[1]} operator view`} />
          <div className="frameCaption"><span>{current[1]}</span><p>{current[3]}</p></div>
        </div>
      </div>
    </section>
  );
}

function Architecture() {
  const stages = [
    ["Inputs", "Repositories, decisions, opt-in agent events", GitBranch],
    ["Private capture", "Bounded spool, redaction, normalization", LockKeyhole],
    ["Truth + context", "Bitemporal evidence, governed packs", Database],
    ["Any agent", "Paste, CLI, skill, or MCP gateway", BrainCircuit],
  ];
  return (
    <section className="architecture" id="architecture">
      <div className="shell">
        <div className="sectionHeading rowHeading">
          <div><span className="sectionIndex">04 / ARCHITECTURE</span><h2>Small enough to understand. Strong enough to reuse.</h2></div>
          <p>Universal Capture feeds an append-only local journal. Bitemporal truth and the context compiler decide what an agent may receive; captured text never promotes itself.</p>
        </div>
        <div className="architectureFlow">
          {stages.map(([title, copy, Icon], index) => (
            <React.Fragment key={title}>
              <article><span><Icon size={23} /></span><strong>{title}</strong><p>{copy}</p></article>
              {index < stages.length - 1 && <ArrowRight className="flowArrow" size={20} />}
            </React.Fragment>
          ))}
        </div>
        <div className="architectureFacts">
          <span><Check size={15} /> Python 3.11+</span><span><Check size={15} /> Private bounded spool</span><span><Check size={15} /> Bitemporal SQLite truth</span><span><Check size={15} /> Governed context compiler</span><span><Check size={15} /> Capability-separated MCP</span><span><Check size={15} /> Ed25519 + encrypted snapshots</span>
        </div>
      </div>
    </section>
  );
}

function PramanaSection() {
  const [active, setActive] = useState("pratyaksha");
  const [label, copy, color] = pramana[active];
  return (
    <section className="pramanaSection">
      <div className="shell pramanaGrid">
        <div>
          <span className="sectionIndex">05 / EVIDENCE-AWARE MEMORY</span>
          <h2>A fact, an instruction, and a hypothesis are not the same thing.</h2>
          <p>Rta-Smriti uses a Vedic-inspired pramana model to preserve how knowledge became known, not just what the text says.</p>
        </div>
        <div className="pramanaControl">
          <div className="pramanaTabs" role="tablist" aria-label="Pramana evidence classes">
            {Object.keys(pramana).map((key) => <button key={key} id={`pramana-tab-${key}`} role="tab" aria-controls="pramana-panel" aria-selected={active === key} onClick={() => setActive(key)}>{key}</button>)}
          </div>
          <div className="pramanaResult" id="pramana-panel" role="tabpanel" aria-labelledby={`pramana-tab-${active}`} style={{ "--pramana-color": color }}>
            <CircleDot size={28} />
            <span><strong>{label}</strong><p>{copy}</p></span>
          </div>
        </div>
      </div>
    </section>
  );
}

function Difference() {
  const rows = [
    ["Plain second brain", "Notes", "Event-backed project truth + evidence"],
    ["Code indexer", "File search", "Durable memory + governed context packs"],
    ["Vector memory", "Similar text", "Trust class + time + freshness + receipts"],
    ["Agent chat memory", "One vendor", "Bounded opt-in capture across agents"],
    ["MCP memory server", "Tools only", "Capability-separated CLI + MCP + console"],
  ];
  return (
    <section className="difference" id="difference">
      <div className="shell">
        <div className="sectionHeading rowHeading">
          <div><span className="sectionIndex">06 / THE DIFFERENCE</span><h2>Not another notes app. Not another black-box memory.</h2></div>
          <p>The product combines repository structure, durable human knowledge, session handoffs, evidence strength, and agent-ready output.</p>
        </div>
        <div className="comparisonTable" role="table" aria-label="Rta-Smriti comparison">
          <div className="comparisonHead" role="row"><span role="columnheader">Category</span><span role="columnheader">Usually stops at</span><span role="columnheader">Rta-Smriti adds</span></div>
          {rows.map((row) => <div className="comparisonRow" role="row" key={row[0]}>{row.map((cell, i) => <span role="cell" key={cell} className={i === 2 ? "highlightCell" : ""}>{i === 2 && <Check size={15} />}{cell}</span>)}</div>)}
        </div>
      </div>
    </section>
  );
}

function AgentRail() {
  return <section className="agentRail"><div className="shell"><span>ONE BRAIN</span><div tabIndex="0" aria-label="Supported coding agents">{agents.map((agent) => <strong key={agent}>{agent}</strong>)}</div><span>ANY AGENT</span></div></section>;
}

function Demo() {
  return (
    <section className="demoSection" id="demo">
      <div className="shell demoGrid">
        <div>
          <span className="sectionIndex">07 / HISTORICAL v0.9 TOUR</span>
          <h2>The v0.9 capture workflow, preserved as a historical product tour.</h2>
          <ol>
            <li><span>1</span>Start one canonical project brain.</li>
            <li><span>2</span>Authorize capture sources explicitly.</li>
            <li><span>3</span>Review truth, provenance, and readiness.</li>
            <li><span>4</span>Compile a bounded pack for any agent.</li>
          </ol>
        </div>
        <div className="demoVisual">
          <video controls preload="metadata" poster="./assets/rta-smriti-v0.9-launch-poster.png" aria-label="60-second Rta-Smriti Brain v0.9 Universal Capture product tour">
            <source src="./assets/rta-smriti-v0.9-launch-demo.mp4" type="video/mp4" />
            Your browser does not support embedded video. <a href="./assets/rta-smriti-v0.9-launch-demo.mp4">Open the v0.9 MP4 demo.</a>
          </video>
        </div>
      </div>
    </section>
  );
}

function Install() {
  const [platform, setPlatform] = useState("windows");
  const labels = { windows: "Windows", macos: "macOS", linux: "Linux" };
  const commands = installCommands[platform];
  return (
    <section className="installSection" id="install">
      <div className="shell installGrid">
        <div><span className="sectionIndex">08 / START LOCAL</span><h2>Install locally. Start a project in one command.</h2><p>The source checkout contains the v1 candidate. Verified downloadable binaries and checksums remain v0.9.1-alpha until the v1 tagged workflows pass.</p><p><a href={candidateUrl}>v1 candidate notes</a> · <a href={releaseUrl}>Current public assets</a> · <a href={ciRunUrl}>CI matrix</a> · <a href={nativeRunUrl}>Native builds</a></p></div>
        <div>
          <div className="platformSwitch" role="tablist" aria-label="Installation platform">
            {Object.entries(labels).map(([id, label]) => <button key={id} role="tab" aria-selected={platform === id} onClick={() => setPlatform(id)}>{label}</button>)}
          </div>
          <div className="terminalBlock">
            <div className="terminalHeader"><span><i /> <i /> <i /></span><strong>{labels[platform]}</strong><CopyButton value={commands.join("\n")} label={`Copy ${labels[platform]} install commands`} /></div>
            {commands.map((command) => <code key={command}><span>$</span> {command}</code>)}
          </div>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer><div className="shell footerGrid"><Brand compact /><p>Conceived by Sulabh Dubey. Built with OpenAI Codex.</p><div><a href="#install">Install</a><a href={`${repositoryUrl}/blob/main/CONTRIBUTORS.md`}>Build provenance</a><a href={`${repositoryUrl}/blob/main/SECURITY.md`}>Security & privacy</a><a href="./LICENSE.txt">MIT License</a><a href={productHuntUrl}>Product Hunt <ExternalLink size={13} /></a>{repositoryUrl && <a href={repositoryUrl}>Get source <ExternalLink size={13} /></a>}</div></div></footer>
  );
}

function ReleaseStory() {
  const releases = [
    ["v0.6", "Hardened runtime", "Cross-platform lifecycle, parsing, hybrid retrieval, signed and encrypted snapshots."],
    ["v0.7", "Temporal truth", "Append-only event sourcing with recorded time, valid time, claims, evidence, and contradictions."],
    ["v0.8", "Context compiler", "Capability-bound, privacy-aware packs with fixed-point scoring, receipts, and abstention."],
    ["v0.9.1", "Operator-ready Universal Capture", "Progressive multi-project loading, race-safe project isolation, bounded capture diagnostics, and verified cross-platform artifacts."],
    ["v1 candidate", "Project Reality", "Deterministic readiness, project twin, decision debt, coverage, change impact, multimodal evidence, and stable local interfaces."],
  ];
  return (
    <section className="releaseStory" id="release">
      <div className="shell">
        <div className="sectionHeading rowHeading">
          <div><span className="sectionIndex">02 / CANDIDATE REALITY</span><h2>v1 turns governed continuity into an inspectable project-reality layer.</h2></div>
          <p>The local candidate reconciles what the project contains, what the team decided, what changed, what remains unsupported, and whether another agent can continue safely. v0.9.1 remains the current public release.</p>
        </div>
        <div className="releaseTrack">
          {releases.map(([version, title, copy], index) => <article className={index === releases.length - 1 ? "current" : ""} key={version}><span>{version}</span><strong>{title}</strong><p>{copy}</p></article>)}
        </div>
        <div className="releaseProof">
          <img src="./assets/project-reality-v1.png" alt="Rta-Smriti v1 Project Reality cockpit with bounded cognition evidence" />
          <div><span className="sectionIndex">PROJECT REALITY</span><h3>Know what is ready, stale, conflicted, or unsupported.</h3><p>Project Cognition projects deterministic readiness, decision debt, knowledge coverage, change impact, project-twin observations, and governed media evidence without granting the agent execution authority.</p><a href={candidateUrl}>Read the v1 candidate evidence <ArrowRight size={15} /></a></div>
        </div>
      </div>
    </section>
  );
}

function LandingPage() {
  useEffect(() => {
    const observer = new IntersectionObserver((entries) => entries.forEach((entry) => entry.target.classList.toggle("revealed", entry.isIntersecting)), { threshold: 0.12 });
    document.querySelectorAll("section:not(.hero)").forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);
  return <><Header /><main><Hero /><ProblemBand /><ReleaseStory /><ProductSection /><Architecture /><PramanaSection /><Difference /><AgentRail /><Demo /><Install /></main><Footer /></>;
}

const assetContent = {
  social: ["Give every project an inspectable reality.", "The v1 candidate combines Project Cognition, bitemporal truth, governed context, and local evidence for any AI coding agent.", "dashboard"],
  "gallery-1": ["Your AI starts from governed project truth.", "Repository evidence, bounded capture, durable decisions, and structured checkpoints — compiled locally for the next task.", "dashboard"],
  "gallery-2": ["One brain. Any agent.", "Codex · Claude Code · Cursor · GitHub Copilot CLI · Gemini CLI · Aider · Cline · MCP", "agents"],
  "gallery-3": ["Evidence, not vibes.", "Observed facts, trusted instructions, inferences, memories, and hypotheses stay meaningfully different.", "pramana"],
  "gallery-4": ["10,000 synthetic files. One focused pack.", "A public, reproducible performance fixture exercises bounded local retrieval without exposing a private repository.", "performance"],
};

function AssetBoard({ name }) {
  if (name === "thumbnail") return <div className="assetCanvas thumbnailAsset"><Brand compact /><BrainCircuit /><strong>Rta-Smriti</strong><span>Local AI project brain</span></div>;
  const content = assetContent[name] || assetContent["gallery-1"];
  const assetClass = name === "social" ? "galleryAsset dashboard socialAsset" : `galleryAsset ${content[2]}`;
  return (
    <div className={`assetCanvas ${assetClass}`}>
      <div className="assetTop"><Brand compact /><span>LOCAL ONLY</span></div>
      <div className="assetCopy"><small>RTA-SMRITI BRAIN · v1 CANDIDATE</small><h1>{content[0]}</h1><p>{content[1]}</p></div>
      {content[2] === "dashboard" && <img src="./assets/project-reality-v1.png" alt="" />}
      {content[2] === "agents" && <div className="assetAgentOrbit"><BrainCircuit />{agents.slice(0, 7).map((agent, i) => <span key={agent} style={{ "--i": i }}>{agent}</span>)}</div>}
      {content[2] === "pramana" && <div className="assetPramana">{Object.entries(pramana).map(([key, value]) => <span key={key} style={{ "--color": value[2] }}><i />{key}<small>{value[0]}</small></span>)}</div>}
      {content[2] === "performance" && <div className="assetMetric"><span><strong>10,000</strong>synthetic files</span><ArrowRight /><span><strong>1</strong>task-specific pack</span></div>}
      <div className="assetFooter"><span>v1 candidate · Project Reality · Bitemporal Truth · Context Compiler</span><strong>rta-smriti</strong></div>
    </div>
  );
}

const asset = new URLSearchParams(window.location.search).get("asset");
createRoot(document.getElementById("root")).render(asset ? <AssetBoard name={asset} /> : <LandingPage />);
