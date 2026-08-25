import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowLeft,
  BrainCircuit,
  Boxes,
  Cable,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clipboard,
  Code2,
  Command,
  Crosshair,
  Database,
  Download,
  Eye,
  FileCode2,
  FileText,
  Files,
  Folder,
  FolderTree,
  GitBranch,
  GitPullRequest,
  Gauge,
  HardDrive,
  KeyRound,
  Layers3,
  Map as MapIcon,
  Maximize2,
  MemoryStick,
  Network,
  PanelRightOpen,
  Plus,
  RadioTower,
  RefreshCw,
  RotateCcw,
  Route,
  Rocket,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Table2,
  ThumbsDown,
  ThumbsUp,
  Trash2,
  Zap,
} from "lucide-react";
import { chooseProject, defaultProjectIdentity, isExactProjectIdentity } from "./project-selection.js";
import { shellPathArg, shellQuote } from "./shell-command.js";
import CaptureConsole from "./capture-console.jsx";
import CognitionConsole from "./cognition-console.jsx";
import "./styles.css";

const DEFAULT_TASK = "Prepare this project for a focused coding task";
const LEGACY_RECEIPT_STORAGE_KEY = "rta-smriti.context-pack-receipts.v1";
const CANVAS_STORAGE_KEY = "rta-smriti.canvas-layout.v2";
const AGENT_STORAGE_KEY = "rta-smriti.target-agent.v1";
const API_TOKEN_SESSION_KEY = "rta-smriti.api-token.v1";

const targetAgents = [
  { value: "universal", label: "Universal / Any Agent" },
  { value: "codex", label: "OpenAI Codex" },
  { value: "claude-code", label: "Claude Code" },
  { value: "cursor", label: "Cursor" },
  { value: "github-copilot", label: "GitHub Copilot CLI" },
  { value: "gemini-cli", label: "Gemini CLI" },
  { value: "windsurf", label: "Windsurf" },
  { value: "cline", label: "Cline" },
  { value: "aider", label: "Aider" },
  { value: "opencode", label: "OpenCode" },
  { value: "continue", label: "Continue" },
  { value: "custom", label: "Custom Agent" },
];

const graphPalette = {
  file: "#38bdf8",
  memory: "#5eead4",
  docs: "#86efac",
  config: "#fbbf24",
  test: "#a78bfa",
  data: "#94a3b8",
  artifact: "#f472b6",
};

const canvasNodeIcons = {
  file: FileCode2,
  memory: MemoryStick,
  docs: FileText,
  config: SlidersHorizontal,
  test: ShieldCheck,
  data: Database,
  artifact: Sparkles,
};

const canvasDefaultSlots = [
  { x: 4, y: 9 }, { x: 23, y: 6 }, { x: 42, y: 10 }, { x: 61, y: 6 }, { x: 80, y: 10 },
  { x: 9, y: 35 }, { x: 28, y: 31 }, { x: 47, y: 36 }, { x: 66, y: 31 }, { x: 84, y: 35 },
  { x: 4, y: 63 }, { x: 20, y: 68 }, { x: 36, y: 62 }, { x: 52, y: 68 }, { x: 68, y: 62 }, { x: 84, y: 68 },
];

function canvasCurvePath(source, target) {
  const start = { x: source.x + 6.5, y: source.y + 4.5 };
  const end = { x: target.x + 6.5, y: target.y + 4.5 };
  const dx = end.x - start.x;
  const dy = end.y - start.y;
  if (Math.abs(dx) >= Math.abs(dy)) {
    const control = Math.max(5, Math.abs(dx) * 0.46) * Math.sign(dx || 1);
    return `M ${start.x.toFixed(2)} ${start.y.toFixed(2)} C ${(start.x + control).toFixed(2)} ${start.y.toFixed(2)}, ${(end.x - control).toFixed(2)} ${end.y.toFixed(2)}, ${end.x.toFixed(2)} ${end.y.toFixed(2)}`;
  }
  const control = Math.max(5, Math.abs(dy) * 0.46) * Math.sign(dy || 1);
  return `M ${start.x.toFixed(2)} ${start.y.toFixed(2)} C ${start.x.toFixed(2)} ${(start.y + control).toFixed(2)}, ${end.x.toFixed(2)} ${(end.y - control).toFixed(2)}, ${end.x.toFixed(2)} ${end.y.toFixed(2)}`;
}

const allGraphTypes = Object.keys(graphPalette);
const graphModes = ["global", "local", "task"];
const graphHubs = [
  { id: "hub-files", key: "files", label: "Files", x: 50, y: 18, angle: -Math.PI / 2, color: "#38bdf8", icon: FileCode2 },
  { id: "hub-imports", key: "imports", label: "Imports", x: 69, y: 42, angle: -0.1, color: "#fbbf24", icon: GitBranch },
  { id: "hub-evidence", key: "evidence", label: "Evidence", x: 64, y: 73, angle: 0.9, color: "#60a5fa", icon: ShieldCheck },
  { id: "hub-memories", key: "memories", label: "Memories", x: 36, y: 73, angle: 2.25, color: "#a78bfa", icon: MemoryStick },
  { id: "hub-symbols", key: "symbols", label: "Symbols", x: 31, y: 42, angle: Math.PI + 0.1, color: "#86efac", icon: Code2 },
];

function safeNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function displayPath(value) {
  return String(value || "...")
    .replace(/^[A-Za-z]:[\\/]Users[\\/][^\\/]+/i, "%USERPROFILE%")
    .replace(/^\/(?:Users|home)\/[^/]+/i, "$HOME")
    .replace(/^[/\\]{2}[^/\\]+[/\\][^/\\]+/, "<network-share>");
}

function readApiToken() {
  try {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const supplied = fragment.get("token");
    if (supplied) {
      sessionStorage.setItem(API_TOKEN_SESSION_KEY, supplied);
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      return supplied;
    }
    return sessionStorage.getItem(API_TOKEN_SESSION_KEY) || "";
  } catch {
    return "";
  }
}

const API_TOKEN = readApiToken();

async function api(path, options = {}) {
  const timeoutMs = Number(options.timeoutMs || (String(options.method || "GET").toUpperCase() === "GET" ? 60_000 : 300_000));
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  const { timeoutMs: _ignoredTimeout, ...fetchOptions } = options;
  try {
    const response = await fetch(path, {
      ...fetchOptions,
      signal: fetchOptions.signal || controller.signal,
      headers: { "Content-Type": "application/json", "X-Rta-Smriti-Token": API_TOKEN, ...(fetchOptions.headers || {}) },
    });
    const payload = await response.json();
    if (!response.ok || payload.status === "error") {
      throw new Error(displayPath(payload.error?.message || `Request failed: ${path}`));
    }
    return payload;
  } catch (error) {
    if (error?.name === "AbortError") throw new Error(`Request timed out after ${Math.round(timeoutMs / 1000)} seconds: ${path.split("?")[0]}`);
    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}

function qs(params) {
  return new URLSearchParams(params).toString();
}

function readLocalJson(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key)) || fallback;
  } catch {
    return fallback;
  }
}

function writeLocalJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // The console remains fully usable when browser storage is unavailable.
  }
}

function readLocalString(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
}

function writeLocalString(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // The selected handoff target remains available for the current session.
  }
}

function sourceType(node) {
  if (node.type === "memory") return "memory";
  if (node.type === "file") {
    const name = String(node.name || "").toLowerCase();
    if (/test|spec/.test(name)) return "test";
    if (/readme|\.md$|docs?[\\/]/.test(name)) return "docs";
    if (/json|ya?ml|toml|ini|config|env/.test(name)) return "config";
    return "file";
  }
  if (node.type === "symbol") return "docs";
  if (node.type === "import") return "config";
  return "data";
}

function taskWords(task) {
  return new Set(String(task || "").toLowerCase().match(/[a-z0-9_-]{3,}/g) || []);
}

function semanticHubKey(node) {
  if (node.type === "memory") return "memories";
  if (node.type === "symbol") return "symbols";
  if (node.type === "import") return "imports";
  return sourceType(node) === "file" ? "files" : "evidence";
}

function selectBalancedNodes(candidates, limit) {
  const caps = { files: 8, symbols: 8, imports: 8, memories: 6, evidence: 6 };
  const grouped = Object.fromEntries(graphHubs.map((hub) => [hub.key, []]));
  candidates.forEach((node) => grouped[semanticHubKey(node)]?.push(node));
  return graphHubs.flatMap((hub) => grouped[hub.key].slice(0, caps[hub.key])).slice(0, limit);
}

function buildGraph(project, graphData, memories, packText, options = {}) {
  const mode = options.mode || "global";
  const depth = Math.max(1, Math.min(4, Number(options.depth) || 2));
  const available = graphData?.nodes || [];
  const rawEdges = graphData?.edges || [];
  const byId = new Map(available.map((node) => [Number(node.id), node]));
  const adjacency = new Map(available.map((node) => [Number(node.id), new Set()]));
  rawEdges.forEach((edge) => {
    adjacency.get(Number(edge.from_id))?.add(Number(edge.to_id));
    adjacency.get(Number(edge.to_id))?.add(Number(edge.from_id));
  });
  const words = taskWords(options.task);
  const pack = String(packText || "").toLowerCase();
  const taskMatches = available.filter((node) => {
    const haystack = `${node.name || ""} ${node.type || ""}`.toLowerCase();
    return [...words].some((word) => haystack.includes(word)) || (node.name && pack.includes(String(node.name).toLowerCase()));
  });
  let candidates = available;
  if (mode === "task" && taskMatches.length) candidates = taskMatches;
  if (mode === "local" && available.length) {
    const start = Number(options.focalSourceId) || Number(rawEdges[0]?.from_id) || Number(available[0].id);
    const visited = new Set([start]);
    let frontier = [start];
    for (let level = 0; level < depth; level += 1) {
      const next = frontier.flatMap((id) => [...(adjacency.get(id) || [])]).filter((id) => !visited.has(id));
      next.forEach((id) => visited.add(id));
      frontier = next;
    }
    candidates = [...visited].map((id) => byId.get(id)).filter(Boolean);
  }
  const limit = mode === "global" ? 40 : mode === "task" ? 12 + depth * 4 : 10 + depth * 6;
  let orderedCandidates = candidates;
  if (mode === "global" && rawEdges.length) {
    const candidateIds = new Set(candidates.map((node) => Number(node.id)));
    const connectedIds = [];
    const seen = new Set();
    rawEdges.forEach((edge) => {
      [Number(edge.from_id), Number(edge.to_id)].forEach((id) => {
        if (candidateIds.has(id) && !seen.has(id)) {
          seen.add(id);
          connectedIds.push(id);
        }
      });
    });
    orderedCandidates = [
      ...connectedIds.map((id) => byId.get(id)).filter(Boolean),
      ...candidates.filter((node) => !seen.has(Number(node.id))),
    ];
  }
  const selected = selectBalancedNodes(orderedCandidates, limit);
  const selectedIds = new Set(selected.map((node) => Number(node.id)));
  const grouped = Object.fromEntries(graphHubs.map((hub) => [hub.key, []]));
  selected.forEach((node) => grouped[semanticHubKey(node)]?.push(node));
  const hubs = graphHubs
    .filter((hub) => grouped[hub.key].length)
    .map((hub) => ({ ...hub, count: grouped[hub.key].length }));
  const nodes = hubs.flatMap((hub) => grouped[hub.key].map((node, index, group) => {
    const slots = group.length;
    const angle = hub.angle + (index / Math.max(1, slots)) * Math.PI * 2;
    const radiusX = slots === 1 ? 6.2 : 6.7;
    const radiusY = slots === 1 ? 10 : 10.8;
    return {
      id: `g-${node.id}`,
      sourceId: Number(node.id),
      label: node.name.split(/[\\/]/).pop() || node.name,
      type: sourceType(node),
      meta: node.type,
      hubId: hub.id,
      color: hub.color,
      x: Math.max(2.2, Math.min(97.8, hub.x + Math.cos(angle) * radiusX)),
      y: Math.max(3.5, Math.min(96, hub.y + Math.sin(angle) * radiusY)),
      size: node.type === "file" ? 13 : 11,
    };
  }));
  const edges = rawEdges
    .filter((edge) => selectedIds.has(Number(edge.from_id)) && selectedIds.has(Number(edge.to_id)))
    .map((edge) => ({ id: `edge-${edge.id}`, source: `g-${edge.from_id}`, target: `g-${edge.to_id}`, label: edge.relation }));
  return {
    nodes,
    edges,
    hubs,
    core: {
      id: `project-${project?.project || "brain"}`,
      label: project?.project || "Project Brain",
      meta: `${selected.length} visible nodes`,
      x: 50,
      y: 49,
    },
  };
}

function deriveReferences(graph, node, memories) {
  if (!node) return [];
  const connected = graph.edges
    .filter((edge) => edge.source === node.id || edge.target === node.id)
    .map((edge) => {
      const otherId = edge.source === node.id ? edge.target : edge.source;
      const other = graph.nodes.find((candidate) => candidate.id === otherId);
      return other ? { id: edge.id, label: other.label, relation: edge.label, type: other.type, node: other } : null;
    })
    .filter(Boolean);
  const mentions = memories
    .filter((memory) => String(memory.text || "").toLowerCase().includes(String(node.label || "").toLowerCase()))
    .slice(0, 5)
    .map((memory) => ({ id: `memory-${memory.id}`, label: memory.type, relation: "mentions", type: "memory" }));
  return [...connected, ...mentions];
}

function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  window.setTimeout(() => {
    anchor.remove();
    URL.revokeObjectURL(url);
  }, 250);
}

function filterGraph(graph, query, types, semanticFocus = null) {
  const normalizedQuery = query.trim().toLowerCase();
  const activeTypes = new Set(types);
  const nodes = graph.nodes.filter((node) => {
    const matchesType = activeTypes.has(node.type);
    const matchesFocus = !semanticFocus || node.hubId === `hub-${semanticFocus}`;
    const haystack = `${node.label} ${node.meta} ${node.text || ""}`.toLowerCase();
    const matchesQuery = !normalizedQuery || haystack.includes(normalizedQuery);
    return matchesType && matchesFocus && matchesQuery;
  });
  const ids = new Set(nodes.map((node) => node.id));
  return {
    nodes,
    edges: graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)),
    hubs: (graph.hubs || []).map((hub) => ({
      ...hub,
      count: nodes.filter((node) => node.hubId === hub.id).length,
    })).filter((hub) => hub.count),
    core: graph.core,
  };
}

function App() {
  const presentationMode = new URLSearchParams(window.location.search).get("presentation") === "1";
  const [health, setHealth] = useState(null);
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const selectedProjectRef = useRef(null);
  const registryRequestRef = useRef(0);
  const [task, setTask] = useState(DEFAULT_TASK);
  const [contextBudget, setContextBudget] = useState(4000);
  const [contextStudioMode, setContextStudioMode] = useState("quick");
  const [compilerMode, setCompilerMode] = useState("balanced");
  const [comparisonMode, setComparisonMode] = useState("minimal");
  const [governedCompilation, setGovernedCompilation] = useState(null);
  const [compilerInspection, setCompilerInspection] = useState(null);
  const contextSessionRef = useRef(
    `dashboard-${globalThis.crypto?.randomUUID?.() || Date.now().toString(36)}`,
  );
  const [packText, setPackText] = useState("");
  const [memories, setMemories] = useState([]);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [freshness, setFreshness] = useState(null);
  const projectRequestRef = useRef(0);
  const fileRequestRef = useRef(0);
  const filePreviewRequestRef = useRef(0);
  const governanceRequestRef = useRef(0);
  const intelligenceRequestRef = useRef(0);
  const truthRequestRef = useRef(0);
  const inspectorRef = useRef(null);
  const [publish, setPublish] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [message, setMessageState] = useState("");
  const messageRevisionRef = useRef(0);
  const setMessage = (nextMessage) => {
    messageRevisionRef.current += 1;
    setMessageState(nextMessage);
  };
  const setBackgroundMessage = (nextMessage, expectedRevision) => {
    if (messageRevisionRef.current !== expectedRevision) return;
    setMessageState(nextMessage);
  };
  const [loadError, setLoadError] = useState("");
  const [activeDrawer, setActiveDrawer] = useState("evidence");
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isProjectRegistryLoading, setIsProjectRegistryLoading] = useState(true);
  const [searchOpen, setSearchOpen] = useState(false);
  const [projectsOpen, setProjectsOpen] = useState(false);
  const [nodeQuery, setNodeQuery] = useState("");
  const [typesOpen, setTypesOpen] = useState(false);
  const [activeTypes, setActiveTypes] = useState(allGraphTypes);
  const [commandOpen, setCommandOpen] = useState(false);
  const [stageExpanded, setStageExpanded] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRefreshingIndex, setIsRefreshingIndex] = useState(false);
  const [viewMode, setViewMode] = useState("graph");
  const [semanticFocus, setSemanticFocus] = useState(null);
  const [navContext, setNavContext] = useState("graph");
  const [baseScope, setBaseScope] = useState({ table: "memory", kind: "" });
  const [fileTree, setFileTree] = useState({ entries: [], prefix: "", query: "", total_files: 0 });
  const [filePreview, setFilePreview] = useState(null);
  const [filesLoading, setFilesLoading] = useState(false);
  const [targetAgent, setTargetAgent] = useState(() => readLocalString(AGENT_STORAGE_KEY, "universal"));
  const [customAgent, setCustomAgent] = useState("");
  const [graphMode, setGraphMode] = useState("global");
  const [graphDepth, setGraphDepth] = useState(2);
  const [showLabels, setShowLabels] = useState(false);
  const [showEdges, setShowEdges] = useState(true);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [projectSettings, setProjectSettings] = useState(null);
  const [parserCapabilities, setParserCapabilities] = useState({});
  const [watcher, setWatcher] = useState({ state: "stopped", backend: null });
  const [isChangingWatcher, setIsChangingWatcher] = useState(false);
  const [continuity, setContinuity] = useState({ state: "stopped", backend: null });
  const [isChangingContinuity, setIsChangingContinuity] = useState(false);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [receipts, setReceipts] = useState([]);
  const [checkpoint, setCheckpoint] = useState(null);
  const [continuationReadiness, setContinuationReadiness] = useState(null);
  const [isSavingCheckpoint, setIsSavingCheckpoint] = useState(false);
  const [isRefreshingPublish, setIsRefreshingPublish] = useState(false);
  const [referenceHistory, setReferenceHistory] = useState([]);
  const [governance, setGovernance] = useState({ policies: [], receipts: [] });
  const [preflightDecision, setPreflightDecision] = useState(null);
  const [isGovernanceBusy, setIsGovernanceBusy] = useState(false);
  const [intelligence, setIntelligence] = useState({ diagnostics: null, graph: null, workspaces: [] });
  const [isIntelligenceBusy, setIsIntelligenceBusy] = useState(false);
  const [truthData, setTruthData] = useState({ claims: [], events: [], contradictions: [], validators: [], abstentions: [], counts: {} });
  const [truthDetail, setTruthDetail] = useState(null);
  const [truthDiff, setTruthDiff] = useState(null);
  const [isTruthBusy, setIsTruthBusy] = useState(false);
  const captureRequestRef = useRef(0);
  const captureActionRequestRef = useRef(0);
  const [captureData, setCaptureData] = useState({ overview: null, replay: null, diagnostics: null });
  const [captureBusy, setCaptureBusy] = useState(false);
  const [captureError, setCaptureError] = useState("");
  const [captureReplayMode, setCaptureReplayMode] = useState("chronological");
  const [capturePrivacyCeiling, setCapturePrivacyCeiling] = useState("internal");
  const cognitionRequestRef = useRef(0);
  const [cognitionData, setCognitionData] = useState(null);
  const [cognitionBusy, setCognitionBusy] = useState(false);
  const [cognitionError, setCognitionError] = useState("");
  const [mediaVerification, setMediaVerification] = useState({});

  const selectedParams = useMemo(() => {
    if (!selectedProject) return null;
    return { db_path: selectedProject.db_path, project: selectedProject.project };
  }, [selectedProject]);

  selectedProjectRef.current = selectedProject;
  const isCurrentProject = (project) => Boolean(
    project
    && selectedProjectRef.current?.db_path === project.db_path
    && selectedProjectRef.current?.project === project.project
  );

  const graphOptions = useMemo(() => ({ mode: graphMode, depth: graphDepth, task, focalSourceId: selectedNode?.sourceId }), [graphMode, graphDepth, task, selectedNode?.sourceId]);
  const computedGraph = useMemo(
    () => buildGraph(selectedProject, graphData, memories, packText, graphOptions),
    [selectedProject, graphData, memories, packText, graphOptions],
  );
  const visibleGraph = useMemo(
    () => filterGraph(computedGraph, nodeQuery, activeTypes, semanticFocus),
    [computedGraph, nodeQuery, activeTypes, semanticFocus],
  );
  const activeNode = computedGraph.nodes.find((node) => node.id === selectedNode?.id) || computedGraph.nodes[0];
  const references = useMemo(() => deriveReferences(computedGraph, activeNode, memories), [computedGraph, activeNode, memories]);
  const readyProjects = projects.filter((project) => project.ready).length;
  const publishReady = publish?.checks?.filter((check) => check.ok).length || 0;
  const publishTotal = publish?.checks?.length || 0;
  const targetAgentLabel = targetAgent === "custom"
    ? customAgent.trim() || "Custom Agent"
    : targetAgents.find((agent) => agent.value === targetAgent)?.label || "Universal / Any Agent";
  const contextBinding = useMemo(() => JSON.stringify({
    dbPath: selectedProject?.db_path || null,
    project: selectedProject?.project || null,
    task: task.trim(),
    contextBudget,
    contextStudioMode,
    compilerMode,
    comparisonMode,
    targetAgent,
    customAgent: customAgent.trim(),
  }), [
    selectedProject?.db_path, selectedProject?.project, task, contextBudget,
    contextStudioMode, compilerMode, comparisonMode, targetAgent, customAgent,
  ]);
  const contextBindingRef = useRef(contextBinding);
  contextBindingRef.current = contextBinding;

  async function refreshProjectRegistry(preferredProject = null) {
    const requestId = registryRequestRef.current + 1;
    registryRequestRef.current = requestId;
    setIsProjectRegistryLoading(true);
    try {
      const payload = await api("/api/projects");
      if (requestId !== registryRequestRef.current) return null;
      const available = payload.projects || [];
      setProjects(available);
      setHealth((current) => ({ ...(current || {}), project_scan_state: "ready" }));
      setSelectedProject((current) => chooseProject(available, current, current || preferredProject).selected);
      setLoadError("");
      return payload;
    } catch (error) {
      if (requestId === registryRequestRef.current) {
        setLoadError(error.message);
        setMessage(`Project health scan failed: ${error.message}`);
      }
      return null;
    } finally {
      if (requestId === registryRequestRef.current) setIsProjectRegistryLoading(false);
    }
  }

  async function loadHealth(preferredProject = null) {
    setIsLoading(true);
    try {
      const payload = await api("/api/bootstrap");
      setLoadError("");
      setHealth(payload);
      setProjects(payload.projects || []);
      setPublish(payload.publish);
      const available = payload.projects || [];
      const preferredIdentity = preferredProject || defaultProjectIdentity(payload);
      const preferredDecision = chooseProject(available, null, preferredIdentity);
      setSelectedProject((current) => chooseProject(available, current, preferredIdentity).selected);
      if (preferredDecision.reason === "preferred_identity_missing") {
        setMessage(`The new brain could not be matched to its exact database identity. Selection was cleared to protect the canonical root.`);
      } else if (preferredDecision.reason === "preferred_name_ambiguous") {
        setMessage(`More than one brain has that name. Select the exact database before continuing.`);
      } else if (available.length) {
        setMessage(`${available.length} project brains found. Verifying repository health in the background...`);
      }
      void refreshProjectRegistry(preferredIdentity);
      void refreshPublishReadiness({ silent: true });
      return payload;
    } catch (error) {
      if (isExactProjectIdentity(preferredProject)) {
        projectRequestRef.current += 1;
        registryRequestRef.current += 1;
        setIsProjectRegistryLoading(false);
        setSelectedProject(null);
      }
      setLoadError(error.message);
      setMessage(`Dashboard refresh failed: ${error.message}`);
      return null;
    } finally {
      setIsLoading(false);
    }
  }

  async function refreshPublishReadiness({ silent = false } = {}) {
    if (isRefreshingPublish) return;
    setIsRefreshingPublish(true);
    try {
      const payload = await api("/api/publish-readiness");
      setPublish(payload);
      const ready = payload.checks?.filter((check) => check.ok).length || 0;
      if (!silent) setMessage(`Rta-Smriti release checks refreshed: ${ready}/${payload.checks?.length || 0} ready.`);
    } catch (error) {
      if (!silent) setMessage(`Rta-Smriti release checks failed: ${error.message}`);
    } finally {
      setIsRefreshingPublish(false);
    }
  }

  async function loadGovernance(project = selectedProject, { silent = false } = {}) {
    if (!project) return null;
    const requestId = governanceRequestRef.current + 1;
    governanceRequestRef.current = requestId;
    if (!silent) setIsGovernanceBusy(true);
    try {
      const payload = await api(`/api/governance?${qs({
        db_path: project.db_path,
        project: project.project,
        limit: 50,
      })}`);
      if (requestId !== governanceRequestRef.current) return null;
      setGovernance({ policies: payload.policies || [], receipts: payload.receipts || [] });
      return payload;
    } catch (error) {
      if (requestId === governanceRequestRef.current) setMessage(`Action Gate could not load: ${error.message}`);
      return null;
    } finally {
      if (!silent && requestId === governanceRequestRef.current) setIsGovernanceBusy(false);
    }
  }

  async function loadProjectDetails(project = selectedProject) {
    if (!project) return;
    const requestId = projectRequestRef.current + 1;
    projectRequestRef.current = requestId;
    const messageRevision = messageRevisionRef.current;
    const governanceRequestId = governanceRequestRef.current + 1;
    governanceRequestRef.current = governanceRequestId;
    const params = { db_path: project.db_path, project: project.project };
    setFreshness({ state: "checking", fresh: 0, changed: 0, missing: 0, added: 0, uninspectable: 0 });
    setWatcher({ state: "loading", backend: null });
    setContinuity({ state: "loading", backend: null });
    setTruthDetail(null);
    setTruthDiff(null);
    setSelectedNode(null);
    setReferenceHistory([]);

    const requests = [
      ["memories", api(`/api/memories?${qs({ ...params, limit: 40 })}`), (payload) => setMemories(payload.memories || [])],
      ["graph", api(`/api/graph?${qs({ ...params, limit: 120 })}`), (payload) => setGraphData(payload || { nodes: [], edges: [] })],
      ["freshness", api(`/api/stale-check?${qs(params)}`), setFreshness],
      ["settings", api(`/api/settings?${qs(params)}`), (payload) => {
        setProjectSettings(payload.settings);
        setParserCapabilities(payload.parser_capabilities || {});
      }],
      ["checkpoint", api(`/api/checkpoint?${qs({ ...params, mode: "summary" })}`), (payload) => {
        setCheckpoint(payload.checkpoint || null);
        setContinuationReadiness(payload.readiness || null);
      }],
      ["sync", api(`/api/watcher?${qs(params)}`), setWatcher],
      ["governance", api(`/api/governance?${qs({ ...params, limit: 50 })}`), (payload) => {
        if (governanceRequestId === governanceRequestRef.current) {
          setGovernance({ policies: payload.policies || [], receipts: payload.receipts || [] });
        }
      }],
      ["continuity", api(`/api/continuity?${qs(params)}`), setContinuity],
      ["truth", api(`/api/truth?${qs({ ...params, mode: "overview", limit: 120 })}`), setTruthData],
      ["cognition", api(`/api/cognition?${qs(params)}`), setCognitionData],
    ];
    const pending = new Set(requests.map(([label]) => label));
    const results = await Promise.all(requests.map(async ([label, request, apply]) => {
      try {
        const payload = await request;
        if (requestId === projectRequestRef.current) apply(payload);
        return { label, ok: true };
      } catch (error) {
        return { label, ok: false, error: error.message };
      } finally {
        pending.delete(label);
        if (requestId === projectRequestRef.current && pending.size) {
          setBackgroundMessage(`${project.project}: core data available; checking ${[...pending].join(", ")}...`, messageRevision);
        }
      }
    }));
    if (requestId !== projectRequestRef.current) return;
    const failures = results.filter((result) => !result.ok);
    if (failures.length) {
      setBackgroundMessage(`${project.project} loaded with ${failures.length} unavailable section${failures.length === 1 ? "" : "s"}: ${failures.map((result) => result.label).join(", ")}.`, messageRevision);
    } else {
      setBackgroundMessage(`${project.project} index loaded.`, messageRevision);
    }
  }
  async function loadCapture(
    project = selectedProject,
    replayMode = captureReplayMode,
    privacyCeiling = capturePrivacyCeiling,
  ) {
    if (!project) return null;
    const requestId = captureRequestRef.current + 1;
    captureRequestRef.current = requestId;
    setCaptureBusy(true);
    try {
      const params = { db_path: project.db_path, project: project.project };
      const [overview, replay, diagnostics] = await Promise.all([
        api(`/api/capture?${qs({ ...params, mode: "overview" })}`),
        api(`/api/capture?${qs({ ...params, mode: "replay", replay_mode: replayMode, privacy_ceiling: privacyCeiling, limit: 100 })}`),
        api(`/api/capture?${qs({ ...params, mode: "diagnostics" })}`),
      ]);
      if (requestId !== captureRequestRef.current || !isCurrentProject(project)) return null;
      const next = { overview, replay, diagnostics };
      setCaptureData(next);
      setCaptureError("");
      return next;
    } catch (error) {
      if (requestId === captureRequestRef.current && isCurrentProject(project)) {
        setCaptureError(error.message);
        setMessage(`Capture console could not load: ${error.message}`);
      }
      return null;
    } finally {
      if (requestId === captureRequestRef.current && isCurrentProject(project)) setCaptureBusy(false);
    }
  }

  async function runCaptureAction(action, values = {}, success = "Capture state updated.") {
    const project = selectedProject;
    if (!project || captureBusy) return null;
    const requestId = captureActionRequestRef.current + 1;
    captureActionRequestRef.current = requestId;
    const params = { db_path: project.db_path, project: project.project };
    setCaptureBusy(true);
    setCaptureError("");
    try {
      const result = await api("/api/capture", {
        method: "POST",
        body: JSON.stringify({ ...params, action, ...values }),
      });
      if (requestId !== captureActionRequestRef.current || !isCurrentProject(project)) return null;
      if (action === "daemon-start" || action === "daemon-stop") {
        setCaptureData((current) => ({
          ...current,
          overview: {
            ...(current.overview || {}),
            daemon: result,
          },
        }));
      }
      setMessage(success);
      await loadCapture(project);
      return isCurrentProject(project) ? result : null;
    } catch (error) {
      if (requestId === captureActionRequestRef.current && isCurrentProject(project)) {
        setCaptureError(error.message);
        setMessage(`Capture operation failed: ${error.message}`);
      }
      return null;
    } finally {
      if (requestId === captureActionRequestRef.current && isCurrentProject(project)) setCaptureBusy(false);
    }
  }

  async function exportCapture(privacyCeiling) {
    const project = selectedProject;
    const payload = await runCaptureAction(
      "export",
      { privacy_ceiling: privacyCeiling, limit: 500, max_bytes: 16_000_000 },
      "Privacy-verified capture export prepared.",
    );
    if (!payload || !isCurrentProject(project)) return;
    downloadJson(`${project.project}-capture.json`, payload);
    setMessage("Privacy-verified capture export downloaded.");
  }

  async function loadCognition(project = selectedProject, { silent = false } = {}) {
    if (!project) return null;
    const requestId = cognitionRequestRef.current + 1;
    cognitionRequestRef.current = requestId;
    if (!silent) setCognitionBusy(true);
    try {
      const payload = await api(`/api/cognition?${qs({ db_path: project.db_path, project: project.project })}`);
      if (requestId !== cognitionRequestRef.current || !isCurrentProject(project)) return null;
      setCognitionData(payload);
      setCognitionError("");
      return payload;
    } catch (error) {
      if (requestId === cognitionRequestRef.current && isCurrentProject(project)) {
        setCognitionError(error.message);
        setMessage(`Project cognition could not load: ${error.message}`);
      }
      return null;
    } finally {
      if (!silent && requestId === cognitionRequestRef.current && isCurrentProject(project)) setCognitionBusy(false);
    }
  }

  async function reconcileCognition(observationId, status, reason) {
    const project = selectedProject;
    if (!project || cognitionBusy) return;
    setCognitionBusy(true);
    try {
      await api("/api/cognition", {
        method: "POST",
        body: JSON.stringify({
          db_path: project.db_path,
          project: project.project,
          action: "reconcile",
          observation_id: observationId,
          receipt_id: `dashboard-${observationId}-${globalThis.crypto?.randomUUID?.() || Date.now().toString(36)}`,
          status,
          reason,
          evidence: { source: "operator-console" },
        }),
      });
      setMessage(`${observationId} reconciled as ${status}.`);
      await loadCognition(project, { silent: true });
    } catch (error) {
      setCognitionError(error.message);
      setMessage(`Reconciliation failed: ${error.message}`);
    } finally {
      if (isCurrentProject(project)) setCognitionBusy(false);
    }
  }

  async function addMediaSource(path, privacyClass) {
    const project = selectedProject;
    if (!project || cognitionBusy) return;
    setCognitionBusy(true);
    try {
      await api("/api/multimodal", {
        method: "POST",
        body: JSON.stringify({
          db_path: project.db_path,
          project: project.project,
          action: "add",
          path,
          privacy_class: privacyClass,
          sharing_policy: privacyClass === "public" ? "exportable" : "local-only",
        }),
      });
      setMessage(`${path} added as ${privacyClass} media evidence.`);
      await loadCognition(project, { silent: true });
    } catch (error) {
      setCognitionError(error.message);
      setMessage(`Media source could not be added: ${error.message}`);
    } finally {
      if (isCurrentProject(project)) setCognitionBusy(false);
    }
  }

  async function verifyMediaSource(sourceId) {
    if (!selectedParams) return;
    try {
      const payload = await api(`/api/multimodal?${qs({ ...selectedParams, mode: "verify", source_id: sourceId })}`);
      setMediaVerification((current) => ({ ...current, [sourceId]: payload.state }));
      setMessage(`Media source ${sourceId.slice(0, 8)} is ${payload.state}.`);
    } catch (error) {
      setMessage(`Media verification failed: ${error.message}`);
    }
  }

  async function exportMediaManifest(audience = "local") {
    if (!selectedParams || !selectedProject) return;
    const payload = await api(`/api/multimodal?${qs({ ...selectedParams, mode: "export", audience })}`);
    downloadJson(`${selectedProject.project}-multimodal-${audience}.json`, payload);
    setMessage(`${audience} multimodal manifest exported.`);
  }

  async function loadFiles(prefix = "", query = "", project = selectedProject) {
    if (!project) return;
    const requestId = fileRequestRef.current + 1;
    fileRequestRef.current = requestId;
    setFilesLoading(true);
    try {
      const payload = await api(`/api/files?${qs({ db_path: project.db_path, project: project.project, prefix, query, limit: 500 })}`);
      if (requestId !== fileRequestRef.current) return;
      setFileTree(payload);
      setFilePreview(null);
    } catch (error) {
      if (requestId === fileRequestRef.current) setMessage(`File explorer failed: ${error.message}`);
    } finally {
      if (requestId === fileRequestRef.current) setFilesLoading(false);
    }
  }

  async function loadFilePreview(entry) {
    const project = selectedProject;
    if (!project || entry.kind !== "file") return;
    const requestId = filePreviewRequestRef.current + 1;
    filePreviewRequestRef.current = requestId;
    setFilePreview({ loading: true, relative_path: entry.relative_path, name: entry.name });
    try {
      const payload = await api(`/api/file-preview?${qs({ db_path: project.db_path, project: project.project, path: entry.relative_path })}`);
      if (requestId === filePreviewRequestRef.current && isCurrentProject(project)) {
        setFilePreview(payload.file || { ...entry, missing: true });
      }
    } catch (error) {
      if (requestId === filePreviewRequestRef.current && isCurrentProject(project)) {
        setFilePreview({ ...entry, error: error.message });
      }
    }
  }

  useEffect(() => {
    loadHealth();
  }, []);

  useEffect(() => {
    try {
      localStorage.removeItem(LEGACY_RECEIPT_STORAGE_KEY);
    } catch {
      // Old receipt metadata is best-effort cleanup only.
    }
  }, []);

  useEffect(() => {
    writeLocalString(AGENT_STORAGE_KEY, targetAgent);
  }, [targetAgent]);

  useEffect(() => {
    setPackText("");
    setGovernedCompilation(null);
    setCompilerInspection(null);
  }, [contextBinding]);

  useEffect(() => {
    if (selectedProject) {
      projectRequestRef.current += 1;
      fileRequestRef.current += 1;
      filePreviewRequestRef.current += 1;
      governanceRequestRef.current += 1;
      intelligenceRequestRef.current += 1;
      truthRequestRef.current += 1;
      captureRequestRef.current += 1;
      captureActionRequestRef.current += 1;
      setMemories([]);
      setGraphData({ nodes: [], edges: [] });
      setFreshness({ state: "checking", fresh: 0, changed: 0, missing: 0, added: 0, uninspectable: 0 });
      setProjectSettings(null);
      setParserCapabilities({});
      setWatcher({ state: "loading", backend: null });
      setContinuity({ state: "loading", backend: null });
      setReceipts([]);
      setCheckpoint(null);
      setContinuationReadiness(null);
      setFileTree({ entries: [], prefix: "", query: "", total_files: 0 });
      setFilePreview(null);
      setFilesLoading(false);
      setGovernance({ policies: [], receipts: [] });
      setPreflightDecision(null);
      setIntelligence({ diagnostics: null, graph: null, workspaces: [] });
      setTruthData({ claims: [], events: [], contradictions: [], validators: [], abstentions: [], counts: {} });
      setTruthDetail(null);
      setTruthDiff(null);
      setCaptureData({ overview: null, replay: null, diagnostics: null });
      setCaptureBusy(false);
      setCaptureError("");
      setCognitionData(null);
      setCognitionBusy(false);
      setCognitionError("");
      setMediaVerification({});
      setSelectedNode(null);
      setReferenceHistory([]);
      setMessage(`Loading ${selectedProject.project}...`);
      loadProjectDetails(selectedProject)
        .then(async () => {
          if (viewMode === "files") await loadFiles("", "", selectedProject);
        })
        .catch((error) => setMessage(`Could not load ${selectedProject.project}: ${error.message}`));
    }
  }, [selectedProject?.db_path, selectedProject?.project]);

  useEffect(() => {
    if (viewMode === "capture" && selectedProject) loadCapture(selectedProject);
    if (viewMode === "cognition" && selectedProject) loadCognition(selectedProject);
  }, [viewMode, selectedProject?.db_path, selectedProject?.project]);

  useEffect(() => {
    if (!selectedProject) return undefined;
    let cancelled = false;
    const params = { db_path: selectedProject.db_path, project: selectedProject.project };
    const refreshContinuity = async () => {
      try {
        const [continuityPayload, checkpointPayload] = await Promise.all([
          api(`/api/continuity?${qs(params)}`),
          api(`/api/checkpoint?${qs({ ...params, mode: "summary" })}`),
        ]);
        if (!cancelled) {
          setContinuity(continuityPayload);
          setCheckpoint(checkpointPayload.checkpoint || null);
          setContinuationReadiness(checkpointPayload.readiness || null);
        }
      } catch {
        // The full project refresh surfaces persistent backend errors to the operator.
      }
    };
    const timer = window.setInterval(refreshContinuity, 5_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selectedProject?.db_path, selectedProject?.project]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen(true);
      }
      if (event.key === "Escape") {
        setCommandOpen(false);
        setStageExpanded(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  async function generatePack() {
    if (!selectedParams) return setMessage("Select a project first.");
    if (!task.trim()) return setMessage("Enter a task first.");
    const requestBinding = contextBinding;
    setIsGenerating(true);
    setPackText("");
    setGovernedCompilation(null);
    setCompilerInspection(null);
    try {
      setMessage(contextStudioMode === "governed" ? "Authorizing and compiling context..." : "Generating context pack...");
      const payload = contextStudioMode === "governed"
        ? await api("/api/context-compiler", {
          method: "POST",
          body: JSON.stringify({
            ...selectedParams,
            action: "authorize-and-compile",
            profile_id: targetAgent === "custom" ? "custom" : targetAgent,
            max_input_tokens: contextBudget,
            objective: task.trim(),
            compiler_mode: compilerMode,
            comparison_modes: comparisonMode && comparisonMode !== compilerMode ? [comparisonMode] : [],
            privacy_ceiling: "internal",
            principal_id: targetAgent === "custom" ? customAgent.trim() || "custom-agent" : targetAgent,
            session_id: contextSessionRef.current,
            variant: "primary",
          }),
        })
        : await api("/api/context-pack", {
          method: "POST",
          body: JSON.stringify({ ...selectedParams, task: task.trim(), limit: 8, max_tokens: contextBudget }),
        });
      if (contextBindingRef.current !== requestBinding) {
        setMessage("Context inputs changed while compilation was running. The stale result was discarded.");
        return;
      }
      const rawPack = contextStudioMode === "governed" ? payload.context_pack?.context_text : payload.pack;
      const rawText = typeof rawPack === "string" ? rawPack : JSON.stringify(rawPack, null, 2);
      const text = targetAgent === "universal" ? rawText : `Target agent: ${targetAgentLabel}\n\n${rawText}`;
      setPackText(text);
      setGovernedCompilation(contextStudioMode === "governed" ? payload : null);
      setCompilerInspection(null);
      const receipt = {
        id: payload.compilation_receipt?.compilation_id || `pack-${Date.now()}`,
        createdAt: new Date().toISOString(),
        project: selectedProject.project,
        task: task.trim(),
        agent: targetAgentLabel,
        tokenBudget: contextBudget,
        nodes: buildGraph(selectedProject, graphData, memories, text, graphOptions).nodes.length,
        bytes: new Blob([text]).size,
        pack: text,
        governed: contextStudioMode === "governed",
        mode: payload.context_pack?.compiler_mode,
        receiptDigest: payload.compilation_receipt?.receipt_digest,
        variants: payload.available_variants || [],
      };
      const nextReceipts = [receipt, ...receipts].slice(0, 30);
      setReceipts(nextReceipts);
      setMessage(contextStudioMode === "governed" ? "Governed context compiled and receipted." : "Context pack generated.");
      showDrawer("receipts");
      setViewMode("graph");
      setGraphMode("task");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setIsGenerating(false);
    }
  }

  async function copyText(text, success = "Copied.") {
    const value = String(text || "");
    if (!value.trim()) {
      setMessage("Nothing is available to copy yet.");
      return false;
    }
    try {
      let copied = false;
      if (navigator.clipboard?.writeText && window.isSecureContext) {
        try {
          await navigator.clipboard.writeText(value);
          copied = true;
        } catch {
          copied = false;
        }
      }
      const element = document.createElement("textarea");
      element.value = value;
      element.setAttribute("readonly", "");
      element.style.position = "fixed";
      element.style.inset = "0 auto auto -9999px";
      element.style.opacity = "0";
      document.body.appendChild(element);
      element.focus();
      element.select();
      element.setSelectionRange(0, element.value.length);
      try {
        copied = document.execCommand("copy") || copied;
      } finally {
        document.body.removeChild(element);
      }
      if (!copied) {
        throw new Error("clipboard permission was denied");
      }
      setMessage(success);
      return true;
    } catch (error) {
      setMessage(`Copy failed: ${error.message}`);
      return false;
    }
  }

  async function reflect() {
    if (!selectedParams) return;
    try {
      const payload = await api("/api/reflect", { method: "POST", body: JSON.stringify(selectedParams) });
      setMessage(`Reflection complete: ${payload.duplicates_superseded} duplicates, ${payload.contradictions_flagged} contradictions.`);
      await loadProjectDetails();
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function refreshIndex() {
    if (!selectedParams || isRefreshingIndex) return;
    setIsRefreshingIndex(true);
    setMessage(`Refreshing ${selectedProject.project} index...`);
    try {
      const payload = await api("/api/ingest-repo", { method: "POST", body: JSON.stringify(selectedParams) });
      await Promise.all([loadProjectDetails(selectedProject), loadHealth()]);
      const warnings = [
        payload.blocked_files ? `${payload.blocked_files} blocked` : "",
        payload.parser_warnings?.length ? `${payload.parser_warnings.length} parser fallback warnings` : "",
      ].filter(Boolean).join(", ");
      setMessage(`${selectedProject.project}: ${payload.updated_files} updated, ${payload.removed_files} removed, ${payload.unchanged_files} unchanged${warnings ? `, ${warnings}` : ""}.`);
    } catch (error) {
      setMessage(`Index refresh failed: ${error.message}`);
    } finally {
      setIsRefreshingIndex(false);
    }
  }

  async function saveProjectSettings() {
    if (!selectedParams || !projectSettings || isSavingSettings) return;
    setIsSavingSettings(true);
    setMessage(`Saving ${selectedProject.project} indexing policy...`);
    try {
      const payload = await api("/api/settings", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, settings: projectSettings }),
      });
      setProjectSettings(payload.settings);
      setParserCapabilities(payload.parser_capabilities || {});
      setMessage("Indexing policy saved. Refresh the index to apply it to existing files.");
    } catch (error) {
      setMessage(`Settings could not be saved: ${error.message}`);
    } finally {
      setIsSavingSettings(false);
    }
  }

  async function startWatcher() {
    if (!selectedParams || isChangingWatcher) return;
    setIsChangingWatcher(true);
    setMessage(`Starting background sync for ${selectedProject.project}...`);
    try {
      const payload = await api("/api/watcher", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "start", interval: 2 }),
      });
      setWatcher(payload);
      setMessage(`${selectedProject.project} background sync is running with ${payload.backend}.`);
    } catch (error) {
      setMessage(`Background sync could not start: ${error.message}`);
    } finally {
      setIsChangingWatcher(false);
    }
  }

  async function stopWatcher() {
    if (!selectedParams || isChangingWatcher) return;
    setIsChangingWatcher(true);
    setMessage(`Stopping background sync for ${selectedProject.project}...`);
    try {
      const payload = await api("/api/watcher", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "stop" }),
      });
      setWatcher(payload);
      setMessage(`${selectedProject.project} background sync stopped.`);
    } catch (error) {
      setMessage(`Background sync could not stop: ${error.message}`);
    } finally {
      setIsChangingWatcher(false);
    }
  }

  async function toggleContinuity() {
    if (!selectedParams || isChangingContinuity) return;
    const running = continuity?.state === "running";
    setIsChangingContinuity(true);
    setMessage(`${running ? "Stopping" : "Starting"} continuity capture for ${selectedProject.project}...`);
    try {
      const payload = await api("/api/continuity", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: running ? "stop" : "start", interval: 2, inactivity: 900 }),
      });
      setContinuity(payload);
      setMessage(running ? "Continuity capture stopped." : "Continuity capture is monitoring Codex sessions.");
    } catch (error) {
      setMessage(`Continuity capture could not ${running ? "stop" : "start"}: ${error.message}`);
    } finally {
      setIsChangingContinuity(false);
    }
  }

  async function saveCheckpoint(values) {
    if (!selectedParams || isSavingCheckpoint) return;
    setIsSavingCheckpoint(true);
    try {
      const payload = await api("/api/checkpoint", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, ...values, expected_version: checkpoint?.version ?? 0 }),
      });
      setCheckpoint(payload.checkpoint);
      setMessage("Structured checkpoint saved for the next task.");
    } catch (error) {
      if (error.message.includes("checkpoint version conflict")) {
        await loadProjectDetails(selectedProject);
        setMessage("A newer checkpoint was saved by another agent. The latest version has been loaded; review and save again.");
        return;
      }
      setMessage(`Checkpoint could not be saved: ${error.message}`);
    } finally {
      setIsSavingCheckpoint(false);
    }
  }

  async function copyContinuationPrompt() {
    if (!selectedParams) {
      setMessage("Select a project first.");
      return false;
    }
    try {
      const payload = await api(`/api/continuation-prompt?${qs(selectedParams)}`);
      return await copyText(payload.prompt, "New task prompt copied.");
    } catch (error) {
      setMessage(`Continuation prompt failed: ${error.message}`);
      return false;
    }
  }

  async function evaluatePreflight(values) {
    if (!selectedParams || isGovernanceBusy) return null;
    setIsGovernanceBusy(true);
    try {
      const payload = await api("/api/preflight", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, ...values, actor: "dashboard-operator", include_operational_context: true }),
      });
      setPreflightDecision(payload);
      await loadGovernance(selectedProject, { silent: true });
      const matched = payload.matches?.length || 0;
      setMessage(`Action Gate: ${payload.decision.replaceAll("_", " ")} (${matched} matching ${matched === 1 ? "check" : "checks"}).`);
      return payload;
    } catch (error) {
      setMessage(`Action Gate failed: ${error.message}`);
      return null;
    } finally {
      setIsGovernanceBusy(false);
    }
  }

  async function createGovernancePolicy(values) {
    if (!selectedParams || isGovernanceBusy) return null;
    setIsGovernanceBusy(true);
    try {
      const payload = await api("/api/governance-policy", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "create", ...values }),
      });
      await loadGovernance(selectedProject, { silent: true });
      setPreflightDecision(null);
      setMessage(`Governance policy ${payload.policy.id} added.`);
      return payload;
    } catch (error) {
      setMessage(`Policy could not be added: ${error.message}`);
      return null;
    } finally {
      setIsGovernanceBusy(false);
    }
  }

  async function retireGovernancePolicy(policyId, reason) {
    if (!selectedParams || isGovernanceBusy) return null;
    setIsGovernanceBusy(true);
    try {
      const payload = await api("/api/governance-policy", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "retire", policy_id: policyId, reason }),
      });
      await loadGovernance(selectedProject, { silent: true });
      setPreflightDecision(null);
      setMessage(`Governance policy ${policyId} retired.`);
      return payload;
    } catch (error) {
      setMessage(`Policy could not be retired: ${error.message}`);
      return null;
    } finally {
      setIsGovernanceBusy(false);
    }
  }

  async function loadWorkspaces(project = selectedProject) {
    if (!project) return [];
    const requestId = intelligenceRequestRef.current + 1;
    intelligenceRequestRef.current = requestId;
    const params = { db_path: project.db_path, project: project.project };
    const payload = await api(`/api/workspaces?${qs(params)}`);
    if (requestId !== intelligenceRequestRef.current || !isCurrentProject(project)) return [];
    setIntelligence((current) => ({ ...current, workspaces: payload.workspaces || [] }));
    return payload.workspaces || [];
  }

  async function runRetrievalDiagnostics(query) {
    const project = selectedProject;
    if (!project || !query.trim()) return null;
    const requestId = intelligenceRequestRef.current + 1;
    intelligenceRequestRef.current = requestId;
    const params = { db_path: project.db_path, project: project.project };
    setIsIntelligenceBusy(true);
    try {
      const payload = await api(`/api/retrieval-diagnostics?${qs({ ...params, query: query.trim(), limit: 8 })}`);
      if (requestId !== intelligenceRequestRef.current || !isCurrentProject(project)) return null;
      setIntelligence((current) => ({ ...current, diagnostics: payload }));
      setMessage(`Retrieval explained in ${payload.latency_ms} ms.`);
      return payload;
    } catch (error) {
      if (requestId === intelligenceRequestRef.current && isCurrentProject(project)) {
        setMessage(`Retrieval diagnostics failed: ${error.message}`);
      }
      return null;
    } finally {
      if (requestId === intelligenceRequestRef.current && isCurrentProject(project)) setIsIntelligenceBusy(false);
    }
  }

  async function runImpactQuery(target, queryType = "impact") {
    const project = selectedProject;
    if (!project || !target.trim()) return null;
    const requestId = intelligenceRequestRef.current + 1;
    intelligenceRequestRef.current = requestId;
    const params = { db_path: project.db_path, project: project.project };
    setIsIntelligenceBusy(true);
    try {
      const payload = await api(`/api/graph-query?${qs({ ...params, target: target.trim(), type: queryType, depth: 3, limit: 100 })}`);
      if (requestId !== intelligenceRequestRef.current || !isCurrentProject(project)) return null;
      setIntelligence((current) => ({ ...current, graph: payload }));
      setMessage(`${queryType} query found ${payload.nodes.length} nodes and ${payload.edges.length} relationships.`);
      return payload;
    } catch (error) {
      if (requestId === intelligenceRequestRef.current && isCurrentProject(project)) {
        setMessage(`Graph query failed: ${error.message}`);
      }
      return null;
    } finally {
      if (requestId === intelligenceRequestRef.current && isCurrentProject(project)) setIsIntelligenceBusy(false);
    }
  }

  async function createProjectWorkspace(values) {
    if (!selectedParams) return null;
    setIsIntelligenceBusy(true);
    try {
      const payload = await api("/api/workspace", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "create", ...values }),
      });
      await loadWorkspaces();
      setMessage(`Workspace ${payload.workspace.name} created.`);
      return payload;
    } catch (error) {
      setMessage(`Workspace could not be created: ${error.message}`);
      return null;
    } finally {
      setIsIntelligenceBusy(false);
    }
  }

  async function addWorkspaceMember(values) {
    if (!selectedParams) return null;
    setIsIntelligenceBusy(true);
    try {
      const payload = await api("/api/workspace", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "add", ...values }),
      });
      await loadWorkspaces();
      setMessage(`${values.project} added to ${values.name}.`);
      return payload;
    } catch (error) {
      setMessage(`Workspace member could not be added: ${error.message}`);
      return null;
    } finally {
      setIsIntelligenceBusy(false);
    }
  }

  async function loadTruth(project = selectedProject, { silent = false } = {}) {
    if (!project) return null;
    const requestId = truthRequestRef.current + 1;
    truthRequestRef.current = requestId;
    if (!silent) setIsTruthBusy(true);
    try {
      const payload = await api(`/api/truth?${qs({
        db_path: project.db_path, project: project.project, mode: "overview", limit: 120,
      })}`);
      if (requestId !== truthRequestRef.current || !isCurrentProject(project)) return null;
      setTruthData(payload);
      return payload;
    } catch (error) {
      if (requestId === truthRequestRef.current && isCurrentProject(project)) {
        setMessage(`Temporal truth could not load: ${error.message}`);
      }
      return null;
    } finally {
      if (!silent && requestId === truthRequestRef.current && isCurrentProject(project)) setIsTruthBusy(false);
    }
  }

  async function inspectGovernedCompilation(action) {
    const compilationId = governedCompilation?.compilation_receipt?.compilation_id;
    if (!selectedParams || !compilationId) return setMessage("Compile a governed context pack first.");
    try {
      setMessage(`${action === "audit" ? "Auditing" : "Explaining"} compilation receipt...`);
      const payload = await api("/api/context-compiler", {
        method: "POST",
        body: JSON.stringify({
          ...selectedParams,
          action,
          compilation_id: compilationId,
          principal_id: targetAgent === "custom" ? customAgent.trim() || "custom-agent" : targetAgent,
          session_id: action === "audit" ? `${contextSessionRef.current}-operator` : contextSessionRef.current,
        }),
      });
      setCompilerInspection({ action, payload });
      setMessage(`${action === "audit" ? "Receipt audit" : "Context explanation"} verified.`);
    } catch (error) {
      setMessage(error.message);
    }
  }

  async function inspectTruthClaim(claimId) {
    const project = selectedProject;
    if (!project || !claimId) return;
    const requestId = truthRequestRef.current + 1;
    truthRequestRef.current = requestId;
    const params = { db_path: project.db_path, project: project.project };
    setIsTruthBusy(true);
    try {
      const payload = await api(`/api/truth?${qs({
        ...params, mode: "explain", claim_id: claimId,
      })}`);
      if (requestId === truthRequestRef.current && isCurrentProject(project)) setTruthDetail(payload);
    } catch (error) {
      if (requestId === truthRequestRef.current && isCurrentProject(project)) {
        setMessage(`Claim evidence could not load: ${error.message}`);
      }
    } finally {
      if (requestId === truthRequestRef.current && isCurrentProject(project)) setIsTruthBusy(false);
    }
  }

  async function compareTruth(fromSequence, toSequence, validAt) {
    const project = selectedProject;
    if (!project) return;
    const requestId = truthRequestRef.current + 1;
    truthRequestRef.current = requestId;
    const params = { db_path: project.db_path, project: project.project };
    setIsTruthBusy(true);
    try {
      const payload = await api(`/api/truth?${qs({
        ...params, mode: "diff", from_sequence: fromSequence,
        to_sequence: toSequence, valid_at: validAt, limit: 200,
      })}`);
      if (requestId !== truthRequestRef.current || !isCurrentProject(project)) return;
      setTruthDiff(payload);
      setMessage(`${payload.changes?.length || 0} truth changes found between sequences ${fromSequence} and ${toSequence}.`);
    } catch (error) {
      if (requestId === truthRequestRef.current && isCurrentProject(project)) {
        setMessage(`Truth diff failed: ${error.message}`);
      }
    } finally {
      if (requestId === truthRequestRef.current && isCurrentProject(project)) setIsTruthBusy(false);
    }
  }

  async function rebuildTruth() {
    if (!selectedProject || isTruthBusy) return;
    setIsTruthBusy(true);
    try {
      const payload = await api("/api/truth", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "rebuild" }),
      });
      await loadTruth(selectedProject, { silent: true });
      setMessage(`Temporal projections rebuilt from ${payload.events_replayed} verified events.`);
    } catch (error) {
      setMessage(`Projection rebuild failed: ${error.message}`);
    } finally {
      setIsTruthBusy(false);
    }
  }

  async function removeWorkspaceMember(values) {
    if (!selectedParams) return null;
    setIsIntelligenceBusy(true);
    try {
      const payload = await api("/api/workspace", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "remove", ...values }),
      });
      await loadWorkspaces();
      setMessage(`${values.project} removed from ${values.name}.`);
      return payload;
    } catch (error) {
      setMessage(`Workspace member could not be removed: ${error.message}`);
      return null;
    } finally {
      setIsIntelligenceBusy(false);
    }
  }

  async function deleteProjectWorkspace(name) {
    if (!selectedParams) return null;
    setIsIntelligenceBusy(true);
    try {
      const payload = await api("/api/workspace", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, action: "delete", name }),
      });
      await loadWorkspaces();
      setMessage(`Workspace ${name} deleted.`);
      return payload;
    } catch (error) {
      setMessage(`Workspace could not be deleted: ${error.message}`);
      return null;
    } finally {
      setIsIntelligenceBusy(false);
    }
  }

  async function recordMemoryFeedback(memoryId, outcome) {
    if (!selectedParams) return;
    try {
      await api("/api/memory-feedback", {
        method: "POST",
        body: JSON.stringify({ ...selectedParams, memory_id: memoryId, outcome, evidence: "operator-dashboard" }),
      });
      await loadProjectDetails(selectedProject);
      setMessage(`Memory ${memoryId} marked ${outcome}.`);
    } catch (error) {
      setMessage(`Memory feedback failed: ${error.message}`);
    }
  }

  function addFileToTask(path) {
    if (task.includes(path)) {
      setMessage(`${path} is already in the task objective.`);
      return "existing";
    }
    setTask(`${task.trim()}\nRelevant file: ${path}`.trim());
    setMessage(`${path} added to the task objective.`);
    return "added";
  }

  function toggleType(type) {
    setActiveTypes((current) => {
      if (current.includes(type) && current.length === 1) return allGraphTypes;
      if (current.includes(type)) return current.filter((item) => item !== type);
      return [...current, type];
    });
  }

  function exportView(filename, payload) {
    downloadJson(filename, payload);
    setMessage(`${filename} export started.`);
  }

  function showDrawer(name) {
    setActiveDrawer(name);
    setInspectorOpen(true);
    setNavContext(name);
    setSettingsOpen(false);
  }

  function showPublishReadiness() {
    showDrawer("publish");
    refreshPublishReadiness();
  }

  function showGovernance() {
    showDrawer("governance");
    loadGovernance();
  }

  function showIntelligence() {
    showDrawer("intelligence");
    loadWorkspaces().catch((error) => setMessage(`Workspaces could not load: ${error.message}`));
  }

  function selectPrimaryNode(node, drawer = null) {
    setReferenceHistory([]);
    setSelectedNode(node);
    if (drawer) showDrawer(drawer);
  }

  function inspectCanvasNodeFromKeyboard(node) {
    selectPrimaryNode(node, "evidence");
    window.requestAnimationFrame(() => {
      const inspector = inspectorRef.current;
      if (!inspector) return;
      inspector.focus({ preventScroll: true });
      if (window.matchMedia("(max-width: 1180px)").matches) {
        inspector.scrollIntoView({ block: "start" });
      }
    });
  }

  function openReference(reference) {
    if (!reference.node) {
      setMessage(`${reference.label} is a memory backlink and has no graph node to open.`);
      return;
    }
    setReferenceHistory((current) => activeNode ? [...current, activeNode].slice(-24) : current);
    setSelectedNode(reference.node);
    setMessage(`Opened ${reference.label} from References.`);
  }

  function goBackReference() {
    const previous = referenceHistory.at(-1);
    if (!previous) return;
    setReferenceHistory((current) => current.slice(0, -1));
    setSelectedNode(previous);
    setMessage(`Returned to ${previous.label}.`);
  }

  function goToReferenceStart() {
    const first = referenceHistory[0];
    if (!first) return;
    setReferenceHistory([]);
    setSelectedNode(first);
    setMessage(`Returned to reference start: ${first.label}.`);
  }

  function showWorkspace(view) {
    setViewMode(view);
    setSemanticFocus(null);
    setNavContext(view);
    setSettingsOpen(false);
  }

  function focusSemanticHub(hub) {
    setViewMode("graph");
    setSemanticFocus((current) => (current === hub ? null : hub));
    setNavContext(hub);
  }

  function showFiles() {
    setViewMode("files");
    setSemanticFocus(null);
    setNavContext("files");
    setSettingsOpen(false);
    loadFiles(fileTree.prefix || "", fileTree.query || "");
  }

  function showTruth() {
    setViewMode("truth");
    setSemanticFocus(null);
    setNavContext("truth");
    setSettingsOpen(false);
    loadTruth();
  }

  function showCapture() {
    setViewMode("capture");
    setSemanticFocus(null);
    setNavContext("capture");
    setSettingsOpen(false);
    setInspectorOpen(false);
  }

  function showCognition() {
    setViewMode("cognition");
    setSemanticFocus(null);
    setNavContext("cognition");
    setSettingsOpen(false);
    setInspectorOpen(false);
    loadCognition();
  }

  function showBase(table, kind = "", context = "bases") {
    setViewMode("bases");
    setSemanticFocus(null);
    setBaseScope({ table, kind });
    setNavContext(context);
    setSettingsOpen(false);
  }

  const shellKind = health?.shell || "powershell";
  const commandDbPath = presentationMode
    ? `${selectedProject?.project || "project"}.sqlite`
    : selectedProject?.db_path;
  const cliCommand = presentationMode ? "rta-brain" : health?.cli_command || "rta-brain";
  const command = selectedProject
    ? `${cliCommand} --db ${shellPathArg(commandDbPath, shellKind)} context-pack ${shellQuote(task || "<task>", shellKind)} --project ${shellQuote(selectedProject.project, shellKind)} --max-tokens ${contextBudget}`
    : "Select a project";

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <div className="brandMark">
            <BrainCircuit size={25} />
          </div>
          <div>
            <h1>Rta-Smriti Brain</h1>
            <span>v1.0.1 Alpha Operator Console</span>
          </div>
        </div>
        <div className="topStatus">
          <span className="localBadge">
            <ShieldCheck size={15} /> Local Only
          </span>
          <span className="pathText">Brain Path {presentationMode ? "Local demo brain" : displayPath(health?.brain_dir)}</span>
        </div>
        <div className="topActions">
          <button className="ghostButton" onClick={() => showDrawer("bootstrap")}>
            <Plus size={16} /> New Brain
          </button>
          <button className="ghostButton" onClick={showPublishReadiness}>
            <GitPullRequest size={16} /> Publish
          </button>
          <button className="ghostButton commandButton" onClick={() => setCommandOpen(true)}>
            <Command size={16} /> Cmd Palette
          </button>
          <span className="healthDot" />
        </div>
      </div>

      <div className={inspectorOpen ? "layout" : "layout inspectorClosed"}>
        <aside className="projectRail">
          <div className="projectSwitcher">
            <div className="railHeader">
              <span>Workspace</span>
              <button onClick={loadHealth} aria-label="Refresh projects" title="Refresh projects">
                <RefreshCw size={15} />
              </button>
            </div>
            <button
              className={projectsOpen ? "activeProjectButton open" : "activeProjectButton"}
              onClick={() => setProjectsOpen((value) => !value)}
              aria-expanded={projectsOpen}
              aria-controls="project-switcher-list"
            >
              <span className="activeProjectIcon"><Network size={18} /></span>
              <span className="activeProjectCopy">
                <small>Projects</small>
                <strong>{selectedProject?.project || "Choose a brain"}</strong>
              </span>
              <span className={`projectStateDot ${selectedProject?.scan_state === "checking" ? "checking" : selectedProject?.ready ? "ok" : "warn"}`} />
              <ChevronRight className="projectChevron" size={16} />
            </button>
            {projectsOpen && (
              <div className="compactProjectList" id="project-switcher-list">
                {projects.map((project) => (
                  <button
                    key={`${project.db_path}:${project.project}`}
                    className={selectedProject?.db_path === project.db_path && selectedProject?.project === project.project ? "compactProject active" : "compactProject"}
                    onClick={() => {
                      setSelectedProject(project);
                      setProjectsOpen(false);
                    }}
                    aria-label={`${project.project}, ${safeNumber(project.sources)} files, ${project.scan_state === "checking" ? "health checking" : project.root_conflict || project.root_duplicate ? "root conflict" : project.ready ? "indexed" : "needs attention"}`}
                  >
                    <Network size={15} />
                    <span>
                      <strong>{project.project}</strong>
                      <small>{safeNumber(project.sources)} files / {safeNumber(project.memories)} memories{project.git?.branch ? ` / ${project.git.branch}@${project.git.head || "unborn"}` : ""}</small>
                    </span>
                    <i className={project.scan_state === "checking" ? "checking" : project.ready && !project.root_conflict && !project.root_duplicate ? "ok" : "warn"} title={project.scan_state === "checking" ? "Repository health is still being verified" : project.root_conflict || project.root_duplicate ? "Canonical checkout ownership needs review" : ""} />
                  </button>
                ))}
                {isLoading && !projects.length && <div className="railEmpty">Scanning local brains...</div>}
                {!isLoading && !projects.length && <button className="railEmpty actionable" onClick={() => showDrawer("bootstrap")}>Bootstrap the first project</button>}
                <button className="addProjectButton" onClick={() => showDrawer("bootstrap")}><Plus size={14} /> Add project brain</button>
              </div>
            )}
          </div>

          <nav className="sideNavigation" aria-label="Operator console navigation">
            <div className="navGroup">
              <span className="navGroupLabel">Overview</span>
              <button title="Explore project relationships" aria-current={navContext === "graph" ? "page" : undefined} className={navContext === "graph" ? "active" : ""} onClick={() => showWorkspace("graph")}><GitBranch size={17} /><span>Graph</span></button>
              <button title="Arrange a temporary working set" aria-current={navContext === "canvas" ? "page" : undefined} className={navContext === "canvas" ? "active" : ""} onClick={() => showWorkspace("canvas")}><MapIcon size={17} /><span>Canvas</span></button>
              <button title="Scan structured project records" aria-current={navContext === "bases" ? "page" : undefined} className={navContext === "bases" ? "active" : ""} onClick={() => showBase("memory", "", "bases")}><Table2 size={17} /><span>Bases</span></button>
            </div>
            <div className="navGroup">
              <span className="navGroupLabel">Project</span>
              <button title="Browse and preview indexed source" aria-current={navContext === "files" ? "page" : undefined} className={navContext === "files" ? "active" : ""} onClick={showFiles}><Files size={17} /><span>Files</span></button>
              <button title="Scan indexed code symbols" aria-current={navContext === "symbols" ? "page" : undefined} className={navContext === "symbols" ? "active" : ""} onClick={() => showBase("files", "symbol", "symbols")}><Code2 size={17} /><span>Symbols</span></button>
              <button title="Scan indexed dependencies" aria-current={navContext === "imports" ? "page" : undefined} className={navContext === "imports" ? "active" : ""} onClick={() => showBase("files", "import", "imports")}><GitBranch size={17} /><span>Imports</span></button>
              <button title="Review durable project knowledge" aria-current={navContext === "memories" ? "page" : undefined} className={navContext === "memories" ? "active" : ""} onClick={() => showBase("memory", "", "memories")}><MemoryStick size={17} /><span>Memories</span></button>
              <button title="Inspect evidence and freshness" aria-current={navContext === "evidence" ? "page" : undefined} className={navContext === "evidence" ? "active" : ""} onClick={() => { focusSemanticHub("evidence"); showDrawer("evidence"); }}><ShieldCheck size={17} /><span>Evidence</span></button>
              <button title="Inspect event-sourced project truth" aria-current={navContext === "truth" ? "page" : undefined} className={navContext === "truth" ? "active" : ""} onClick={showTruth}><Activity size={17} /><span>Truth Timeline</span><em>{truthData.counts?.events || 0}</em></button>
              <button title="Review authorized agent continuity events" aria-current={navContext === "capture" ? "page" : undefined} className={navContext === "capture" ? "active" : ""} onClick={showCapture}><RadioTower size={17} /><span>Capture</span><em>{captureData.overview?.sources?.length || 0}</em></button>
              <button title="Review decision debt and project reality" aria-current={navContext === "cognition" ? "page" : undefined} className={navContext === "cognition" ? "active" : ""} onClick={showCognition}><BrainCircuit size={17} /><span>Project Reality</span><em>{cognitionData?.decision_debt?.count || 0}</em></button>
            </div>
            <div className="navGroup">
              <span className="navGroupLabel">Tools</span>
              <button aria-current={searchOpen && navContext === "search" ? "page" : undefined} className={searchOpen && navContext === "search" ? "active" : ""} onClick={() => { setViewMode("graph"); setNavContext("search"); setSearchOpen(true); }}><Search size={17} /><span>Search</span></button>
              <button aria-current={navContext === "governance" ? "page" : undefined} className={navContext === "governance" ? "active" : ""} onClick={showGovernance}><ShieldAlert size={17} /><span>Action Gate</span><em>{governance.policies.length}</em></button>
              <button aria-current={navContext === "intelligence" ? "page" : undefined} className={navContext === "intelligence" ? "active" : ""} onClick={showIntelligence}><Gauge size={17} /><span>Intelligence</span></button>
              <button aria-current={navContext === "memory" ? "page" : undefined} className={navContext === "memory" ? "active" : ""} onClick={() => showDrawer("memory")}><Database size={17} /><span>Memory Ledger</span></button>
              <button aria-current={navContext === "checkpoint" ? "page" : undefined} className={navContext === "checkpoint" ? "active" : ""} onClick={() => showDrawer("checkpoint")}><Route size={17} /><span>Continue Work</span></button>
              <button aria-current={navContext === "receipts" ? "page" : undefined} className={navContext === "receipts" ? "active" : ""} onClick={() => showDrawer("receipts")}><Sparkles size={17} /><span>Context Packs</span><em>{receipts.length}</em></button>
              <button onClick={() => setCommandOpen(true)}><Command size={17} /><span>Command Palette</span></button>
              <button title="Check this Rta-Smriti checkout for GitHub release requirements" aria-current={navContext === "publish" ? "page" : undefined} className={navContext === "publish" ? "active" : ""} onClick={showPublishReadiness}><Rocket size={17} /><span>Rta-Smriti Release</span><em>{publishReady}/{publishTotal}</em></button>
              <button aria-current={navContext === "settings" ? "page" : undefined} className={navContext === "settings" ? "active" : ""} onClick={() => { showWorkspace("graph"); setSettingsOpen(true); setNavContext("settings"); }}><SlidersHorizontal size={17} /><span>Settings</span></button>
            </div>
          </nav>
          <div className="railFooter">
            <span>
              <Database size={15} /> {isProjectRegistryLoading ? `${projects.length} found / checking` : `${readyProjects}/${projects.length} ready`}
            </span>
            <span>
              <HardDrive size={15} /> SQLite
            </span>
          </div>
        </aside>

        <main className={stageExpanded ? "brainStage expanded" : "brainStage"}>
          <div className="stageToolbar">
            <div className="viewSwitch" aria-label="Workspace view">
              <button aria-pressed={viewMode === "graph"} className={viewMode === "graph" ? "active" : ""} onClick={() => showWorkspace("graph")}><GitBranch size={15} /> Graph</button>
              <button aria-pressed={viewMode === "canvas"} className={viewMode === "canvas" ? "active" : ""} onClick={() => showWorkspace("canvas")}><MapIcon size={15} /> Canvas</button>
              <button aria-pressed={viewMode === "bases"} className={viewMode === "bases" ? "active" : ""} onClick={() => showBase("memory", "", "bases")}><Table2 size={15} /> Bases</button>
              <button aria-pressed={viewMode === "truth"} className={viewMode === "truth" ? "active" : ""} onClick={showTruth}><Activity size={15} /> Truth</button>
              <button aria-pressed={viewMode === "capture"} className={viewMode === "capture" ? "active" : ""} onClick={showCapture}><RadioTower size={15} /> Capture</button>
              <button aria-pressed={viewMode === "cognition"} className={viewMode === "cognition" ? "active" : ""} onClick={showCognition}><BrainCircuit size={15} /> Reality</button>
            </div>
            {!(["truth", "capture", "cognition"].includes(viewMode)) && (
              <>
                <div className="modeGroup" aria-label="Graph scope">
                  {graphModes.map((mode) => (
                    <button key={mode} aria-pressed={graphMode === mode} className={graphMode === mode ? "active" : ""} onClick={() => setGraphMode(mode)}>{mode}</button>
                  ))}
                </div>
                <button className={searchOpen ? "toolButton active" : "toolButton"} onClick={() => setSearchOpen((value) => !value)} aria-label="Search" aria-pressed={searchOpen} title="Search">
                  <Search size={16} /> <span className="toolText">Search</span>
                </button>
                <button className={typesOpen ? "toolButton active" : "toolButton"} onClick={() => setTypesOpen((value) => !value)} aria-label="Types" aria-pressed={typesOpen} title="Types">
                  <Layers3 size={16} /> <span className="toolText">Types</span>
                </button>
                <button className={settingsOpen ? "toolButton active" : "toolButton"} onClick={() => setSettingsOpen((value) => { const next = !value; setNavContext(next ? "settings" : viewMode); return next; })} aria-label="Settings" aria-pressed={settingsOpen} title="Graph settings">
                  <SlidersHorizontal size={16} /> <span className="toolText">Settings</span>
                </button>
                <button className="toolButton iconOnly" onClick={() => exportView(`${selectedProject?.project || "rta-smriti"}-${viewMode}.json`, { project: selectedProject?.project, task, view: viewMode, graph: visibleGraph })} aria-label="Export current view" title="Export current view">
                  <Download size={16} />
                </button>
                <button className={inspectorOpen ? "toolButton active" : "toolButton"} onClick={() => setInspectorOpen((value) => !value)} aria-label={inspectorOpen ? "Close detail panel" : "Open detail panel"} title={inspectorOpen ? "Close detail panel" : "Open detail panel"}>
                  <PanelRightOpen size={16} />
                </button>
              </>
            )}
            <button className="toolButton" onClick={() => setStageExpanded((value) => !value)} aria-label={stageExpanded ? "Exit expanded workspace" : "Expand workspace"}>
              <Maximize2 size={16} />
            </button>
            {(selectedProject?.root_conflict || selectedProject?.root_duplicate || (selectedProject?.scan_state !== "checking" && selectedProject?.integrity?.status !== "checking" && selectedProject?.integrity?.operationally_ready === false)) && (
              <div className="rootConflictBanner" role="alert">
                <ShieldCheck size={17} />
                <span>
                  <strong>{selectedProject?.root_conflict || selectedProject?.root_duplicate ? "Canonical-root conflict." : "Checkout integrity needs attention."}</strong>
                  <span className="rootConflictDetail"> Verify the selected project binding before using its context.</span>
                </span>
                <button onClick={() => showDrawer("checkpoint")}>Review</button>
              </div>
            )}
          </div>

          {!(["truth", "capture", "cognition"].includes(viewMode)) && <div className={searchOpen || typesOpen || settingsOpen ? "graphFilters" : "graphFilters collapsed"}>
              {searchOpen && (
                <label className="nodeSearch" id="graph-search-controls">
                  <Search size={15} />
                  <input value={nodeQuery} onChange={(event) => setNodeQuery(event.target.value)} placeholder="Search files, symbols, memories..." aria-label="Search graph nodes" autoFocus />
                </label>
              )}
              {typesOpen && (
                <div className="typeFilters" id="graph-type-controls" aria-label="Graph type filters">
                  {allGraphTypes.map((type) => (
                    <button key={type} aria-pressed={activeTypes.includes(type)} className={activeTypes.includes(type) ? "active" : ""} onClick={() => toggleType(type)}>
                      <i style={{ background: graphPalette[type] }} /> {type}
                    </button>
                  ))}
                </div>
              )}
              {settingsOpen && (
                <GraphSettings
                  id="graph-settings-controls"
                  depth={graphDepth}
                  setDepth={setGraphDepth}
                  showLabels={showLabels}
                  setShowLabels={setShowLabels}
                  showEdges={showEdges}
                  setShowEdges={setShowEdges}
                  projectSettings={projectSettings}
                  setProjectSettings={setProjectSettings}
                  parserCapabilities={parserCapabilities}
                  integrity={selectedProject?.integrity}
                  onSave={saveProjectSettings}
                  isSaving={isSavingSettings}
                  watcher={watcher}
                  onStartWatcher={startWatcher}
                  onStopWatcher={stopWatcher}
                  isChangingWatcher={isChangingWatcher}
                  continuity={continuity}
                  onToggleContinuity={toggleContinuity}
                  isChangingContinuity={isChangingContinuity}
                />
              )}
            </div>}

          {viewMode === "graph" && <GraphCanvas graph={visibleGraph} selectedNode={selectedNode} onSelect={selectPrimaryNode} query={nodeQuery} showLabels={showLabels} showEdges={showEdges} />}
          {viewMode === "files" && (
            <FileExplorer
              tree={fileTree}
              preview={filePreview}
              loading={filesLoading}
              freshness={freshness}
              onOpen={(entry) => entry.kind === "directory" ? loadFiles(entry.relative_path, "") : loadFilePreview(entry)}
              onNavigate={(prefix) => loadFiles(prefix, "")}
              onSearch={(query) => loadFiles("", query)}
              onRefresh={() => loadFiles(fileTree.prefix || "", fileTree.query || "")}
              onCopy={(path) => copyText(path, "Relative path copied.")}
              onUse={addFileToTask}
            />
          )}
          {viewMode === "canvas" && <CanvasBoard project={selectedProject} graph={visibleGraph} onSelect={(node) => selectPrimaryNode(node, "evidence")} onKeyboardInspect={inspectCanvasNodeFromKeyboard} onExport={exportView} />}
          {viewMode === "bases" && <BasesView memories={memories} graph={computedGraph} publish={publish} onSelect={(node) => selectPrimaryNode(node, "evidence")} initialTable={baseScope.table} kindFilter={baseScope.kind} />}
          {viewMode === "truth" && (
            <TemporalTruthWorkspace
              data={truthData}
              detail={truthDetail}
              diff={truthDiff}
              busy={isTruthBusy}
              onRefresh={() => loadTruth()}
              onInspect={inspectTruthClaim}
              onCompare={compareTruth}
              onRebuild={rebuildTruth}
            />
          )}

          {viewMode === "capture" && (
            <CaptureConsole
              project={selectedProject}
              overview={captureData.overview}
              replay={captureData.replay}
              diagnostics={captureData.diagnostics}
              busy={captureBusy}
              error={captureError}
              replayMode={captureReplayMode}
              privacyCeiling={capturePrivacyCeiling}
              onReplayMode={(mode) => { setCaptureReplayMode(mode); loadCapture(selectedProject, mode, capturePrivacyCeiling); }}
              onPrivacyCeiling={(ceiling) => { setCapturePrivacyCeiling(ceiling); loadCapture(selectedProject, captureReplayMode, ceiling); }}
              onRefresh={() => loadCapture()}
              onAction={runCaptureAction}
              onExport={exportCapture}
            />
          )}
          {viewMode === "cognition" && (
            <CognitionConsole
              data={cognitionData ? { ...cognitionData, multimodal: { ...cognitionData.multimodal, verification: mediaVerification } } : null}
              busy={cognitionBusy}
              error={cognitionError}
              onRefresh={() => loadCognition()}
              onReconcile={reconcileCognition}
              onAddMedia={addMediaSource}
              onVerifyMedia={verifyMediaSource}
              onExportMedia={exportMediaManifest}
              onOpenTruth={showTruth}
            />
          )}

          {viewMode !== "capture" && <TaskComposer
            task={task}
            setTask={setTask}
            project={selectedProject}
            freshness={freshness}
            command={command}
            packText={packText}
            onGenerate={generatePack}
            onCopy={() => copyText(packText || command, packText ? "Context pack copied." : "Command copied.")}
            onReceipts={() => showDrawer("receipts")}
            onCopyContinuation={copyContinuationPrompt}
            receiptCount={receipts.length}
            isGenerating={isGenerating}
            targetAgent={targetAgent}
            setTargetAgent={setTargetAgent}
            customAgent={customAgent}
            setCustomAgent={setCustomAgent}
            contextBudget={contextBudget}
            setContextBudget={setContextBudget}
            studioMode={contextStudioMode}
            setStudioMode={setContextStudioMode}
            compilerMode={compilerMode}
            setCompilerMode={setCompilerMode}
            comparisonMode={comparisonMode}
            setComparisonMode={setComparisonMode}
            governedCompilation={governedCompilation}
            compilerInspection={compilerInspection}
            onInspectCompilation={inspectGovernedCompilation}
          />}
        </main>

        <aside ref={inspectorRef} tabIndex={-1} aria-label="Project detail inspector" className={inspectorOpen ? "inspector" : "inspector hidden"}>
          <div className="inspectorTabs">
            <button aria-pressed={activeDrawer === "evidence"} className={activeDrawer === "evidence" ? "active" : ""} onClick={() => showDrawer("evidence")}>
              <PanelRightOpen size={15} /> Evidence
            </button>
            <button aria-pressed={activeDrawer === "references"} className={activeDrawer === "references" ? "active" : ""} onClick={() => showDrawer("references")}>
              <GitBranch size={15} /> Refs
            </button>
            <button aria-pressed={activeDrawer === "governance"} className={activeDrawer === "governance" ? "active" : ""} onClick={showGovernance}>
              <ShieldAlert size={15} /> Gate
            </button>
            <button aria-pressed={activeDrawer === "intelligence"} className={activeDrawer === "intelligence" ? "active" : ""} onClick={showIntelligence}>
              <Gauge size={15} /> Intel
            </button>
            <button aria-pressed={activeDrawer === "memory"} className={activeDrawer === "memory" ? "active" : ""} onClick={() => showDrawer("memory")}>
              <MemoryStick size={15} /> Memory
            </button>
            <button aria-pressed={activeDrawer === "checkpoint"} className={activeDrawer === "checkpoint" ? "active" : ""} onClick={() => showDrawer("checkpoint")}>
              <Route size={15} /> Continue
            </button>
            <button aria-pressed={activeDrawer === "receipts"} className={activeDrawer === "receipts" ? "active" : ""} onClick={() => showDrawer("receipts")}>
              <Clipboard size={15} /> Packs
            </button>
            <button aria-pressed={activeDrawer === "publish"} className={activeDrawer === "publish" ? "active" : ""} onClick={showPublishReadiness}>
              <Rocket size={15} /> Release
            </button>
          </div>

          {activeDrawer === "evidence" && (
            <EvidenceInspector
              node={activeNode}
              memories={memories}
              project={selectedProject}
              freshness={freshness}
              packText={packText}
              onCopy={() => copyText(packText || command)}
              onBootstrap={() => showDrawer("bootstrap")}
              onRefresh={refreshIndex}
              isRefreshing={isRefreshingIndex}
            />
          )}
          {activeDrawer === "references" && (
            <ReferencesPanel
              node={activeNode}
              references={references}
              history={referenceHistory}
              onSelect={openReference}
              onBack={goBackReference}
              onStart={goToReferenceStart}
            />
          )}
          {activeDrawer === "governance" && (
            <GovernancePanel
              project={selectedProject}
              governance={governance}
              decision={preflightDecision}
              onEvaluate={evaluatePreflight}
              onCreate={createGovernancePolicy}
              onRetire={retireGovernancePolicy}
              onRefresh={() => loadGovernance()}
              isBusy={isGovernanceBusy}
            />
          )}
          {activeDrawer === "memory" && <MemoryLedger memories={memories} onReflect={reflect} onFeedback={recordMemoryFeedback} />}
          {activeDrawer === "intelligence" && (
            <IntelligencePanel
              project={selectedProject}
              projects={projects}
              task={task}
              data={intelligence}
              busy={isIntelligenceBusy}
              onDiagnose={runRetrievalDiagnostics}
              onGraphQuery={runImpactQuery}
              onCreateWorkspace={createProjectWorkspace}
              onAddMember={addWorkspaceMember}
              onRemoveMember={removeWorkspaceMember}
              onDeleteWorkspace={deleteProjectWorkspace}
              onNotify={setMessage}
            />
          )}
          {activeDrawer === "checkpoint" && (
            <CheckpointPanel
              checkpoint={checkpoint}
              readiness={continuationReadiness}
              project={selectedProject}
              onSave={saveCheckpoint}
              onCopy={copyContinuationPrompt}
              isSaving={isSavingCheckpoint}
            />
          )}
          {activeDrawer === "receipts" && <ReceiptsPanel receipts={receipts} onCopy={copyText} onClear={() => setReceipts([])} />}
          {activeDrawer === "publish" && <PublishPanel publish={publish} onRefresh={refreshPublishReadiness} isRefreshing={isRefreshingPublish} />}
          {activeDrawer === "bootstrap" && <BootstrapPanel onDone={loadHealth} shellKind={shellKind} />}
        </aside>
      </div>

      <footer className="statusBar">
        <span>
          <CheckCircle2 size={14} /> Brain Status: {isLoading || isProjectRegistryLoading ? "Checking" : loadError ? "Needs attention" : "Healthy"}
        </span>
        <span>
          <CircleDot size={14} /> Graph DB: Local SQLite
        </span>
        <span role="status" aria-live="polite" aria-atomic="true">
          <Activity size={14} /> {message || "Ready"}
        </span>
      </footer>

      {commandOpen && (
        <CommandPalette
          command={command}
          cliCommand={cliCommand}
          shellKind={shellKind}
          brainDir={health?.brain_dir}
          onClose={() => setCommandOpen(false)}
          onCopy={copyText}
        />
      )}
    </div>
  );
}

function GraphSettings({
  id,
  depth, setDepth, showLabels, setShowLabels, showEdges, setShowEdges,
  projectSettings, setProjectSettings, parserCapabilities, integrity, onSave, isSaving,
  watcher, onStartWatcher, onStopWatcher, isChangingWatcher,
  continuity, onToggleContinuity, isChangingContinuity,
}) {
  const settings = projectSettings || {};
  const integrityPending = !integrity || integrity.status === "checking" || integrity.status === "not_checked";
  const updateSetting = (key, value) => setProjectSettings((current) => ({ ...(current || {}), [key]: value }));
  const parserStatus = parserCapabilities[settings.parser_adapter];
  const watcherRunning = watcher?.state === "running";
  return (
    <div className="graphSettings" id={id}>
      <div className="settingsGroup graphDisplaySettings">
        <strong>Graph display</strong>
        <label>
          <span>Connection depth</span>
          <input type="range" min="1" max="4" value={depth} onChange={(event) => setDepth(Number(event.target.value))} />
          <strong>{depth}</strong>
        </label>
        <label className="toggleLabel"><input type="checkbox" checked={showLabels} onChange={(event) => setShowLabels(event.target.checked)} /> Persistent labels</label>
        <label className="toggleLabel"><input type="checkbox" checked={showEdges} onChange={(event) => setShowEdges(event.target.checked)} /> Connections</label>
      </div>
      <div className="settingsGroup indexPolicySettings">
        <strong>Project indexing policy</strong>
        <label>
          <span>Maximum source file size</span>
          <div className="numberUnit">
            <input
              type="number"
              min="0.01"
              max="16"
              step="0.1"
              value={settings.max_file_bytes ? Number(settings.max_file_bytes / 1_000_000).toFixed(2) : ""}
              onChange={(event) => updateSetting("max_file_bytes", Math.round(Number(event.target.value) * 1_000_000))}
            />
            <span>MB</span>
          </div>
        </label>
        <label>
          <span>Oversized source handling</span>
          <select value={settings.large_file_policy || "metadata"} onChange={(event) => updateSetting("large_file_policy", event.target.value)}>
            <option value="metadata">Metadata only (recommended)</option>
            <option value="block">Strict block</option>
          </select>
        </label>
        <label>
          <span>Parser adapter</span>
          <select value={settings.parser_adapter || "auto"} onChange={(event) => updateSetting("parser_adapter", event.target.value)}>
            <option value="auto">Auto (bundled Tree-sitter)</option>
            <option value="regex">Regex (built in)</option>
            <option value="tree-sitter">Tree-sitter</option>
            <option value="lsp">Language server</option>
          </select>
          {parserStatus && <em className={parserStatus.available ? "available" : "optional"}>{parserStatus.available ? "Ready" : "Optional dependency"}</em>}
        </label>
        {settings.parser_adapter === "lsp" && (
          <>
            <label className="toggleLabel">
              <input type="checkbox" checked={settings.lsp_auto_discovery !== false} onChange={(event) => updateSetting("lsp_auto_discovery", event.target.checked)} />
              Auto-detect supported language servers
            </label>
            <label className="lspCommand">
              <span>Legacy JSON adapter <em>optional override</em></span>
              <input value={settings.lsp_command || ""} onChange={(event) => updateSetting("lsp_command", event.target.value)} placeholder="Leave blank to use a detected LSP server" />
            </label>
            <small className="detectedServers">
              {(parserCapabilities.lsp?.detected_servers || []).length
                ? `Detected: ${parserCapabilities.lsp.detected_servers.map((server) => server.name).join(", ")}`
                : "No supported language server detected; parsing will fall back safely."}
            </small>
            <p className="blockedPolicyWarning"><ShieldCheck size={14} /> Use only language servers you trust. A server can read repository files and project configuration; Rta-Smriti rejects project-local discovery and verifies the selected executable has not changed before launch.</p>
          </>
        )}
        <label>
          <span>Hybrid retrieval</span>
          <select value={settings.embedding_provider || "none"} onChange={(event) => updateSetting("embedding_provider", event.target.value)}>
            <option value="none">Off (FTS only)</option>
            <option value="hash">Local feature hash</option>
            <option value="sentence-transformers">Sentence Transformers (optional)</option>
          </select>
        </label>
        <label>
          <span>Thread compaction</span>
          <select value={settings.compaction_provider || "none"} onChange={(event) => updateSetting("compaction_provider", event.target.value)}>
            <option value="none">Off (deterministic checkpoint only)</option>
            <option value="ollama">Local Ollama (opt in)</option>
          </select>
        </label>
        {settings.compaction_provider === "ollama" && (
          <>
            <label><span>Local model</span><input type="text" value={settings.compaction_model || "qwen3:0.6b"} onChange={(event) => updateSetting("compaction_model", event.target.value)} /></label>
            <label><span>Loopback endpoint</span><input type="text" value={settings.compaction_endpoint || "http://127.0.0.1:11434"} onChange={(event) => updateSetting("compaction_endpoint", event.target.value)} /></label>
          </>
        )}
        <button className="savePolicyButton" onClick={onSave} disabled={!projectSettings || isSaving}>
          <ShieldCheck size={15} /> {isSaving ? "Saving..." : "Save Policy"}
        </button>
        <p className="blockedPolicyWarning"><ShieldCheck size={14} /> Metadata-only files remain visible as warnings and are never represented as content-verified. Strict block mode remains available.</p>
      </div>
      <div className={`settingsGroup integritySettings ${integrityPending ? "checking" : integrity?.operationally_ready ? "verified" : "attention"}`}>
        <div className="watcherHeading">
          <ShieldCheck size={16} />
          <span><strong>Checkout integrity</strong><small>{integrityPending ? "Verifying" : integrity?.operationally_ready ? "Verified" : "Attention required"}</small></span>
        </div>
        <div className="integrityFacts">
          <span>Schema <b>{integrityPending ? "checking" : `v${integrity?.schema_version ?? "?"}`}</b></span>
          <span>Binding <b>{integrityPending ? "checking" : integrity?.binding?.state?.replaceAll("_", " ") || "unknown"}</b></span>
          <span>Root <b>{integrityPending ? "checking" : integrity?.binding?.root_fingerprint || "unbound"}</b></span>
          <span>Duplicates <b>{integrityPending ? "checking" : integrity?.duplicate_root_count ?? 0}</b></span>
        </div>
      </div>
      <div className="settingsGroup watcherSettings">
        <div className="watcherHeading">
          <span className={`watcherDot ${watcher?.state === "running" ? "running" : ""}`} />
          <span><strong>Repository sync</strong><small>{watcher?.state || "stopped"}{watcher?.backend ? ` / ${watcher.backend}` : ""}</small></span>
        </div>
        <p>Keep the indexed brain current after this console closes.</p>
        {watcher?.last_error && <em className="watcherError" title={watcher.last_error}>Last cycle needs attention</em>}
        <button
          className={watcherRunning ? "watcherStopButton" : "watcherStartButton"}
          onClick={watcherRunning ? onStopWatcher : onStartWatcher}
          disabled={isChangingWatcher}
          aria-busy={isChangingWatcher}
        >
          {watcherRunning ? <CircleDot size={15} /> : <Activity size={15} />}
          {watcherRunning ? "Stop Sync" : "Start Sync"}
        </button>
      </div>
      <div className="settingsGroup watcherSettings continuitySettings">
        <div className="watcherHeading">
          <span className={`watcherDot ${continuity?.state === "running" ? "running" : ""}`} />
          <span><strong>Task continuity</strong><small>{continuity?.state || "stopped"}{continuity?.backend ? ` / ${continuity.backend}` : ""}</small></span>
        </div>
        <p>Capture matching Codex sessions and create clearly marked, unverified interruption checkpoints.</p>
        {continuity?.last_capture_at && <small>Last capture {new Date(continuity.last_capture_at).toLocaleString()}</small>}
        {continuity?.last_checkpoint_at && <small>Last checkpoint {new Date(continuity.last_checkpoint_at).toLocaleString()}</small>}
        {continuity?.state === "running" && <small>{continuity?.sessions_pending || 0} session{continuity?.sessions_pending === 1 ? "" : "s"} pending / {continuity?.lookback_days === 0 ? "all history" : `${continuity?.lookback_days || 30}-day lookback`}</small>}
        {continuity?.last_error && <em className="watcherError" title={continuity.last_error}>Capture needs attention</em>}
        <button
          className={continuity?.state === "running" ? "watcherStopButton" : "watcherStartButton"}
          onClick={onToggleContinuity}
          disabled={isChangingContinuity}
        >
          {continuity?.state === "running" ? <CircleDot size={15} /> : <Activity size={15} />}
          {isChangingContinuity ? "Working..." : continuity?.state === "running" ? "Stop Capture" : "Start Capture"}
        </button>
      </div>
    </div>
  );
}

function TemporalTruthWorkspace({ data, detail, diff, busy, onRefresh, onInspect, onCompare, onRebuild }) {
  const [tab, setTab] = useState("timeline");
  const maxSequence = Math.max(1, ...(data.events || []).map((event) => Number(event.project_sequence || 0)));
  const [fromSequence, setFromSequence] = useState(Math.max(1, maxSequence - 1));
  const [toSequence, setToSequence] = useState(maxSequence);
  const [validAt, setValidAt] = useState(() => new Date().toISOString());

  useEffect(() => {
    setFromSequence(Math.max(1, maxSequence - 1));
    setToSequence(maxSequence);
  }, [maxSequence]);

  const readiness = data.readiness || {};
  const counts = data.counts || {};
  const selectedClaim = detail?.claim;
  const objectText = (value) => {
    const encoded = JSON.stringify(value) ?? "null";
    return encoded.length > 180 ? `${encoded.slice(0, 177)}...` : encoded;
  };

  return (
    <section className="truthWorkspace" aria-label="Temporal truth workspace">
      <header className="truthHeader">
        <div>
          <span className="sectionEyebrow">Selective event sourcing</span>
          <h2>Temporal Truth</h2>
          <p>What the project claimed, when it applied, and when the brain learned it.</p>
        </div>
        <div className="truthHeaderActions">
          <span className={readiness.ledger_intact ? "truthHealth ok" : "truthHealth danger"}>
            {readiness.ledger_intact ? <ShieldCheck size={15} /> : <ShieldAlert size={15} />}
            {readiness.ledger_intact ? "Ledger intact" : "Ledger failed"}
          </span>
          <button className="iconButton" onClick={onRefresh} disabled={busy} title="Refresh temporal truth" aria-label="Refresh temporal truth"><RefreshCw size={16} /></button>
          <button className="secondaryButton" onClick={onRebuild} disabled={busy || !readiness.ledger_intact}><RotateCcw size={15} /> Rebuild projections</button>
        </div>
      </header>

      <div className="truthMetrics" aria-label="Temporal truth counts">
        <article><strong>{safeNumber(counts.events)}</strong><span>Immutable events</span></article>
        <article><strong>{safeNumber(counts.current_claims)}</strong><span>Current claims</span></article>
        <article className={counts.contradictions ? "warn" : ""}><strong>{safeNumber(counts.contradictions)}</strong><span>Contradictions</span></article>
        <article className={counts.failed_validators ? "danger" : ""}><strong>{safeNumber(counts.failed_validators)}</strong><span>Failed validators</span></article>
        <article><strong>{safeNumber(counts.abstentions)}</strong><span>Abstentions</span></article>
      </div>

      <div className="truthTabs" role="tablist" aria-label="Temporal truth views">
        {["timeline", "claims", "conflicts", "validators", "diff"].map((item) => (
          <button key={item} role="tab" aria-selected={tab === item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>
            {item === "conflicts" ? "Contradictions" : item === "validators" ? "Validator Health" : item[0].toUpperCase() + item.slice(1)}
          </button>
        ))}
      </div>

      <div className="truthBody">
        <div className="truthPrimary">
          {tab === "timeline" && (
            <div className="truthTimeline" role="tabpanel">
              {(data.events || []).map((event) => (
                <article key={event.event_id}>
                  <div className="timelineRail"><i /><span>{event.project_sequence}</span></div>
                  <div className="timelineCard">
                    <header><strong>{String(event.event_type).replace(/\.v\d+$/, "").replaceAll("_", " ")}</strong><time>{new Date(event.recorded_at).toLocaleString()}</time></header>
                    <p>{event.stream_id} / v{event.stream_version}</p>
                    <code>{objectText(event.payload_summary || {})}</code>
                    <footer>{event.actor_type}:{event.actor_id} / {event.source} / {event.verification_status}</footer>
                  </div>
                </article>
              ))}
              {!data.events?.length && <div className="truthEmpty"><Activity size={24} /><strong>No temporal events yet</strong><span>Create the first consequential claim through the CLI or operator API.</span></div>}
            </div>
          )}

          {tab === "claims" && (
            <div className="truthClaimList" role="tabpanel">
              {(data.claims || []).map((claim) => (
                <button key={claim.claim_id} onClick={() => onInspect(claim.claim_id)} className={selectedClaim?.claim_id === claim.claim_id ? "active" : ""}>
                  <span className={`truthState ${claim.effective_state}`}>{claim.effective_state}</span>
                  <strong>{claim.redacted ? `${String(claim.privacy_class || "private").replace(/^./, (letter) => letter.toUpperCase())} claim` : claim.subject}</strong>
                  <span>{claim.redacted ? "Value hidden by privacy policy" : `${claim.predicate} = ${objectText(claim.object)}`}</span>
                  <small>Recorded from sequence {claim.recorded_from_sequence}</small>
                </button>
              ))}
              {!data.claims?.length && <div className="truthEmpty"><Database size={24} /><strong>No current claims</strong><span>The legacy memory index remains available while temporal truth starts empty.</span></div>}
            </div>
          )}

          {tab === "conflicts" && (
            <div className="truthConflictList" role="tabpanel">
              {(data.contradictions || []).map((item) => (
                <article key={item.relation_id}>
                  <ShieldAlert size={18} />
                  <div><strong>{item.from_claim_id}</strong><span>contradicts</span><strong>{item.to_claim_id}</strong></div>
                  <small>{item.authority_class} / confidence {Number(item.confidence || 0).toFixed(2)}</small>
                </article>
              ))}
              {!data.contradictions?.length && <div className="truthEmpty"><CheckCircle2 size={24} /><strong>No active contradictions</strong><span>Competing branches will appear here without being silently resolved.</span></div>}
            </div>
          )}

          {tab === "validators" && (
            <div className="truthValidatorList" role="tabpanel">
              {(data.validators || []).map((validator) => (
                <article key={validator.validator_id} className={validator.outcome === "fail" || validator.outcome === "error" ? "failed" : ""}>
                  <div className={`validatorOutcome ${validator.outcome}`}><CircleDot size={15} /> {validator.outcome}</div>
                  <strong>{validator.validator_id}</strong>
                  <span>{validator.type} protects {validator.claim_id}</span>
                  <small>Failure makes the claim {validator.failure_effect}</small>
                </article>
              ))}
              {!data.validators?.length && <div className="truthEmpty"><ShieldCheck size={24} /><strong>No validators defined</strong><span>Add deterministic proof checks from the CLI or operator API.</span></div>}
            </div>
          )}

          {tab === "diff" && (
            <div className="truthDiff" role="tabpanel">
              <form onSubmit={(event) => { event.preventDefault(); onCompare(fromSequence, toSequence, validAt); }}>
                <label>From sequence<input type="number" min="1" value={fromSequence} onChange={(event) => setFromSequence(Number(event.target.value))} /></label>
                <label>To sequence<input type="number" min="1" value={toSequence} onChange={(event) => setToSequence(Number(event.target.value))} /></label>
                <label>Valid at<input value={validAt} onChange={(event) => setValidAt(event.target.value)} /></label>
                <button className="primaryButton" type="submit" disabled={busy || fromSequence >= toSequence}><GitBranch size={15} /> Compare</button>
              </form>
              <div className="truthDiffResults">
                {(diff?.changes || []).map((change) => (
                  <article key={change.claim_id}>
                    <strong>{change.claim_id}</strong>
                    <div><span>Before</span><code>{objectText(change.before || { status: "absent" })}</code></div>
                    <div><span>After</span><code>{objectText(change.after || { status: "absent" })}</code></div>
                  </article>
                ))}
                {diff && !diff.changes?.length && <div className="truthEmpty"><CheckCircle2 size={24} /><strong>No truth changes</strong><span>The selected recorded-time interval produced the same valid-time view.</span></div>}
              </div>
            </div>
          )}
        </div>

        <aside className="truthInspector" aria-label="Selected truth claim evidence">
          <span className="sectionEyebrow">Claim inspector</span>
          {selectedClaim ? (
            <>
              <span className={`truthState ${selectedClaim.effective_state}`}>{selectedClaim.effective_state}</span>
              <h3>{selectedClaim.redacted ? `${String(selectedClaim.privacy_class || "private").replace(/^./, (letter) => letter.toUpperCase())} claim` : selectedClaim.subject}</h3>
              <p>{selectedClaim.redacted ? "Value hidden by privacy policy" : `${selectedClaim.predicate} = ${objectText(selectedClaim.object)}`}</p>
              <section><strong>Evidence</strong>{(detail.evidence || []).map((item) => <div key={item.evidence_id} className="truthEvidence"><span>{item.polarity}</span><b>{item.evidence_id}</b><small>{item.method} / {item.authority_class}</small></div>)}{!detail.evidence?.length && <small>No evidence attached.</small>}</section>
              <section><strong>Relations</strong>{(detail.relations || []).map((item) => <div key={item.relation_id} className="truthEvidence"><span>{item.relation_type}</span><b>{item.from_claim_id} → {item.to_claim_id}</b></div>)}{!detail.relations?.length && <small>No relations attached.</small>}</section>
            </>
          ) : (
            <div className="truthEmpty"><Eye size={24} /><strong>Select a claim</strong><span>Open Claims to inspect its evidence, contradictions, and provenance.</span></div>
          )}
        </aside>
      </div>
    </section>
  );
}


function GraphCanvas({ graph, selectedNode, onSelect, query, showLabels, showEdges }) {
  const canvasRef = useRef(null);
  const panRef = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [hoveredNodeId, setHoveredNodeId] = useState(null);
  const [hoveredHubId, setHoveredHubId] = useState(null);
  const [collapsedHubs, setCollapsedHubs] = useState([]);
  const displayedNodes = graph.nodes.filter((node) => !collapsedHubs.includes(node.hubId));
  const nodesById = useMemo(() => new Map(displayedNodes.map((node) => [node.id, node])), [displayedNodes]);

  useEffect(() => {
    setCollapsedHubs([]);
  }, [graph.core?.id]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas && canvas.scrollWidth > canvas.clientWidth) {
      canvas.scrollLeft = (canvas.scrollWidth - canvas.clientWidth) / 2;
    }
  }, [graph.nodes.length]);

  const focusX = 500;
  const focusY = 304;
  const viewWidth = 1000 / zoom;
  const viewHeight = 620 / zoom;
  const viewX = Math.max(0, Math.min(1000 - viewWidth, focusX - viewWidth / 2 + pan.x));
  const viewY = Math.max(0, Math.min(620 - viewHeight, focusY - viewHeight / 2 + pan.y));

  function centerGraph() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    window.requestAnimationFrame(() => {
      const canvas = canvasRef.current;
      if (canvas && canvas.scrollWidth > canvas.clientWidth) {
        canvas.scrollLeft = (canvas.scrollWidth - canvas.clientWidth) / 2;
      }
    });
  }

  function beginPan(event) {
    if (event.button !== 0) return;
    const bounds = event.currentTarget.ownerSVGElement?.getBoundingClientRect();
    if (!bounds) return;
    event.currentTarget.setPointerCapture?.(event.pointerId);
    panRef.current = { x: event.clientX, y: event.clientY, pan, bounds };
    setIsPanning(true);
  }

  function movePan(event) {
    const start = panRef.current;
    if (!start) return;
    setPan({
      x: start.pan.x - ((event.clientX - start.x) / start.bounds.width) * viewWidth,
      y: start.pan.y - ((event.clientY - start.y) / start.bounds.height) * viewHeight,
    });
  }

  function endPan() {
    panRef.current = null;
    setIsPanning(false);
  }

  function toggleHub(hubId) {
    setCollapsedHubs((current) => current.includes(hubId) ? current.filter((id) => id !== hubId) : [...current, hubId]);
  }

  return (
    <section ref={canvasRef} className={`graphCanvas ${isPanning ? "panning" : ""}`} aria-label="Interactive project brain graph">
      <svg className="graphSvg" viewBox={`${viewX} ${viewY} ${viewWidth} ${viewHeight}`} role="group" aria-label="Rta-Smriti graph">
        <defs>
          <filter id="softGlow">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <rect width="1000" height="620" className="gridRect" onPointerDown={beginPan} onPointerMove={movePan} onPointerUp={endPan} onPointerCancel={endPan} />
        {showEdges && (graph.hubs || []).length > 1 && (graph.hubs || []).map((hub, index, hubs) => {
          const next = hubs[(index + 1) % hubs.length];
          const x1 = hub.x * 10;
          const y1 = hub.y * 6.2;
          const x2 = next.x * 10;
          const y2 = next.y * 6.2;
          return (
            <g key={`web-${hub.id}-${next.id}`} className="semanticWebEdge">
              <line x1={x1} y1={y1} x2={x2} y2={y2} />
              <circle cx={(x1 + x2) / 2} cy={(y1 + y2) / 2} r="4" />
            </g>
          );
        })}
        {showEdges && (graph.hubs || []).map((hub) => {
          const collapsed = collapsedHubs.includes(hub.id);
          const x1 = graph.core.x * 10;
          const y1 = graph.core.y * 6.2;
          const x2 = hub.x * 10;
          const y2 = hub.y * 6.2;
          return (
            <g key={`core-${hub.id}`} className={`structureEdge ${hoveredHubId === hub.id ? "active" : ""} ${collapsed ? "collapsed" : ""}`}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} />
              <circle className="relayNode" cx={x1 + (x2 - x1) * 0.56} cy={y1 + (y2 - y1) * 0.56} r="4.5" />
            </g>
          );
        })}
        {showEdges && displayedNodes.map((node) => {
          const hub = graph.hubs?.find((candidate) => candidate.id === node.hubId);
          if (!hub) return null;
          return (
            <g key={`structure-${node.id}`} className={`structureEdge leaf ${hoveredHubId === hub.id ? "active" : ""}`}>
              <line style={{ stroke: hub.color }} x1={hub.x * 10} y1={hub.y * 6.2} x2={node.x * 10} y2={node.y * 6.2} />
            </g>
          );
        })}
        {showEdges && graph.edges.map((edge) => {
          const source = nodesById.get(edge.source);
          const target = nodesById.get(edge.target);
          if (!source || !target) return null;
          const x1 = source.x * 10;
          const y1 = source.y * 6.2;
          const x2 = target.x * 10;
          const y2 = target.y * 6.2;
          const active = selectedNode?.id === source.id || selectedNode?.id === target.id || hoveredNodeId === source.id || hoveredNodeId === target.id;
          return (
            <g key={edge.id} className={active ? "graphEdge active" : "graphEdge"}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} />
              {showLabels && <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 8}>{edge.label}</text>}
            </g>
          );
        })}
        {graph.core && (
          <g className="projectCore" transform={`translate(${graph.core.x * 10}, ${graph.core.y * 6.2})`} aria-label={`${graph.core.label} project brain`} role="img">
            <circle className="projectOrbit outer" r="78" />
            <circle className="projectOrbit" r="64" />
            <circle className="coreAura" r="55" />
            <circle className="coreBody" r="45" />
            <foreignObject x="-17" y="-29" width="34" height="34" pointerEvents="none">
              <span className="projectCoreIcon"><BrainCircuit size={33} /></span>
            </foreignObject>
            <text className="coreLabel" y="25">{graph.core.label.length > 18 ? `${graph.core.label.slice(0, 16)}...` : graph.core.label}</text>
            <text className="coreMeta" y="42">{graph.core.meta}</text>
          </g>
        )}
        {(graph.hubs || []).map((hub) => {
          const HubIcon = hub.icon;
          const collapsed = collapsedHubs.includes(hub.id);
          return (
            <g
              key={hub.id}
              className={`semanticHub ${collapsed ? "collapsed" : ""}`}
              transform={`translate(${hub.x * 10}, ${hub.y * 6.2})`}
              onClick={() => toggleHub(hub.id)}
              onMouseEnter={() => setHoveredHubId(hub.id)}
              onMouseLeave={() => setHoveredHubId(null)}
              onFocus={() => setHoveredHubId(hub.id)}
              onBlur={() => setHoveredHubId(null)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  toggleHub(hub.id);
                }
              }}
              tabIndex={0}
              role="button"
              aria-pressed={collapsed}
              aria-label={`${hub.label}, ${hub.count} nodes. ${collapsed ? "Expand" : "Collapse"} group.`}
            >
              <title>{collapsed ? "Expand" : "Collapse"} {hub.label}</title>
              <circle className="hubAura" r="40" fill={hub.color} />
              <circle className="hubBody" r="32" stroke={hub.color} />
              <foreignObject x="-12" y="-21" width="24" height="24" pointerEvents="none">
                <span className="hubIcon" style={{ color: hub.color }}><HubIcon size={23} /></span>
              </foreignObject>
              <text className="hubLabel" y="21">{hub.label}</text>
              <text className="hubCount" y="39">{hub.count}</text>
            </g>
          );
        })}
        {displayedNodes.map((node, index) => {
          const color = node.color || graphPalette[node.type] || graphPalette.data;
          const active = selectedNode?.id === node.id;
          const NodeIcon = {
            file: FileCode2,
            memory: MemoryStick,
            docs: Files,
            config: SlidersHorizontal,
            test: ShieldCheck,
            data: Database,
            artifact: Layers3,
          }[node.type] || CircleDot;
          const reveal = showLabels || hoveredNodeId === node.id || active;
          const shortLabel = node.label.length > 32 ? `${node.label.slice(0, 29)}...` : node.label;
          const tooltipWidth = Math.min(230, Math.max(112, shortLabel.length * 7.2));
          const absoluteX = node.x * 10;
          const absoluteY = node.y * 6.2;
          const tooltipX = Math.max(8 - absoluteX, Math.min(-tooltipWidth / 2, 992 - absoluteX - tooltipWidth));
          const tooltipY = absoluteY < 70 ? node.size + 12 : -(node.size + 48);
          const related = hoveredHubId === node.hubId;
          return (
            <g
              key={node.id}
              className={`graphNode ${active ? "active" : ""} ${related ? "related" : ""}`}
              transform={`translate(${node.x * 10}, ${node.y * 6.2})`}
              style={{ animationDelay: `${Math.min(index, 20) * 18}ms` }}
              onClick={() => onSelect(node)}
              onMouseEnter={() => setHoveredNodeId(node.id)}
              onMouseLeave={() => setHoveredNodeId(null)}
              onFocus={() => setHoveredNodeId(node.id)}
              onBlur={() => setHoveredNodeId(null)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(node);
                }
              }}
              tabIndex={0}
              role="button"
              aria-label={`${node.label}, ${node.meta}`}
            >
              <circle className="nodeAura" r={node.size + 8} fill={color} />
              <circle className="nodeCore" r={node.size} stroke={color} />
              <foreignObject x="-7" y="-7" width="14" height="14" pointerEvents="none">
                <span className="graphNodeIcon" style={{ color }}><NodeIcon size={14} /></span>
              </foreignObject>
              {reveal && (
                <g className="nodeTooltip" transform={`translate(${tooltipX}, ${tooltipY})`}>
                  <rect width={tooltipWidth} height="38" rx="6" />
                  <text className="nodeLabel" x={tooltipWidth / 2} y="16">{shortLabel}</text>
                  <text className="nodeMeta" x={tooltipWidth / 2} y="30">{node.meta}</text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
      {!displayedNodes.length && (
        <div className="emptyGraph">
          <Search size={24} />
          <strong>No matching nodes</strong>
          <span>{query ? `No graph evidence matched "${query}".` : "Enable at least one graph type."}</span>
        </div>
      )}
      <div className="graphControls">
        <button aria-label="Center graph" onClick={centerGraph}>
          <Crosshair size={14} />
        </button>
        <button aria-label="Zoom in" onClick={() => setZoom((value) => Math.min(1.7, Number((value + 0.1).toFixed(2))))}>
          +
        </button>
        <button aria-label="Zoom out" onClick={() => setZoom((value) => Math.max(0.7, Number((value - 0.1).toFixed(2))))}>
          -
        </button>
        <span>{Math.round(zoom * 100)}%</span>
      </div>
      <div className="legend">
        <span><i className="structureLegend" /> semantic group</span>
        <span><i className="evidenceLegend" /> evidence link</span>
        <span>Hover nodes for detail</span>
      </div>
      {!!displayedNodes.length && (
        <div className="graphMinimap">
          <svg viewBox="0 0 1000 620" role="img" aria-label="Minimap showing the current graph viewport">
            {(graph.hubs || []).map((hub) => <line key={`mini-core-${hub.id}`} x1={graph.core.x * 10} y1={graph.core.y * 6.2} x2={hub.x * 10} y2={hub.y * 6.2} />)}
            {displayedNodes.map((node) => {
              const hub = graph.hubs?.find((candidate) => candidate.id === node.hubId);
              return hub ? <line key={`mini-${node.id}`} x1={hub.x * 10} y1={hub.y * 6.2} x2={node.x * 10} y2={node.y * 6.2} /> : null;
            })}
            <circle className="miniCore" cx={graph.core.x * 10} cy={graph.core.y * 6.2} r="18" />
            {(graph.hubs || []).map((hub) => <circle key={`mini-hub-${hub.id}`} className="miniHub" cx={hub.x * 10} cy={hub.y * 6.2} r="11" />)}
            {displayedNodes.map((node) => <circle key={`mini-node-${node.id}`} className="miniNode" cx={node.x * 10} cy={node.y * 6.2} r="4" />)}
            <rect className="miniViewport" x={viewX} y={viewY} width={viewWidth} height={viewHeight} />
          </svg>
        </div>
      )}
    </section>
  );
}

function FileExplorer({ tree, preview, loading, freshness, onOpen, onNavigate, onSearch, onRefresh, onCopy, onUse }) {
  const [draft, setDraft] = useState(tree.query || "");
  const [previewAction, setPreviewAction] = useState({ kind: "", status: "" });
  const previewActionTimer = useRef(null);
  const parts = String(tree.prefix || "").split("/").filter(Boolean);

  useEffect(() => {
    setDraft(tree.query || "");
  }, [tree.query]);

  useEffect(() => {
    window.clearTimeout(previewActionTimer.current);
    setPreviewAction({ kind: "", status: "" });
  }, [preview?.relative_path]);

  useEffect(() => () => window.clearTimeout(previewActionTimer.current), []);

  function settlePreviewAction(kind, status) {
    window.clearTimeout(previewActionTimer.current);
    setPreviewAction({ kind, status });
    previewActionTimer.current = window.setTimeout(() => setPreviewAction({ kind: "", status: "" }), 2400);
  }

  async function addPreviewToTask() {
    if (!preview?.relative_path || previewAction.status === "working") return;
    setPreviewAction({ kind: "task", status: "working" });
    try {
      const result = await onUse(preview.relative_path);
      settlePreviewAction("task", result === "existing" ? "existing" : "added");
    } catch {
      settlePreviewAction("task", "failed");
    }
  }

  async function copyPreviewPath() {
    if (!preview?.relative_path || previewAction.status === "working") return;
    setPreviewAction({ kind: "copy", status: "working" });
    try {
      const copied = await onCopy(preview.relative_path);
      settlePreviewAction("copy", copied ? "copied" : "failed");
    } catch {
      settlePreviewAction("copy", "failed");
    }
  }

  function submitSearch(event) {
    event.preventDefault();
    onSearch(draft.trim());
  }

  return (
    <section className="fileExplorer" aria-label="Indexed project file explorer">
      <div className="fileExplorerToolbar">
        <div className="fileExplorerTitle">
          <FolderTree size={17} />
          <strong>Files</strong>
          <span>{safeNumber(tree.total_files)} indexed</span>
          <em className={freshness?.state === "fresh" ? "fresh" : "attention"}>{freshness?.state || "checking"}</em>
        </div>
        <form className="fileSearch" onSubmit={submitSearch}>
          <Search size={15} />
          <input value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Find indexed files..." aria-label="Find indexed files" />
          {tree.query && <button type="button" onClick={() => { setDraft(""); onSearch(""); }}>Clear</button>}
        </form>
        <button className="fileToolbarButton" onClick={onRefresh} title="Refresh file view" aria-label="Refresh file view"><RefreshCw size={15} /></button>
      </div>

      <div className="fileExplorerBody">
        <div className="fileTreePane">
          <div className="fileBreadcrumbs" aria-label="File path">
            <button onClick={() => onNavigate("")} title="Project root"><FolderTree size={14} /></button>
            {parts.map((part, index) => (
              <React.Fragment key={`${part}-${index}`}>
                <ChevronRight size={13} />
                <button onClick={() => onNavigate(parts.slice(0, index + 1).join("/"))}>{part}</button>
              </React.Fragment>
            ))}
            {tree.query && <><ChevronRight size={13} /><span>Search: {tree.query}</span></>}
          </div>
          {parts.length > 0 && !tree.query && (
            <button className="fileTreeRow parent" onClick={() => onNavigate(parts.slice(0, -1).join("/"))}>
              <ArrowLeft size={15} /><span><strong>Parent folder</strong></span>
            </button>
          )}
          <div className="fileTreeList">
            {loading && <div className="fileTreeState"><RefreshCw className="spin" size={20} /><span>Loading index...</span></div>}
            {!loading && (tree.entries || []).map((entry) => (
              <button
                key={`${entry.kind}:${entry.relative_path}`}
                className={preview?.relative_path === entry.relative_path ? "fileTreeRow active" : "fileTreeRow"}
                onClick={() => onOpen(entry)}
                title={entry.relative_path}
              >
                {entry.kind === "directory" ? <Folder size={16} /> : <FileText size={16} />}
                <span><strong>{entry.name}</strong><small>{entry.kind === "directory" ? `${safeNumber(entry.count)} files` : formatBytes(entry.size)}</small></span>
                {entry.kind === "directory" && <ChevronRight size={14} />}
              </button>
            ))}
            {!loading && !(tree.entries || []).length && <div className="fileTreeState"><Files size={20} /><span>No indexed files found</span></div>}
          </div>
          {tree.truncated && <div className="fileTreeNotice">Showing the first 500 results</div>}
        </div>

        <div className="filePreviewPane">
          {!preview && <div className="filePreviewEmpty"><FileCode2 size={28} /><strong>Indexed file preview</strong><span>{safeNumber(tree.descendant_files || tree.matched_files || tree.total_files)} files in this view</span></div>}
          {preview?.loading && <div className="filePreviewEmpty"><RefreshCw className="spin" size={24} /><strong>Loading preview</strong></div>}
          {preview && !preview.loading && (
            <>
              <div className="filePreviewHeader">
                <div><FileCode2 size={18} /><span><strong>{preview.name}</strong><small>{preview.relative_path}</small></span></div>
                <div className="filePreviewActions" aria-live="polite">
                  <button className={previewAction.kind === "task" && ["added", "existing"].includes(previewAction.status) ? "success" : ""} onClick={addPreviewToTask} disabled={previewAction.status === "working"}>
                    {previewAction.kind === "task" && ["added", "existing"].includes(previewAction.status) ? <CheckCircle2 size={14} /> : <Plus size={14} />}
                    {previewAction.kind === "task" && previewAction.status === "working" ? "Adding..." : previewAction.kind === "task" && previewAction.status === "added" ? "Added" : previewAction.kind === "task" && previewAction.status === "existing" ? "Already Added" : previewAction.kind === "task" && previewAction.status === "failed" ? "Add Failed" : "Add to Task"}
                  </button>
                  <button className={previewAction.kind === "copy" && previewAction.status === "copied" ? "success" : ""} onClick={copyPreviewPath} disabled={previewAction.status === "working"} title={previewAction.kind === "copy" && previewAction.status === "copied" ? "Relative path copied" : "Copy relative path"} aria-label={previewAction.kind === "copy" && previewAction.status === "copied" ? "Path copied" : "Copy relative path"}>
                    {previewAction.kind === "copy" && previewAction.status === "copied" ? <><CheckCircle2 size={14} /> Copied</> : previewAction.kind === "copy" && previewAction.status === "working" ? <RefreshCw className="spin" size={14} /> : previewAction.kind === "copy" && previewAction.status === "failed" ? <>Copy Failed</> : <Clipboard size={14} />}
                  </button>
                </div>
              </div>
              <div className="filePreviewMeta">
                <span>{formatBytes(preview.size)}</span>
                <span>Indexed snapshot</span>
                {preview.preview_truncated && <span>Preview limited</span>}
              </div>
              {preview.error && <div className="filePreviewError">{preview.error}</div>}
              {preview.missing && <div className="filePreviewError">This file is not available in the current index.</div>}
              {!preview.error && !preview.missing && <pre className="filePreviewCode">{preview.content || "No text preview is available for this file."}</pre>}
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function CanvasBoard({ project, graph, onSelect, onKeyboardInspect, onExport }) {
  const storageKey = `${CANVAS_STORAGE_KEY}:${project?.project || "default"}`;
  const [positions, setPositions] = useState(() => readLocalJson(storageKey, {}));
  const [focusedNodeId, setFocusedNodeId] = useState("");
  const [hoveredNodeId, setHoveredNodeId] = useState("");
  const fieldRef = useRef(null);
  const draggedNodeIdRef = useRef("");
  const cards = useMemo(() => graph.nodes.slice(0, 16), [graph.nodes]);
  const cardById = useMemo(() => new Map(cards.map((node, index) => [node.id, { node, index }])), [cards]);
  const visibleEdges = useMemo(
    () => graph.edges.filter((edge) => cardById.has(edge.source) && cardById.has(edge.target)),
    [graph.edges, cardById],
  );
  const traceNodeId = hoveredNodeId || focusedNodeId;
  const relatedNodeIds = useMemo(() => {
    const ids = new Set();
    if (!traceNodeId) return ids;
    visibleEdges.forEach((edge) => {
      if (edge.source === traceNodeId) ids.add(edge.target);
      if (edge.target === traceNodeId) ids.add(edge.source);
    });
    return ids;
  }, [traceNodeId, visibleEdges]);
  const tracedNode = cardById.get(traceNodeId)?.node;
  const tracedLinks = visibleEdges.filter((edge) => edge.source === traceNodeId || edge.target === traceNodeId).length;

  useEffect(() => {
    setPositions(readLocalJson(storageKey, {}));
    setFocusedNodeId("");
    setHoveredNodeId("");
  }, [storageKey]);

  useEffect(() => {
    setFocusedNodeId("");
    setHoveredNodeId("");
  }, [cards]);

  function positionFor(node, index) {
    return positions[node.id] || canvasDefaultSlots[index % canvasDefaultSlots.length];
  }

  function beginDrag(event, node, index) {
    if (window.matchMedia("(max-width: 560px)").matches) return;
    const field = fieldRef.current;
    if (!field) return;
    event.currentTarget.setPointerCapture?.(event.pointerId);
    const start = positionFor(node, index);
    const rect = field.getBoundingClientRect();
    const origin = { x: event.clientX, y: event.clientY };
    let moved = false;
    const move = (moveEvent) => {
      if (Math.hypot(moveEvent.clientX - origin.x, moveEvent.clientY - origin.y) > 4) moved = true;
      const next = {
        x: Math.max(1, Math.min(86, start.x + ((moveEvent.clientX - origin.x) / rect.width) * 100)),
        y: Math.max(2, Math.min(86, start.y + ((moveEvent.clientY - origin.y) / rect.height) * 100)),
      };
      setPositions((current) => ({ ...current, [node.id]: next }));
    };
    const end = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", end);
      draggedNodeIdRef.current = moved ? node.id : "";
      setPositions((current) => {
        writeLocalJson(storageKey, current);
        return current;
      });
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", end, { once: true });
  }

  function resetLayout() {
    setPositions({});
    setFocusedNodeId("");
    setHoveredNodeId("");
    try {
      localStorage.removeItem(storageKey);
    } catch {
      // Reset still applies for the current session when storage is unavailable.
    }
  }

  return (
    <section className="canvasBoard" aria-label="Spatial project canvas">
      <div className="canvasHeader">
        <span><MapIcon size={16} /> Spatial Canvas <em>{cards.length} nodes / {visibleEdges.length} links</em></span>
        <div className="canvasActions">
          <button onClick={resetLayout}><RotateCcw size={15} /> Reset Layout</button>
          <button onClick={() => onExport(`${project?.project || "rta-smriti"}-canvas.json`, { project: project?.project, positions, nodes: cards })}><Download size={15} /> Export JSON</button>
        </div>
      </div>
      <div ref={fieldRef} className={traceNodeId ? "canvasField hasTrace" : "canvasField"}>
        <svg className="canvasThread" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          <defs>
            <marker id="canvas-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 1 L 7 4 L 0 7 z" />
            </marker>
          </defs>
          {visibleEdges.map((edge) => {
            const sourceEntry = cardById.get(edge.source);
            const targetEntry = cardById.get(edge.target);
            const source = positionFor(sourceEntry.node, sourceEntry.index);
            const target = positionFor(targetEntry.node, targetEntry.index);
            const active = !traceNodeId || edge.source === traceNodeId || edge.target === traceNodeId;
            const color = sourceEntry.node.color || graphPalette[sourceEntry.node.type] || graphPalette.data;
            const path = canvasCurvePath(source, target);
            return (
              <g key={edge.id} className={active ? "canvasEdge active" : "canvasEdge muted"} style={{ "--edge-color": color }}>
                <title>{sourceEntry.node.label} {edge.label || "connects to"} {targetEntry.node.label}</title>
                <path className="canvasLinkHalo" d={path} />
                <path className="canvasLink" d={path} markerEnd="url(#canvas-arrow)" />
              </g>
            );
          })}
        </svg>
        {cards.map((node, index) => {
          const position = positionFor(node, index);
          const NodeIcon = canvasNodeIcons[node.type] || CircleDot;
          const isTraced = traceNodeId === node.id;
          const isRelated = relatedNodeIds.has(node.id);
          const linkCount = visibleEdges.filter((edge) => edge.source === node.id || edge.target === node.id).length;
          return (
            <button
              key={node.id}
              className={`canvasCard${isTraced ? " traced" : ""}${isRelated ? " related" : ""}${focusedNodeId === node.id ? " pinned" : ""}`}
              style={{ left: `${position.x}%`, top: `${position.y}%`, "--node-color": node.color || graphPalette[node.type] || graphPalette.data }}
              onPointerDown={(event) => beginDrag(event, node, index)}
              onPointerEnter={() => setHoveredNodeId(node.id)}
              onPointerLeave={() => setHoveredNodeId("")}
              onFocus={() => setHoveredNodeId(node.id)}
              onBlur={() => setHoveredNodeId("")}
              onClick={() => {
                if (draggedNodeIdRef.current === node.id) {
                  draggedNodeIdRef.current = "";
                  return;
                }
                setFocusedNodeId((current) => current === node.id ? "" : node.id);
              }}
              onDoubleClick={() => onSelect(node)}
              onKeyDown={(event) => {
                if (event.key !== "Enter") return;
                event.preventDefault();
                onKeyboardInspect(node);
              }}
              aria-pressed={focusedNodeId === node.id}
              aria-label={`${node.label}, ${node.meta}, ${linkCount} direct links`}
              title="Drag to arrange. Click to trace links. Double-click or press Enter to inspect."
            >
              <span className="canvasPort incoming" aria-hidden="true" />
              <span className="canvasNodeIcon" aria-hidden="true"><NodeIcon size={14} /></span>
              <span className="canvasNodeCopy"><strong>{node.label}</strong><small>{node.meta}</small></span>
              {linkCount > 0 && <em>{linkCount}</em>}
              <span className="canvasPort outgoing" aria-hidden="true" />
            </button>
          );
        })}
        <div className="canvasTraceStatus" aria-live="polite">
          <i style={{ background: tracedNode?.color || graphPalette[tracedNode?.type] || graphPalette.data }} />
          <strong>{tracedNode?.label || project?.project || "Project canvas"}</strong>
          <span>{tracedNode ? `${tracedLinks} direct links` : `${cards.length} visible nodes`}</span>
        </div>
        {!cards.length && <div className="emptyGraph"><MapIcon size={24} /><strong>No nodes to arrange</strong></div>}
      </div>
    </section>
  );
}

function BasesView({ memories, graph, publish, onSelect, initialTable = "memory", kindFilter = "" }) {
  const [table, setTable] = useState(initialTable);
  const [query, setQuery] = useState("");
  const baseTabs = [
    { id: "memory", label: "Memories" },
    { id: "files", label: kindFilter === "symbol" ? "Symbols" : kindFilter === "import" ? "Imports" : "Sources" },
    { id: "readiness", label: "Readiness" },
  ];
  useEffect(() => {
    setTable(initialTable);
    setQuery("");
  }, [initialTable, kindFilter]);
  const normalized = query.toLowerCase();
  const memoryRows = memories.filter((item) => `${item.type} ${item.pramana} ${item.text}`.toLowerCase().includes(normalized));
  const fileRows = graph.nodes.filter((item) => (!kindFilter || item.meta === kindFilter) && `${item.label} ${item.meta}`.toLowerCase().includes(normalized));
  function moveBaseTabFocus(event, index) {
    const directions = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    let nextIndex = index;
    if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = baseTabs.length - 1;
    else if (directions[event.key]) nextIndex = (index + directions[event.key] + baseTabs.length) % baseTabs.length;
    else return;
    event.preventDefault();
    setTable(baseTabs[nextIndex].id);
    event.currentTarget.parentElement?.querySelectorAll('[role="tab"]')[nextIndex]?.focus();
  }
  return (
    <section className="basesView" aria-label="Typed project data tables">
      <div className="basesToolbar">
        <div className="viewSwitch" role="tablist" aria-label="Project data tables">
          {baseTabs.map((entry, index) => (
            <button key={entry.id} id={`base-tab-${entry.id}`} role="tab" aria-selected={table === entry.id} aria-controls={`base-panel-${entry.id}`} tabIndex={table === entry.id ? 0 : -1} className={table === entry.id ? "active" : ""} onClick={() => setTable(entry.id)} onKeyDown={(event) => moveBaseTabFocus(event, index)}>{entry.label}</button>
          ))}
        </div>
        <label className="nodeSearch"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter this base..." aria-label="Filter current project table" /></label>
      </div>
      {table === "memory" && (
        <div id="base-panel-memory" role="tabpanel" aria-labelledby="base-tab-memory">
          <div className="baseTable" role="table" aria-label="Project memories">
            <div role="rowgroup"><div className="baseRow head" role="row"><span role="columnheader">Type</span><span role="columnheader">Evidence</span><span role="columnheader">Confidence</span><span role="columnheader">Memory</span></div></div>
            <div role="rowgroup">{memoryRows.map((item) => <div className="baseRow" role="row" key={item.id}><span role="cell">{item.type}</span><span role="cell">{item.pramana}</span><span role="cell">{Math.round(item.confidence * 100)}%</span><span role="cell">{item.text}</span></div>)}</div>
          </div>
        </div>
      )}
      {table === "files" && (
        <div id="base-panel-files" role="tabpanel" aria-labelledby="base-tab-files">
          <div className="baseTable" role="table" aria-label="Indexed project sources">
            <div role="rowgroup"><div className="baseRow head" role="row"><span role="columnheader">Name</span><span role="columnheader">Kind</span><span role="columnheader">Layer</span><span role="columnheader">Action</span></div></div>
            <div role="rowgroup">{fileRows.map((item) => <div className="baseRow" role="row" key={item.id}><span role="cell">{item.label}</span><span role="cell">{item.type}</span><span role="cell">{item.meta}</span><span role="cell"><button type="button" onClick={() => onSelect(item)} aria-label={`Inspect ${item.label}`}>Inspect</button></span></div>)}</div>
          </div>
        </div>
      )}
      {table === "readiness" && <div id="base-panel-readiness" role="tabpanel" aria-labelledby="base-tab-readiness" className="readinessGrid">{(publish?.checks || []).map((check) => <article key={check.name} className={check.ok ? "ready" : "open"}>{check.ok ? <CheckCircle2 size={18} /> : <CircleDot size={18} />}<strong>{check.name}</strong><span>{check.note || (check.ok ? "Ready" : "Open")}</span></article>)}</div>}
    </section>
  );
}

function TaskComposer({ task, setTask, project, freshness, command, packText, onGenerate, onCopy, onReceipts, onCopyContinuation, receiptCount, isGenerating, targetAgent, setTargetAgent, customAgent, setCustomAgent, contextBudget, setContextBudget, studioMode, setStudioMode, compilerMode, setCompilerMode, comparisonMode, setComparisonMode, governedCompilation, compilerInspection, onInspectCompilation }) {
  const [copyAction, setCopyAction] = useState("");
  const copyTimer = useRef(null);

  useEffect(() => () => window.clearTimeout(copyTimer.current), []);

  async function runCopyAction(kind, action) {
    if (copyAction.endsWith("-working")) return;
    window.clearTimeout(copyTimer.current);
    setCopyAction(`${kind}-working`);
    const copied = await action();
    setCopyAction(`${kind}-${copied ? "copied" : "failed"}`);
    copyTimer.current = window.setTimeout(() => setCopyAction(""), 2200);
  }

  return (
    <section className="taskComposer">
      <div className="composerTitle">
        <span>
          <Sparkles size={16} /> Context-Pack Studio
        </span>
        <div className="composerActions">
          <button type="button" onClick={onReceipts}><Eye size={15} /> {receiptCount} receipts</button>
          <button type="button" onClick={() => runCopyAction("prompt", onCopyContinuation)} disabled={copyAction.endsWith("-working")}>
            {copyAction === "prompt-copied" ? <CheckCircle2 size={15} /> : <Route size={15} />}
            {copyAction === "prompt-working" ? "Preparing..." : copyAction === "prompt-copied" ? "Prompt Copied" : copyAction === "prompt-failed" ? "Copy Failed" : "New Task Prompt"}
          </button>
          <button type="button" onClick={() => runCopyAction("command", onCopy)} disabled={copyAction.endsWith("-working")}>
            {copyAction === "command-copied" ? <CheckCircle2 size={15} /> : <Clipboard size={15} />}
            {copyAction === "command-working" ? "Copying..." : copyAction === "command-copied" ? (packText ? "Pack Copied" : "Command Copied") : copyAction === "command-failed" ? "Copy Failed" : (packText ? "Copy Pack" : "Copy Command")}
          </button>
        </div>
      </div>
      <div className="studioModeSwitch" role="group" aria-label="Context studio mode">
        <button type="button" aria-pressed={studioMode === "quick"} className={studioMode === "quick" ? "active" : ""} onClick={() => setStudioMode("quick")}>
          <Zap size={14} /> Quick Pack
        </button>
        <button type="button" aria-pressed={studioMode === "governed"} className={studioMode === "governed" ? "active" : ""} onClick={() => setStudioMode("governed")}>
          <ShieldCheck size={14} /> Governed Compiler
        </button>
        <span>{studioMode === "governed" ? "Authorized, receipted, explainable" : "Fast lexical and structural context"}</span>
      </div>
      <div className="composerGrid">
        <div className="formStack">
          <label>
            <span>Target Agent</span>
            <select value={targetAgent} onChange={(event) => setTargetAgent(event.target.value)}>
              {targetAgents.map((agent) => <option key={agent.value} value={agent.value}>{agent.label}</option>)}
            </select>
          </label>
          {targetAgent === "custom" && (
            <label>
              <span>Agent Name</span>
              <input value={customAgent} onChange={(event) => setCustomAgent(event.target.value)} placeholder="Your agent or workflow" />
            </label>
          )}
          <label>
            <span>Context Budget</span>
            <select value={contextBudget} onChange={(event) => setContextBudget(Number(event.target.value))}>
              <option value={2000}>Compact / 2K tokens</option>
              <option value={4000}>Balanced / 4K tokens</option>
              <option value={8000}>Deep / 8K tokens</option>
              <option value={16000}>Extended / 16K tokens</option>
            </select>
          </label>
          {studioMode === "governed" && (
            <>
              <label>
                <span>Compiler Mode</span>
                <select value={compilerMode} onChange={(event) => {
                  const next = event.target.value;
                  setCompilerMode(next);
                  if (comparisonMode === next) setComparisonMode("");
                }}>
                  <option value="minimal">Minimal</option>
                  <option value="balanced">Balanced</option>
                  <option value="investigative">Investigative</option>
                  <option value="handoff">Handoff</option>
                </select>
              </label>
              <label>
                <span>Compare With</span>
                <select value={comparisonMode} onChange={(event) => setComparisonMode(event.target.value)}>
                  <option value="">No comparison</option>
                  {["minimal", "balanced", "investigative", "handoff"].filter((mode) => mode !== compilerMode).map((mode) => (
                    <option key={mode} value={mode}>{mode[0].toUpperCase() + mode.slice(1)}</option>
                  ))}
                </select>
              </label>
            </>
          )}
          <label>
            <span>Objective</span>
            <textarea rows="3" value={task} onChange={(event) => setTask(event.target.value)} />
          </label>
          <label>
            <span>{studioMode === "governed" ? "Trust Boundary" : "Command Bridge"}</span>
            <code>{studioMode === "governed" ? "Local authority key / operator contract / agent-safe pack" : command}</code>
          </label>
        </div>
        <div className={studioMode === "governed" ? "packPreview governedPreview" : "packPreview"}>
          <div className="freshRing">
            <strong>{studioMode === "governed" && governedCompilation ? "✓" : freshness?.state === "fresh" ? "OK" : freshness?.state === "stale" ? "!" : "?"}</strong>
            <span>{studioMode === "governed" && governedCompilation ? "receipted" : freshness?.state || "Checking"}</span>
          </div>
          <div>
            <p>{studioMode === "governed" ? "Mode" : "Files"}</p>
            <strong>{studioMode === "governed" ? governedCompilation?.context_pack?.compiler_mode || compilerMode : safeNumber(project?.sources)}</strong>
          </div>
          <div>
            <p>{studioMode === "governed" ? "Variants" : "Memories"}</p>
            <strong>{studioMode === "governed" ? governedCompilation?.available_variants?.length || (comparisonMode ? 2 : 1) : safeNumber(project?.memories)}</strong>
          </div>
          <button className="generateButton" onClick={onGenerate} disabled={isGenerating}>
            {studioMode === "governed" ? <ShieldCheck size={18} /> : <Zap size={18} />}
            {isGenerating ? "Generating..." : studioMode === "governed" ? "Authorize & Compile" : "Generate Context Pack"}
          </button>
          {studioMode === "governed" && governedCompilation && (
            <div className="compilerReceiptSummary">
              <div>
                <span>Receipt</span>
                <code>{governedCompilation.compilation_receipt?.compilation_id}</code>
              </div>
              <div className="compilerReceiptActions">
                <button type="button" onClick={() => onInspectCompilation("explain")}><Eye size={14} /> Explain</button>
                <button type="button" onClick={() => onInspectCompilation("audit")}><KeyRound size={14} /> Audit</button>
              </div>
              {compilerInspection && (
                <p>
                  {compilerInspection.action === "audit" ? "Audit verified" : "Explanation verified"}
                  {" · "}{compilerInspection.payload.selection?.included_count ?? compilerInspection.payload.candidate_receipts?.length ?? 0} included receipts
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function EvidenceInspector({ node, memories, project, freshness, packText, onCopy, onBootstrap, onRefresh, isRefreshing }) {
  return (
    <div className="drawerContent">
      <h2>Evidence Inspector</h2>
      <section className="selectedNode">
        <BrainCircuit size={36} />
        <div>
          <p>Selected Node</p>
          <strong>{node?.label || "Project Brain"}</strong>
          <span>{node?.meta || project?.project}</span>
        </div>
      </section>
      <section>
        <div className="sectionHeader">
          <span>Must-Know Memories</span>
          <em>{memories.length}</em>
        </div>
        <div className="memoryList">
          {memories.slice(0, 5).map((memory) => (
            <article key={memory.id}>
              <CheckCircle2 size={15} />
              <p>{memory.text}</p>
              <strong>{Math.round(memory.confidence * 100)}%</strong>
            </article>
          ))}
        </div>
      </section>
      <FreshnessBars freshness={freshness} onRefresh={onRefresh} isRefreshing={isRefreshing} />
      <RepoTree project={project} />
      <section className="publishMini">
        <div>
          <span>Project Actions</span>
        </div>
        <button onClick={onCopy}>
          <Clipboard size={16} /> {packText ? "Copy Context" : "Copy Command"}
        </button>
        <button className="amberButton" onClick={onBootstrap}>
          <Rocket size={16} /> Bootstrap Checklist
        </button>
      </section>
    </div>
  );
}

function ReferencesPanel({ node, references, history, onSelect, onBack, onStart }) {
  const path = [...history, node].filter(Boolean);
  return (
    <div className="drawerContent">
      <div className="referenceHeader">
        <h2>References & Backlinks</h2>
        <div className="referenceNavigation" aria-label="Reference navigation">
          <button type="button" onClick={onBack} disabled={!history.length} title={history.length ? `Back to ${history.at(-1).label}` : "No previous reference"}>
            <ArrowLeft size={14} /> Back
          </button>
          <button type="button" onClick={onStart} disabled={!history.length} title={history.length ? `Return to ${history[0].label}` : "Already at reference start"}>
            <RotateCcw size={14} /> Start
          </button>
        </div>
      </div>
      <nav className="referenceTrail" aria-label="Reference trail">
        {path.slice(-4).map((item, index, visiblePath) => (
          <React.Fragment key={`${item.id}-${index}`}>
            <span className={index === visiblePath.length - 1 ? "active" : ""}>{item.label}</span>
            {index < visiblePath.length - 1 && <ChevronRight size={11} />}
          </React.Fragment>
        ))}
      </nav>
      <section className="selectedNode compact">
        <GitBranch size={28} />
        <div><p>Connected to</p><strong>{node?.label || "Project Brain"}</strong><span>{references.length} references</span></div>
      </section>
      <div className="referenceList">
        {references.map((reference) => (
          <button
            key={reference.id}
            onClick={() => onSelect(reference)}
            aria-label={`${reference.label}, ${reference.relation}`}
          >
            <i style={{ background: graphPalette[reference.type] || graphPalette.data }} />
            <span><strong>{reference.label}</strong><em>{reference.relation}</em></span>
            <ChevronRight size={15} />
          </button>
        ))}
        {!references.length && <p className="emptyText">No visible backlinks for this node. Increase graph depth or switch to Global.</p>}
      </div>
    </div>
  );
}

function FreshnessBars({ freshness, onRefresh, isRefreshing }) {
  const total = Math.max(1, (freshness?.fresh || 0) + (freshness?.changed || 0) + (freshness?.missing || 0) + (freshness?.added || 0) + (freshness?.uninspectable || 0));
  const bars = [
    ["Fresh", freshness?.fresh || 0],
    ["Changed", freshness?.changed || 0],
    ["Missing", freshness?.missing || 0],
    ["Added", freshness?.added || 0],
    ["Blocked", freshness?.uninspectable || 0],
  ];
  return (
    <section>
      <div className="sectionHeader">
        <span>Freshness</span>
        <button className="freshnessAction" onClick={onRefresh} disabled={isRefreshing} title="Refresh repository index">
          <RefreshCw size={13} /> {isRefreshing ? "Indexing" : freshness?.state || "Checking"}
        </button>
      </div>
      <div className="bars">
        {bars.map(([label, count]) => (
          <div key={label}>
            <span>{label}</span>
            <i>
              <b style={{ width: `${Math.round((count / total) * 100)}%` }} />
            </i>
            <em>{count}</em>
          </div>
        ))}
      </div>
    </section>
  );
}

function RepoTree({ project }) {
  const root = project?.root_path || "memory-only";
  const git = project?.git || {};
  return (
    <section>
      <div className="sectionHeader">
        <span>Repo Tree</span>
        <em>{project?.project}</em>
      </div>
      <div className="repoTree">
        <p title={root}>
          <FolderTree size={15} /> {root.split(/[\\/]/).pop() || root}
        </p>
        {git.is_git_repo && (
          <>
            <p title={git.repository_root}><GitBranch size={15} /> {git.branch} @ {git.head || "unborn"}</p>
            <p className={git.dirty_files ? "repoDirty" : "repoClean"}><CircleDot size={15} /> {git.dirty_files} dirty files</p>
          </>
        )}
        {project?.root_conflict && <p className="repoConflict"><ShieldCheck size={15} /> duplicate project roots</p>}
        <p>
          <Files size={15} /> source files
        </p>
        <p>
          <FileCode2 size={15} /> symbols and imports
        </p>
        <p>
          <Code2 size={15} /> AGENTS.md bridge
        </p>
      </div>
    </section>
  );
}

function CheckpointPanel({ checkpoint, readiness, project, onSave, onCopy, isSaving }) {
  const [values, setValues] = useState({
    objective: "",
    verified_evidence: "",
    remaining_gaps: "",
    next_action: "",
    prohibited_repetition: "",
  });

  useEffect(() => {
    setValues({
      objective: checkpoint?.objective || "",
      verified_evidence: checkpoint?.verified_evidence || "",
      remaining_gaps: checkpoint?.remaining_gaps || "",
      next_action: checkpoint?.next_action || "",
      prohibited_repetition: checkpoint?.prohibited_repetition || "",
    });
  }, [checkpoint?.id]);

  const update = (key, value) => setValues((current) => ({ ...current, [key]: value }));
  const git = project?.git || {};
  return (
    <div className="drawerContent checkpointPanel">
      <div className="sectionHeader">
        <h2>Continue Work</h2>
        {checkpoint?.updated_at && <time>v{checkpoint.version} / {new Date(checkpoint.updated_at).toLocaleString()}</time>}
      </div>
      <div className={project?.root_conflict ? "checkpointIdentity conflict" : "checkpointIdentity"}>
        <strong>{project?.project || "Select a project"}</strong>
        <span title={project?.root_path}>{displayPath(project?.root_path)}</span>
        {project?.repository_identity && <small title={project.repository_identity}>Identity: {project.repository_identity.slice(0, 18)}...</small>}
        {git.is_git_repo && <small>{git.branch} @ {git.head || "unborn"} / {git.dirty_files} dirty</small>}
      </div>
      {checkpoint?.source === "continuity-daemon" && (
        <div className="automaticCheckpointNotice" role="status">
          <ShieldCheck size={16} />
          <span><strong>Automatically captured</strong><small>{checkpoint.trigger?.replaceAll("_", " ")} / evidence remains unverified until reviewed</small></span>
        </div>
      )}
      {readiness?.reasons?.includes("continuity_history_truncated") && (
        <div className="automaticCheckpointNotice readinessWarning" role="alert">
          <CircleDot size={16} />
          <span><strong>Manual review required</strong><small>Older transcript history was omitted by the configured capture bound. Review the retained events and source evidence, then save a manual checkpoint.</small></span>
        </div>
      )}
      <label><span>Objective</span><textarea rows="2" value={values.objective} onChange={(event) => update("objective", event.target.value)} /></label>
      <label><span>Verified Evidence</span><textarea rows="3" value={values.verified_evidence} onChange={(event) => update("verified_evidence", event.target.value)} /></label>
      <label><span>Remaining Gaps</span><textarea rows="2" value={values.remaining_gaps} onChange={(event) => update("remaining_gaps", event.target.value)} /></label>
      <label><span>Next Action</span><textarea rows="2" value={values.next_action} onChange={(event) => update("next_action", event.target.value)} /></label>
      <label><span>Do Not Repeat</span><textarea rows="2" value={values.prohibited_repetition} onChange={(event) => update("prohibited_repetition", event.target.value)} /></label>
      <div className="checkpointActions">
        <button className="primarySmall" onClick={() => onSave(values)} disabled={isSaving || !values.objective.trim()}>
          <CheckCircle2 size={16} /> {isSaving ? "Saving..." : "Save Checkpoint"}
        </button>
        <button onClick={onCopy}><Clipboard size={16} /> Copy New Task Prompt</button>
      </div>
    </div>
  );
}

function IntelligencePanel({ project, projects, task, data, busy, onDiagnose, onGraphQuery, onCreateWorkspace, onAddMember, onRemoveMember, onDeleteWorkspace, onNotify }) {
  const [tab, setTab] = useState("retrieval");
  const [query, setQuery] = useState(task);
  const [target, setTarget] = useState("");
  const [queryType, setQueryType] = useState("impact");
  const [workspaceName, setWorkspaceName] = useState("");
  const [selectedWorkspace, setSelectedWorkspace] = useState("");
  const [memberKey, setMemberKey] = useState("");
  const [workspaceQuery, setWorkspaceQuery] = useState("");
  const [workspaceResults, setWorkspaceResults] = useState([]);
  const [workspaceStatus, setWorkspaceStatus] = useState("");
  const [workspaceDetail, setWorkspaceDetail] = useState(null);
  const [workspaceHealth, setWorkspaceHealth] = useState(null);
  const [bundlePath, setBundlePath] = useState("");
  const [snapshotPath, setSnapshotPath] = useState("");
  const [snapshotKeyPath, setSnapshotKeyPath] = useState("");
  const [snapshotMode, setSnapshotMode] = useState("encrypted");
  const [snapshotRestorePath, setSnapshotRestorePath] = useState("");
  const [mcpStatus, setMcpStatus] = useState(null);
  const [bundleConflict, setBundleConflict] = useState("rename");
  const [bundleSections, setBundleSections] = useState({ memories: true, checkpoints: true, policies: true });
  const [bundlePreview, setBundlePreview] = useState(null);
  const [portabilityStatus, setPortabilityStatus] = useState("");
  const [portabilityBusy, setPortabilityBusy] = useState(false);

  useEffect(() => setQuery(task), [task]);
  useEffect(() => {
    if (!selectedWorkspace && data.workspaces?.length) setSelectedWorkspace(data.workspaces[0].name);
  }, [data.workspaces, selectedWorkspace]);
  useEffect(() => {
    const base = String(project?.db_path || "brain.sqlite").replace(/\.sqlite$/i, "");
    setBundlePath(`${base}.memory.rta.json`);
    setSnapshotPath(`${base}.encrypted.rtae`);
    setSnapshotKeyPath(`${base}.snapshot.passphrase`);
    setSnapshotRestorePath(`${base}.restored.sqlite`);
    setBundlePreview(null);
    setPortabilityStatus("");
  }, [project?.db_path]);

  const selectedMember = projects.find((item) => `${item.db_path}:${item.project}` === memberKey);
  const diagnostics = data.diagnostics;
  const graphResult = data.graph;
  const tabs = [
    { id: "retrieval", label: "Retrieval", icon: Gauge },
    { id: "impact", label: "Impact", icon: Network },
    { id: "workspaces", label: "Workspaces", icon: Boxes },
    { id: "agent", label: "Agent Link", icon: Cable },
    { id: "portability", label: "Vault", icon: HardDrive },
  ];

  useEffect(() => {
    let cancelled = false;
    async function loadWorkspaceDetail() {
      if (!project || !selectedWorkspace) {
        setWorkspaceDetail(null);
        setWorkspaceHealth(null);
        return;
      }
      try {
        const params = { db_path: project.db_path, project: project.project, workspace: selectedWorkspace };
        const [detail, health] = await Promise.all([
          api(`/api/workspaces?${qs(params)}`),
          api(`/api/workspace-health?${qs(params)}`),
        ]);
        if (!cancelled) {
          setWorkspaceDetail(detail);
          setWorkspaceHealth(health);
        }
      } catch (error) {
        if (!cancelled) setWorkspaceStatus(error.message);
      }
    }
    loadWorkspaceDetail();
    return () => { cancelled = true; };
  }, [project?.db_path, project?.project, selectedWorkspace, data.workspaces]);

  function moveTabFocus(event, index) {
    const keys = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
    let nextIndex = index;
    if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = tabs.length - 1;
    else if (keys[event.key]) nextIndex = (index + keys[event.key] + tabs.length) % tabs.length;
    else return;
    event.preventDefault();
    setTab(tabs[nextIndex].id);
    event.currentTarget.parentElement?.querySelectorAll('[role="tab"]')[nextIndex]?.focus();
  }

  async function searchSelectedWorkspace() {
    if (!project || !selectedWorkspace || !workspaceQuery.trim()) return;
    try {
      setWorkspaceStatus("Searching workspace...");
      const payload = await api(`/api/workspace-search?${qs({
        db_path: project.db_path, project: project.project, workspace: selectedWorkspace,
        query: workspaceQuery.trim(), limit: 4,
      })}`);
      setWorkspaceResults(payload.results || []);
      const failed = payload.errors?.length || 0;
      setWorkspaceStatus(`${payload.results?.length || 0} project brains searched${failed ? `; ${failed} unavailable` : ""}.`);
    } catch (error) {
      setWorkspaceResults([]);
      setWorkspaceStatus(error.message);
    }
  }

  async function runBundle(action) {
    if (!project || !bundlePath.trim()) return;
    const selected = Object.entries(bundleSections).filter(([, enabled]) => enabled).map(([name]) => name);
    if ((action === "export" || action === "preview-export") && !selected.length) {
      setPortabilityStatus("Select at least one bundle section.");
      return;
    }
    try {
      setPortabilityBusy(true);
      setPortabilityStatus(action.startsWith("preview") ? "Inspecting bundle..." : "Applying verified bundle operation...");
      const payload = await api("/api/bundle", {
        method: "POST",
        body: JSON.stringify({
          db_path: project.db_path,
          project: project.project,
          action,
          path: bundlePath.trim(),
          projects: [project.project],
          include: selected,
          redact: true,
          conflict: bundleConflict,
        }),
      });
      if (action.startsWith("preview")) {
        setBundlePreview({ ...payload, operation: action });
        setPortabilityStatus(`Preview ready: ${payload.counts?.memories || 0} memories, ${payload.counts?.checkpoints || 0} checkpoints, ${payload.counts?.policies || 0} policies.`);
      } else {
        setBundlePreview(null);
        setPortabilityStatus(action === "export" ? "Redacted selective bundle written." : "Verified bundle imported through staging.");
      }
      onNotify?.(action.startsWith("preview") ? "Portability preview completed." : "Portability operation completed.");
    } catch (error) {
      setBundlePreview(null);
      setPortabilityStatus(error.message);
      onNotify?.(`Portability check failed: ${error.message}`);
    } finally {
      setPortabilityBusy(false);
    }
  }

  async function runSnapshot(action) {
    if (!project || !snapshotPath.trim() || !snapshotKeyPath.trim()) return;
    try {
      setPortabilityBusy(true);
      const payload = await api("/api/snapshot", {
        method: "POST",
        body: JSON.stringify({
          db_path: project.db_path,
          project: project.project,
          action: snapshotMode === "encrypted" ? ({ create: "encrypt", verify: "verify-encrypted", restore: "restore" }[action]) : action,
          path: snapshotPath.trim(),
          ...(snapshotMode === "encrypted"
            ? { passphrase_path: snapshotKeyPath.trim(), output_db: snapshotRestorePath.trim() }
            : { key_path: snapshotKeyPath.trim() }),
        }),
      });
      setPortabilityStatus(
        action === "create"
          ? (snapshotMode === "encrypted" ? "Encrypted private snapshot created." : "Authenticated private snapshot created.")
          : action === "restore"
            ? (payload.valid ? `Verified brain restored to ${payload.path}.` : `Restore blocked: ${payload.reason}`)
            : payload.valid ? "Snapshot authentication and database integrity verified." : `Snapshot invalid: ${payload.reason}`,
      );
    } catch (error) {
      setPortabilityStatus(error.message);
    } finally {
      setPortabilityBusy(false);
    }
  }

  async function generateSnapshotPassphrase() {
    if (!snapshotKeyPath.trim()) return;
    try {
      setPortabilityBusy(true);
      const payload = await api("/api/snapshot", {
        method: "POST",
        body: JSON.stringify({ action: "passphrase-keygen", path: snapshotKeyPath.trim() }),
      });
      setPortabilityStatus(`Private 256-bit snapshot key created at ${payload.path}. Keep it separate from the snapshot.`);
    } catch (error) {
      setPortabilityStatus(error.message);
    } finally {
      setPortabilityBusy(false);
    }
  }

  async function probeMcp() {
    if (!project) return;
    try {
      setPortabilityBusy(true);
      setMcpStatus(null);
      const payload = await api("/api/mcp-doctor", {
        method: "POST",
        body: JSON.stringify({ db_path: project.db_path, project: project.project, timeout: 10 }),
      });
      setMcpStatus(payload);
      onNotify?.(payload.ready ? `MCP probe passed with ${payload.tool_count} tools.` : `MCP probe blocked: ${payload.reason}`);
    } catch (error) {
      setMcpStatus({ status: "blocked", ready: false, reason: error.message });
    } finally {
      setPortabilityBusy(false);
    }
  }

  async function copyMcpConfig() {
    if (!mcpStatus?.config) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(mcpStatus.config, null, 2));
      onNotify?.("MCP host configuration copied.");
    } catch (error) {
      onNotify?.(`Could not copy MCP configuration: ${error.message}`);
    }
  }

  async function runLocalControl(path, payload, success) {
    if (!project) return;
    try {
      setPortabilityBusy(true);
      const result = await api(path, {
        method: "POST",
        body: JSON.stringify({ db_path: project.db_path, project: project.project, ...payload }),
      });
      setPortabilityStatus(typeof success === "function" ? success(result) : success);
    } catch (error) {
      setPortabilityStatus(error.message);
    } finally {
      setPortabilityBusy(false);
    }
  }

  return (
    <div className="drawerContent intelligencePanel">
      <div className="sectionHeader"><h2>Project Intelligence</h2><em>{project?.project || "No project"}</em></div>
      <div className="intelligenceTabs" role="tablist" aria-label="Project intelligence views">
        {tabs.map(({ id, label, icon: TabIcon }, index) => (
          <button
            key={id}
            id={`intelligence-tab-${id}`}
            role="tab"
            type="button"
            aria-selected={tab === id}
            aria-controls={`intelligence-panel-${id}`}
            tabIndex={tab === id ? 0 : -1}
            className={tab === id ? "active" : ""}
            onClick={() => setTab(id)}
            onKeyDown={(event) => moveTabFocus(event, index)}
          >
            <TabIcon size={14} /> {label}
          </button>
        ))}
      </div>

      {tab === "retrieval" && (
        <section id="intelligence-panel-retrieval" role="tabpanel" aria-labelledby="intelligence-tab-retrieval" className="intelligenceSection">
          <label><span>Question to explain</span><textarea rows={3} value={query} onChange={(event) => setQuery(event.target.value)} /></label>
          <button className="primarySmall" onClick={() => onDiagnose(query)} disabled={busy || !query.trim()}><Search size={15} /> Explain retrieval</button>
          {diagnostics && (
            <>
              <div className="metricStrip">
                <article><span>Mode</span><strong>{diagnostics.retrieval?.mode}</strong></article>
                <article><span>Coverage</span><strong>{Math.round((diagnostics.index?.embedding_coverage || 0) * 100)}%</strong></article>
                <article><span>Latency</span><strong>{diagnostics.latency_ms} ms</strong></article>
              </div>
              <div className="diagnosticResults">
                {diagnostics.results?.map((item, index) => (
                  <article key={`${item.path}-${index}`}>
                    <div><strong>{item.path}</strong><em>#{item.ranking.position}</em></div>
                    <span>lex {Number(item.ranking.lexical_score || 0).toFixed(3)} / sem {Number(item.ranking.semantic_score || 0).toFixed(3)} / hybrid {Number(item.ranking.hybrid_score || 0).toFixed(3)}</span>
                    <div className="selectionReasons" aria-label={`Why ${item.path} was selected`}>
                      {(item.selection_reasons || []).slice(0, 3).map((reason) => <b key={reason}>{reason}</b>)}
                    </div>
                    <small title={item.evidence.source_hash}>{item.evidence.verification_status}</small>
                  </article>
                ))}
              </div>
            </>
          )}
        </section>
      )}

      {tab === "impact" && (
        <section id="intelligence-panel-impact" role="tabpanel" aria-labelledby="intelligence-tab-impact" className="intelligenceSection">
          <label><span>Symbol or file</span><input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="helper or src/service.py" /></label>
          <label><span>Question</span><select value={queryType} onChange={(event) => setQueryType(event.target.value)}><option value="impact">Change impact</option><option value="dependents">What depends on this?</option><option value="dependencies">What does this depend on?</option><option value="evidence">Supporting evidence</option><option value="relevance">Related knowledge</option></select></label>
          <button className="primarySmall" onClick={() => onGraphQuery(target, queryType)} disabled={busy || !target.trim()}><Network size={15} /> Trace relationships</button>
          {graphResult && (
            <div className="impactResults">
              <p><strong>{graphResult.nodes.length}</strong> nodes, <strong>{graphResult.edges.length}</strong> relationships{graphResult.truncated ? " (bounded result)" : ""}</p>
              {graphResult.edges.slice(0, 12).map((edge) => <article key={edge.id}><span>{edge.from_name}</span><em>{edge.relation}</em><span>{edge.to_name}</span><small>{Math.round(edge.confidence * 100)}%</small></article>)}
            </div>
          )}
        </section>
      )}

      {tab === "workspaces" && (
        <section id="intelligence-panel-workspaces" role="tabpanel" aria-labelledby="intelligence-tab-workspaces" className="intelligenceSection">
          <p className="drawerIntro">Group independently indexed brains for cross-repository recall without merging their roots or databases.</p>
          <div className="workspaceList">
            {data.workspaces?.map((workspace) => <button key={workspace.id} className={selectedWorkspace === workspace.name ? "active" : ""} onClick={() => setSelectedWorkspace(workspace.name)}><span>{workspace.name}</span><em>{workspace.project_count}</em></button>)}
            {!data.workspaces?.length && <p className="emptyState">No workspaces in this brain yet.</p>}
          </div>
          {selectedWorkspace && workspaceHealth && (
            <div className={`workspaceHealth ${workspaceHealth.status}`}>
              <span>{workspaceHealth.status === "ok" ? "All members available" : "Workspace degraded"}</span>
              <em>{workspaceHealth.summary.healthy}/{workspaceHealth.summary.total} healthy</em>
            </div>
          )}
          {workspaceDetail?.projects?.length > 0 && (
            <div className="workspaceMembers" aria-label="Workspace members">
              {workspaceDetail.projects.map((member) => {
                const health = workspaceHealth?.members?.find((item) => item.project === member.project);
                return <div key={`${member.db_path}:${member.project}`}><span className={health?.available && health?.project_present ? "healthy" : "unavailable"} /> <strong>{member.project}</strong><em>{member.role}</em><button title={`Remove ${member.project}`} aria-label={`Remove ${member.project}`} onClick={async () => { const result = await onRemoveMember({ name: selectedWorkspace, project: member.project, member_db_path: member.db_path }); if (result) setWorkspaceDetail(result); }} disabled={busy}><Trash2 size={14} /></button></div>;
              })}
            </div>
          )}
          <div className="workspaceAction">
            <input value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} placeholder="Workspace name" aria-label="New workspace name" />
            <button onClick={async () => { const result = await onCreateWorkspace({ name: workspaceName.trim() }); if (result) { setSelectedWorkspace(workspaceName.trim()); setWorkspaceName(""); } }} disabled={busy || !workspaceName.trim()}><Plus size={14} /> Create</button>
          </div>
          <label><span>Member brain</span><select value={memberKey} onChange={(event) => setMemberKey(event.target.value)}><option value="">Choose a project</option>{projects.map((item) => <option key={`${item.db_path}:${item.project}`} value={`${item.db_path}:${item.project}`}>{item.project}</option>)}</select></label>
          <button className="primarySmall" onClick={() => onAddMember({ name: selectedWorkspace, project: selectedMember.project, member_db_path: selectedMember.db_path, role: "member" })} disabled={busy || !selectedWorkspace || !selectedMember}><Plus size={15} /> Add to workspace</button>
          <button className="dangerSmall" onClick={async () => { if (window.confirm(`Delete workspace ${selectedWorkspace}? Project brains will not be deleted.`)) { const result = await onDeleteWorkspace(selectedWorkspace); if (result) { setSelectedWorkspace(""); setWorkspaceDetail(null); setWorkspaceHealth(null); } } }} disabled={busy || !selectedWorkspace}><Trash2 size={14} /> Delete workspace</button>
          <div className="workspaceAction">
            <input value={workspaceQuery} onChange={(event) => setWorkspaceQuery(event.target.value)} placeholder="Search every member brain" aria-label="Search workspace brains" />
            <button onClick={searchSelectedWorkspace} disabled={!selectedWorkspace || !workspaceQuery.trim()}><Search size={14} /> Search</button>
          </div>
          {workspaceStatus && <p className="workspaceStatus" aria-live="polite">{workspaceStatus}</p>}
          <div className="workspaceResults">
            {workspaceResults.map((result) => (
              <article key={result.project}>
                <div><strong>{result.project}</strong><em>{result.retrieval?.mode}</em></div>
                {[...(result.memories || []), ...(result.chunks || [])].slice(0, 3).map((item, index) => (
                  <p key={`${item.id}-${index}`}><span>{item.path || item.type || "memory"}</span>{item.text}</p>
                ))}
              </article>
            ))}
          </div>
        </section>
      )}

      {tab === "agent" && (
        <section id="intelligence-panel-agent" role="tabpanel" aria-labelledby="intelligence-tab-agent" className="intelligenceSection">
          <p className="drawerIntro">Probe the exact local MCP server before registering it with Codex or another MCP-capable agent.</p>
          <button className="primarySmall" onClick={probeMcp} disabled={portabilityBusy || !project}><Cable size={15} /> Test MCP connection</button>
          {mcpStatus && <div className={`mcpReceipt ${mcpStatus.ready ? "ready" : "blocked"}`}>
            <div><strong>{mcpStatus.ready ? "Connection ready" : "Connection blocked"}</strong><em>{mcpStatus.ready ? `${mcpStatus.tool_count} tools / ${mcpStatus.latency_ms} ms` : mcpStatus.reason}</em></div>
            {mcpStatus.ready && <><p>The generated server passed initialize, tools/list, and ping. Register this config in the agent host, then start a fresh task so the tools appear.</p><button onClick={copyMcpConfig}><Clipboard size={14} /> Copy host config</button></>}
          </div>}
        </section>
      )}

      {tab === "portability" && (
        <section id="intelligence-panel-portability" role="tabpanel" aria-labelledby="intelligence-tab-portability" className="intelligenceSection portabilityPanel">
          <p className="drawerIntro">Move selected memory without source code, authenticate a private brain copy, or opt into local lifecycle controls.</p>
          <h3>Selective bundle</h3>
          <label><span>Bundle path</span><input value={bundlePath} onChange={(event) => { setBundlePath(event.target.value); setBundlePreview(null); }} /></label>
          <div className="bundleChecks">
            {Object.keys(bundleSections).map((section) => <label key={section}><input type="checkbox" checked={bundleSections[section]} onChange={(event) => { setBundleSections({ ...bundleSections, [section]: event.target.checked }); setBundlePreview(null); }} /><span>{section}</span></label>)}
          </div>
          <label><span>Import conflict</span><select value={bundleConflict} onChange={(event) => { setBundleConflict(event.target.value); setBundlePreview(null); }}><option value="rename">Rename incoming project</option><option value="merge">Merge by project name</option><option value="fail">Fail on conflict</option></select></label>
          <div className="portabilityActions">
            <button onClick={() => runBundle("preview-export")} disabled={portabilityBusy}><Eye size={14} /> Preview export</button>
            <button onClick={() => runBundle("export")} disabled={portabilityBusy || bundlePreview?.operation !== "preview-export"}><Download size={14} /> Export</button>
            <button onClick={() => runBundle("preview-import")} disabled={portabilityBusy}><Eye size={14} /> Preview import</button>
            <button onClick={() => runBundle("import")} disabled={portabilityBusy || bundlePreview?.operation !== "preview-import"}><Database size={14} /> Import</button>
          </div>
          {bundlePreview && <div className="portabilityReceipt"><strong>SHA-256 {bundlePreview.sha256?.slice(0, 12)}...</strong><span>{bundlePreview.redacted ? "Redaction verified" : "Unredacted"} / {bundlePreview.conflicts?.length || 0} conflicts</span>{bundlePreview.warnings?.map((warning) => <small key={warning}>{warning}</small>)}</div>}

          <h3>Private brain snapshot</h3>
          <label><span>Protection</span><select value={snapshotMode} onChange={(event) => setSnapshotMode(event.target.value)}><option value="encrypted">Encrypted (recommended)</option><option value="authenticated">HMAC authentication</option></select></label>
          <label><span>Snapshot path</span><input value={snapshotPath} onChange={(event) => setSnapshotPath(event.target.value)} /></label>
          <label><span>{snapshotMode === "encrypted" ? "Passphrase file" : "Separate HMAC key"}</span><input value={snapshotKeyPath} onChange={(event) => setSnapshotKeyPath(event.target.value)} /></label>
          {snapshotMode === "encrypted" && <button className="inlineAction" onClick={generateSnapshotPassphrase} disabled={portabilityBusy || !snapshotKeyPath.trim()}><KeyRound size={14} /> Generate private key file</button>}
          {snapshotMode === "encrypted" && <label><span>Restore as new brain</span><input value={snapshotRestorePath} onChange={(event) => setSnapshotRestorePath(event.target.value)} /></label>}
          <div className="portabilityActions">
            <button onClick={() => runSnapshot("create")} disabled={portabilityBusy}><HardDrive size={14} /> Create</button>
            <button onClick={() => runSnapshot("verify")} disabled={portabilityBusy}><ShieldCheck size={14} /> Verify</button>
            {snapshotMode === "encrypted" && <button onClick={() => runSnapshot("restore")} disabled={portabilityBusy || !snapshotRestorePath.trim()}><Database size={14} /> Restore</button>}
          </div>
          <p className="trustNote">{snapshotMode === "encrypted" ? "AES-256-GCM protects the complete local brain. Keep the passphrase file separate from the snapshot." : "HMAC detects changes but does not encrypt the snapshot. Use only for compatible private workflows."}</p>

          <h3>Local controls</h3>
          <div className="portabilityActions">
            <button onClick={() => runLocalControl("/api/git-hooks", { action: "install" }, "Managed post-commit checkpoint hook installed at the canonical root.")} disabled={portabilityBusy}><GitBranch size={14} /> Hook on</button>
            <button onClick={() => runLocalControl("/api/git-hooks", { action: "uninstall" }, "Managed post-commit checkpoint hook removed.")} disabled={portabilityBusy}><GitBranch size={14} /> Hook off</button>
            <button onClick={() => runLocalControl("/api/memory-decay", { minimum_age_days: 90, step: 0.03 }, (result) => `${result.decayed} eligible memories conservatively aged; ${result.protected_verified} verified records protected.`)} disabled={portabilityBusy}><MemoryStick size={14} /> Run decay</button>
          </div>
          {portabilityStatus && <p className="workspaceStatus" aria-live="polite">{portabilityStatus}</p>}
        </section>
      )}
    </div>
  );
}

function MemoryLedger({ memories, onReflect, onFeedback }) {
  const [filter, setFilter] = useState("all");
  const types = ["all", ...new Set(memories.map((memory) => memory.type).filter(Boolean))];
  const visible = filter === "all" ? memories : memories.filter((memory) => memory.type === filter);
  return (
    <div className="drawerContent">
      <h2>Memory Ledger</h2>
      <button className="primarySmall" onClick={onReflect}>
        <RefreshCw size={16} /> Reflect Memories
      </button>
      <div className="ledgerFilters">
        {types.slice(0, 6).map((type) => <button key={type} className={filter === type ? "active" : ""} onClick={() => setFilter(type)}>{type}</button>)}
      </div>
      <div className="ledgerList">
        {visible.map((memory) => (
          <article key={memory.id}>
            <span>{memory.pramana}</span>
            <strong>{memory.type}</strong>
            <p>{memory.text}</p>
            {memory.provenance && (
              <small className={`provenance ${memory.provenance.verification_status}`}>
                {memory.provenance.verification_status} / {memory.provenance.source_path || "source not recorded"}
              </small>
            )}
            <div className="memoryFeedback" aria-label={`Feedback for memory ${memory.id}`}>
              <button title="This memory helped" aria-label="Mark helpful" onClick={() => onFeedback(memory.id, "helpful")}><ThumbsUp size={13} /></button>
              <button title="This memory was harmful or misleading" aria-label="Mark harmful" onClick={() => onFeedback(memory.id, "harmful")}><ThumbsDown size={13} /></button>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

function ReceiptsPanel({ receipts, onCopy, onClear }) {
  return (
    <div className="drawerContent">
      <div className="sectionHeader"><h2>Context-Pack Receipts</h2>{receipts.length > 0 && <button onClick={onClear}>Clear</button>}</div>
      <p className="drawerIntro">Session-only history of what context was assembled. Closing this tab clears it.</p>
      <div className="receiptList">
        {receipts.map((receipt) => (
          <article key={receipt.id}>
            <div><strong>{receipt.project}</strong><time>{new Date(receipt.createdAt).toLocaleString()}</time></div>
            <p>{receipt.task}</p>
            <span>{receipt.agent || "Universal"} | {receipt.tokenBudget || 4000} token budget | {receipt.nodes} nodes | {(receipt.bytes / 1024).toFixed(1)} KB</span>
            {receipt.pack ? <button onClick={() => onCopy(receipt.pack, "Saved context pack copied.")}><Clipboard size={14} /> Copy</button> : <span className="receiptPrivate">Metadata only</span>}
          </article>
        ))}
        {!receipts.length && <p className="emptyText">Generate a context pack to create the first receipt.</p>}
      </div>
    </div>
  );
}

function GovernancePanel({ project, governance, decision, onEvaluate, onCreate, onRetire, onRefresh, isBusy }) {
  const [action, setAction] = useState("");
  const [path, setPath] = useState("");
  const [overrideReason, setOverrideReason] = useState("");
  const [retireTarget, setRetireTarget] = useState(null);
  const [retireReason, setRetireReason] = useState("");
  const [policy, setPolicy] = useState({
    kind: "constraint",
    effect: "warn",
    statement: "",
    action_contains: "",
    path_glob: "",
    required_check: "",
    pramana: "smriti",
    confidence: "0.75",
    verification_status: "unverified",
    source_path: "",
    overrideable: true,
  });

  async function submitEvaluation(event, reason = "") {
    event?.preventDefault();
    if (!action.trim()) return;
    const result = await onEvaluate({
      action: action.trim(),
      path: path.trim() || null,
      completed_checks: [],
      override_reason: reason || null,
    });
    if (result?.override_receipt) setOverrideReason("");
  }

  async function submitPolicy(event) {
    event.preventDefault();
    if (!policy.statement.trim()) return;
    const result = await onCreate({
      kind: policy.kind,
      effect: policy.effect,
      statement: policy.statement.trim(),
      action_contains: policy.action_contains.trim(),
      path_glob: policy.path_glob.trim(),
      required_check: policy.required_check.trim(),
      pramana: policy.pramana,
      confidence: Number(policy.confidence),
      overrideable: policy.overrideable,
      provenance: {
        verification_status: policy.verification_status,
        source_path: policy.source_path.trim() || null,
      },
    });
    if (result) setPolicy((current) => ({ ...current, statement: "", action_contains: "", path_glob: "", required_check: "", source_path: "" }));
  }

  async function confirmRetire() {
    if (!retireTarget || !retireReason.trim()) return;
    const result = await onRetire(retireTarget, retireReason.trim());
    if (result) {
      setRetireTarget(null);
      setRetireReason("");
    }
  }

  if (!project) {
    return <div className="drawerContent"><h2>Action Gate</h2><p className="emptyState">Select a project brain first.</p></div>;
  }

  const decisionLabel = decision?.decision?.replaceAll("_", " ") || "not checked";
  const canOverride = decision && ["block", "warn"].includes(decision.decision)
    && decision.matches?.some((match) => match.overrideable);

  return (
    <div className="drawerContent governancePanel">
      <div className="sectionHeader">
        <h2>Action Gate</h2>
        <button className="freshnessAction" onClick={onRefresh} disabled={isBusy} aria-label="Refresh governance policies">
          <RefreshCw className={isBusy ? "spin" : ""} size={13} /> Refresh
        </button>
      </div>

      <form className="gateForm" onSubmit={submitEvaluation}>
        <label>
          <span>Intended action</span>
          <textarea value={action} onChange={(event) => setAction(event.target.value)} placeholder="Publish a reviewed release" rows={3} required />
        </label>
        <label>
          <span>Repository path <em>optional</em></span>
          <input value={path} onChange={(event) => setPath(event.target.value)} placeholder="src/release.py" />
        </label>
        <button className="primarySmall" type="submit" disabled={isBusy || !action.trim()}>
          <ShieldCheck size={16} /> {isBusy ? "Evaluating..." : "Evaluate action"}
        </button>
      </form>

      <section className={`gateDecision ${decision?.decision || "idle"}`} aria-live="polite">
        <ShieldAlert size={22} />
        <div><span>Decision</span><strong>{decisionLabel}</strong></div>
        <em>{decision?.matches?.length || 0} matched</em>
      </section>

      {decision?.matches?.length > 0 && (
        <div className="gateMatches">
          {decision.matches.map((match, index) => (
            <article key={match.policy_id ?? `${match.kind}-${index}`} className={match.effective_effect}>
              <div className="policyLine"><strong>{match.kind.replaceAll("_", " ")}</strong><em>{match.effective_effect}</em></div>
              <p>{match.reason}</p>
              <span>{match.pramana} / {Math.round(match.confidence * 100)}% / {match.provenance?.verification_status || "unverified"}</span>
              {match.provenance?.source_path && <code>{match.provenance.source_path}</code>}
            </article>
          ))}
        </div>
      )}

      {decision?.satisfied_policy_ids?.length > 0 && <p className="gateSatisfied"><CheckCircle2 size={14} /> {decision.satisfied_policy_ids.length} required check satisfied</p>}

      {canOverride && (
        <div className="overrideForm">
          <label>
            <span>Override reason</span>
            <textarea value={overrideReason} onChange={(event) => setOverrideReason(event.target.value)} rows={2} placeholder="Owner approval and evidence reference" />
          </label>
          <button className="amberButton" type="button" disabled={isBusy || !overrideReason.trim()} onClick={(event) => submitEvaluation(event, overrideReason.trim())}>
            Record override receipt
          </button>
        </div>
      )}

      <div className="sectionHeader governanceSectionTitle">
        <span>Active policies</span><em>{governance.policies.length}</em>
      </div>
      <div className="policyList">
        {governance.policies.map((item) => (
          <article key={item.id}>
            <div className="policyLine"><strong>{item.kind.replaceAll("_", " ")}</strong><em className={item.effect}>{item.effect}</em></div>
            <p>{item.statement}</p>
            <span>{item.pramana} / {Math.round(item.confidence * 100)}% / {item.provenance?.verification_status || "unverified"}</span>
            {retireTarget === item.id ? (
              <div className="retireForm">
                <input value={retireReason} onChange={(event) => setRetireReason(event.target.value)} placeholder="Reason for retirement" autoFocus />
                <button type="button" onClick={confirmRetire} disabled={isBusy || !retireReason.trim()}>Confirm</button>
                <button type="button" onClick={() => { setRetireTarget(null); setRetireReason(""); }}>Cancel</button>
              </div>
            ) : <button className="policyRetire" type="button" onClick={() => setRetireTarget(item.id)}>Retire</button>}
          </article>
        ))}
        {!governance.policies.length && <p className="emptyState">No active policies for {project.project}.</p>}
      </div>

      <details className="policyAuthoring">
        <summary><Plus size={15} /> Add governance policy</summary>
        <form onSubmit={submitPolicy}>
          <label><span>Statement</span><textarea value={policy.statement} onChange={(event) => setPolicy({ ...policy, statement: event.target.value })} rows={3} required /></label>
          <div className="policyFieldPair">
            <label><span>Kind</span><select value={policy.kind} onChange={(event) => setPolicy({ ...policy, kind: event.target.value })}>
              <option value="constraint">Constraint</option><option value="failed_approach">Failed approach</option><option value="fragile_path">Fragile path</option><option value="required_check">Required check</option><option value="prohibited_repetition">Prohibited repetition</option>
            </select></label>
            <label><span>Effect</span><select value={policy.effect} onChange={(event) => setPolicy({ ...policy, effect: event.target.value })}><option value="warn">Warn</option><option value="block">Block</option></select></label>
          </div>
          <label><span>Action contains</span><input value={policy.action_contains} onChange={(event) => setPolicy({ ...policy, action_contains: event.target.value })} placeholder="publish" /></label>
          <label><span>Path glob</span><input value={policy.path_glob} onChange={(event) => setPolicy({ ...policy, path_glob: event.target.value })} placeholder="migrations/*.sql" /></label>
          <label><span>Required check</span><input value={policy.required_check} onChange={(event) => setPolicy({ ...policy, required_check: event.target.value })} placeholder="privacy-scan" /></label>
          <div className="policyFieldPair">
            <label><span>Pramana</span><select value={policy.pramana} onChange={(event) => setPolicy({ ...policy, pramana: event.target.value })}><option value="smriti">Smriti</option><option value="pratyaksha">Pratyaksha</option><option value="sabda">Sabda</option><option value="anumana">Anumana</option><option value="kalpana">Kalpana</option></select></label>
            <label><span>Confidence</span><input type="number" min="0" max="1" step="0.05" value={policy.confidence} onChange={(event) => setPolicy({ ...policy, confidence: event.target.value })} /></label>
          </div>
          <label><span>Verification</span><select value={policy.verification_status} onChange={(event) => setPolicy({ ...policy, verification_status: event.target.value })}><option value="unverified">Unverified</option><option value="verified">Verified</option><option value="failed">Failed</option><option value="stale">Stale</option></select></label>
          <label><span>Evidence source</span><input value={policy.source_path} onChange={(event) => setPolicy({ ...policy, source_path: event.target.value })} placeholder="SECURITY.md" /></label>
          <label className="checkLabel"><input type="checkbox" checked={policy.overrideable} onChange={(event) => setPolicy({ ...policy, overrideable: event.target.checked })} /><span>Operator may override with a recorded reason</span></label>
          <p className="trustNote">Blocking requires hash-backed, verified Pratyaksha or Sabda evidence at 80% confidence or higher.</p>
          <button className="primarySmall" type="submit" disabled={isBusy || !policy.statement.trim()}><Plus size={16} /> Add policy</button>
        </form>
      </details>

      <div className="governanceReceipts"><span>Override receipts</span><strong>{governance.receipts.length}</strong></div>
      <div className="governanceReceiptList">
        {governance.receipts.slice(0, 5).map((receipt) => (
          <article key={receipt.id}>
            <div className="policyLine"><strong>{receipt.final_decision.replaceAll("_", " ")}</strong><em>#{receipt.id}</em></div>
            <p>{receipt.action}</p>
            <span>{receipt.actor} / {new Date(receipt.created_at).toLocaleString()}</span>
            <small>{receipt.override_reason}</small>
          </article>
        ))}
      </div>
    </div>
  );
}

function PublishPanel({ publish, onRefresh, isRefreshing }) {
  const checks = publish?.checks || [];
  const readyCount = checks.filter((check) => check.ok).length;
  const checkout = String(publish?.tool_root || "rta-smriti-brain").split(/[\\/]/).filter(Boolean).at(-1);
  return (
    <div className="drawerContent releasePanel">
      <div className="sectionHeader">
        <h2>Rta-Smriti Release</h2>
        <button className="freshnessAction" onClick={onRefresh} disabled={isRefreshing}>
          <RefreshCw className={isRefreshing ? "spin" : ""} size={13} /> {isRefreshing ? "Checking" : "Refresh"}
        </button>
      </div>
      <p className="drawerIntro">GitHub release requirements for this Rta-Smriti source checkout. The selected project brain is not assessed here.</p>
      <section className={publish?.ready ? "releaseSummary ready" : "releaseSummary open"}>
        <Rocket size={22} />
        <div><strong>{checkout}</strong><span>Local source checkout</span></div>
        <em>{readyCount}/{checks.length || "?"}</em>
      </section>
      <div className="launchChecks">
        {checks.map((check) => (
          <article key={check.name} className={check.ok ? "ready" : "open"}>
            {check.ok ? <CheckCircle2 size={16} /> : <CircleDot size={16} />}
            <div>
              <strong>{check.name}</strong>
              <span>{check.note || (check.ok ? "Ready" : "Open")}</span>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

function BootstrapPanel({ onDone, shellKind }) {
  const [path, setPath] = useState("");
  const [project, setProject] = useState("");
  const [output, setOutput] = useState("");
  const [writeAgents, setWriteAgents] = useState(false);
  const [embeddingProvider, setEmbeddingProvider] = useState("hash");
  const [targetAgent, setTargetAgent] = useState("universal");
  const [isBootstrapping, setIsBootstrapping] = useState(false);

  async function bootstrap() {
    if (!path.trim()) {
      setOutput("Enter a project folder.");
      return;
    }
    try {
      setIsBootstrapping(true);
      setOutput("Building local brain...");
      const payload = await api("/api/bootstrap", {
        method: "POST",
        body: JSON.stringify({
          path,
          project: project.trim() || null,
          target_agent: targetAgent,
          write_agents: writeAgents,
          embedding_provider: embeddingProvider,
        }),
      });
      const stageText = (payload.stages || []).map((stage) => `${stage.state === "complete" ? "OK" : "BLOCKED"}  ${stage.name}: ${stage.detail}`).join("\n");
      if (!payload.ready) {
        setOutput(`Setup needs attention at ${payload.error?.stage || "verification"}: ${payload.error?.message || "unknown error"}\n\n${stageText}\n\nResume: ${payload.recovery_commands?.resume || "rerun setup"}`);
        return;
      }
      const readyText = `Brain ready: ${payload.project}\nIndexed files: ${payload.bootstrap?.ingest?.indexed_files || 0}\nDatabase: ${displayPath(payload.db_path)}\n\n${stageText}${payload.bootstrap?.agent_index_file ? `\n\nAgent bridge: ${displayPath(payload.bootstrap.agent_index_file)}` : ""}`;
      const refreshed = await onDone({ project: payload.project, db_path: payload.db_path });
      setOutput(refreshed ? readyText : `${readyText}\n\nVERIFY: Dashboard refresh failed after setup. The brain was created, but the operator console cleared selection until the exact project/database identity can be verified.`);
    } catch (error) {
      setOutput(`Bootstrap failed: ${error.message}`);
    } finally {
      setIsBootstrapping(false);
    }
  }

  return (
    <div className="drawerContent">
      <h2>Bootstrap Brain</h2>
        <label>
          <span>Project Folder</span>
          <input
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder={shellKind === "powershell" ? "C:\\path\\to\\my-project" : "/path/to/my-project"}
          />
        </label>
      <label>
        <span>Project Name</span>
        <input value={project} onChange={(event) => setProject(event.target.value)} placeholder="Derived from folder when blank" />
      </label>
      <label>
        <span>Target Agent</span>
        <select value={targetAgent} onChange={(event) => setTargetAgent(event.target.value)}>
          {targetAgents.map((agent) => <option key={agent.value} value={agent.value}>{agent.label}</option>)}
        </select>
      </label>
      <label>
        <span>Retrieval</span>
        <select value={embeddingProvider} onChange={(event) => setEmbeddingProvider(event.target.value)}>
          <option value="hash">Local Hybrid (Recommended)</option>
          <option value="none">Lexical + Structural Only</option>
        </select>
      </label>
      <label className="checkLabel">
        <input type="checkbox" checked={writeAgents} onChange={(event) => setWriteAgents(event.target.checked)} />
        <span>Write the optional AGENTS.md bridge into this project</span>
      </label>
      <button className="primarySmall" onClick={bootstrap} disabled={isBootstrapping}>
        <Rocket size={16} /> {isBootstrapping ? "Starting..." : "Set Up & Start"}
      </button>
      {output && <pre className="miniOutput" role="status" aria-live="polite" aria-atomic="true">{output}</pre>}
    </div>
  );
}

function CommandPalette({ command, cliCommand, shellKind, brainDir, onClose, onCopy }) {
  const paletteRef = useRef(null);
  const returnFocusRef = useRef(null);
  useEffect(() => {
    returnFocusRef.current = document.activeElement;
    paletteRef.current?.querySelector("button")?.focus();
    return () => returnFocusRef.current?.focus?.();
  }, []);

  function keepFocusInside(event) {
    if (event.key !== "Tab") return;
    const controls = [...(paletteRef.current?.querySelectorAll("button:not(:disabled)") || [])];
    if (!controls.length) return;
    const first = controls[0];
    const last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
  const defaultBrainDir = shellPathArg(
    brainDir || (shellKind === "powershell" ? "$env:USERPROFILE\\Documents\\Rta-Smriti\\brains" : "$HOME/.local/share/rta-smriti/brains"),
    shellKind,
  );
  const commands = [
    ["Copy context-pack command", command],
    ["Open managed console", `${cliCommand} console open --brain-dir ${defaultBrainDir}`],
    ["Check Rta-Smriti release", `${cliCommand} publish-readiness --json`],
  ];
  return (
    <div className="paletteBackdrop" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={onClose}>
      <section ref={paletteRef} className="commandPalette" onMouseDown={(event) => event.stopPropagation()} onKeyDown={keepFocusInside}>
        <div className="paletteHeader">
          <span>
            <Command size={17} /> Command Palette
          </span>
          <button onClick={onClose}>Close</button>
        </div>
        <div className="paletteList">
          {commands.map(([label, value]) => (
            <button
              key={label}
              aria-label={label}
              onClick={() => {
                onCopy(value, `${label} copied.`);
                onClose();
              }}
            >
              <strong>{label}</strong>
              <code>{value}</code>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
