"""Parser adapter registry with deterministic and optional backends."""

from __future__ import annotations

import importlib.metadata
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol


SYMBOL_PATTERNS = (
    re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE),
    re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)", re.MULTILINE),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)", re.MULTILINE),
)
IMPORT_PATTERNS = (
    re.compile(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_.]*)", re.MULTILINE),
    re.compile(r"^\s*from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s+", re.MULTILINE),
    re.compile(r"^\s*import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
    re.compile(r"require\(['\"]([^'\"]+)['\"]\)"),
)
CALL_PATTERN = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(")
CALL_EXCLUSIONS = frozenset({
    "and", "assert", "async", "await", "catch", "class", "def", "elif", "except",
    "for", "function", "if", "lambda", "match", "new", "not", "or", "raise",
    "return", "sizeof", "super", "switch", "throw", "try", "typeof", "while", "with",
})

TREE_SITTER_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
}
TREE_SITTER_SYMBOL_NODES = {
    "python": {"function_definition", "class_definition"},
    "javascript": {"function_declaration", "class_declaration", "method_definition"},
    "typescript": {"function_declaration", "class_declaration", "method_definition", "interface_declaration", "type_alias_declaration"},
    "tsx": {"function_declaration", "class_declaration", "method_definition", "interface_declaration", "type_alias_declaration"},
    "go": {"function_declaration", "method_declaration", "type_spec"},
    "rust": {"function_item", "struct_item", "enum_item", "trait_item", "union_item", "type_item", "mod_item"},
    "java": {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "method_declaration", "constructor_declaration"},
}
TREE_SITTER_IMPORT_NODES = {
    "python": {"import_statement", "import_from_statement"},
    "javascript": {"import_statement"},
    "typescript": {"import_statement"},
    "tsx": {"import_statement"},
    "go": {"import_declaration", "import_spec"},
    "rust": {"use_declaration"},
    "java": {"import_declaration"},
}
TREE_SITTER_CALL_NODES = {
    "python": {"call"},
    "javascript": {"call_expression"},
    "typescript": {"call_expression"},
    "tsx": {"call_expression"},
    "go": {"call_expression"},
    "rust": {"call_expression"},
    "java": {"method_invocation"},
}


_PARSER_RUNTIME_ENVIRONMENT_NAMES = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LANGUAGE",
        "LC_ADDRESS",
        "LC_ALL",
        "LC_COLLATE",
        "LC_CTYPE",
        "LC_IDENTIFICATION",
        "LC_MEASUREMENT",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NAME",
        "LC_NUMERIC",
        "LC_PAPER",
        "LC_TELEPHONE",
        "LC_TIME",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    }
)


def sanitized_parser_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    """Delegate only cross-platform runtime settings to parser subprocesses."""
    source = os.environ if environment is None else environment
    child: dict[str, str] = {}
    for name, value in source.items():
        normalized_name = str(name).upper()
        if normalized_name in _PARSER_RUNTIME_ENVIRONMENT_NAMES:
            child[normalized_name] = str(value)
    return child

LSP_SERVER_SPECS = (
    {"name": "pyright", "executables": ("pyright-langserver", "basedpyright-langserver"), "arguments": ("--stdio",), "suffixes": (".py",)},
    {"name": "gopls", "executables": ("gopls",), "arguments": (), "suffixes": (".go",)},
    {"name": "typescript", "executables": ("typescript-language-server",), "arguments": ("--stdio",), "suffixes": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")},
    {"name": "rust-analyzer", "executables": ("rust-analyzer",), "arguments": (), "suffixes": (".rs",)},
)
LSP_LANGUAGE_IDS = {
    ".py": "python", ".go": "go", ".js": "javascript", ".jsx": "javascriptreact",
    ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript",
    ".tsx": "typescriptreact", ".rs": "rust",
}
MAX_LSP_FRAME_BYTES = 8 * 1024 * 1024
MAX_LSP_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_LSP_MESSAGES = 1_024
MAX_LSP_QUEUED_MESSAGES = 256


def discover_lsp_servers(finder=shutil.which, excluded_root: Path | None = None) -> list[dict]:
    """Discover supported language servers from the operator's existing PATH."""
    discovered = []
    for spec in LSP_SERVER_SPECS:
        executable = None
        for candidate in spec["executables"]:
            executable = finder(candidate)
            if executable:
                break
        if not executable:
            continue
        resolved = Path(executable).expanduser().resolve()
        if not resolved.is_absolute() or not resolved.is_file():
            continue
        if excluded_root is not None:
            try:
                resolved.relative_to(excluded_root.expanduser().resolve())
            except ValueError:
                pass
            else:
                continue
        try:
            stat = resolved.stat()
        except OSError:
            continue
        discovered.append({
            "name": spec["name"],
            "executable": str(resolved),
            "executable_identity": f"{stat.st_size}:{stat.st_mtime_ns}",
            "command": [str(resolved), *spec["arguments"]],
            "suffixes": list(spec["suffixes"]),
        })
    return discovered


def _project_root(path: Path) -> Path:
    markers = (".git", "pyproject.toml", "package.json", "go.mod", "Cargo.toml")
    for candidate in (path.parent, *path.parents):
        if any((candidate / marker).exists() for marker in markers):
            return candidate
    return path.parent


def _read_lsp_frame(stream) -> dict:
    headers = {}
    consumed = 0
    while True:
        line = stream.readline()
        if not line:
            raise EOFError("language server closed stdout")
        consumed += len(line)
        if consumed > 16_384:
            raise ValueError("language server header exceeds 16 KB")
        if line in {b"\r\n", b"\n"}:
            break
        key, separator, value = line.decode("ascii", errors="strict").partition(":")
        if not separator:
            raise ValueError("invalid language server frame header")
        headers[key.casefold().strip()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if not 0 < length <= MAX_LSP_FRAME_BYTES:
        raise ValueError("language server frame size is invalid")
    payload = stream.read(length)
    if len(payload) != length:
        raise EOFError("language server response was truncated")
    return json.loads(payload.decode("utf-8"))


class _LspClient:
    def __init__(self, command: list[str], root: Path, timeout: float = 15.0) -> None:
        self.timeout = timeout
        creationflags = 0x08000000 if os.name == "nt" else 0
        self.process = subprocess.Popen(
            command,
            cwd=root,
            env=sanitized_parser_environment(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=creationflags,
        )
        self.messages: queue.Queue = queue.Queue(maxsize=MAX_LSP_QUEUED_MESSAGES)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        total_bytes = 0
        message_count = 0
        try:
            while self.process.stdout is not None:
                message = _read_lsp_frame(self.process.stdout)
                message_count += 1
                total_bytes += len(
                    json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
                )
                if (
                    message_count > MAX_LSP_MESSAGES
                    or total_bytes > MAX_LSP_TOTAL_RESPONSE_BYTES
                ):
                    raise ValueError("language server cumulative output exceeds the safety limit")
                self.messages.put(message)
        except (EOFError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            self.messages.put(exc)

    def send(self, payload: dict) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if self.process.stdin is None:
            raise RuntimeError("language server stdin is unavailable")
        self.process.stdin.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
        self.process.stdin.flush()

    def request(self, request_id: int, method: str, params: dict) -> object:
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"language server timed out during {method}")
            try:
                message = self.messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError(f"language server timed out during {method}") from exc
            if isinstance(message, Exception):
                raise RuntimeError(str(message)) from message
            if message.get("id") == request_id:
                if message.get("error"):
                    raise RuntimeError(f"language server error during {method}: {message['error']}")
                return message.get("result")
            if "id" in message and message.get("method"):
                default = [] if message["method"] == "workspace/configuration" else None
                self.send({"jsonrpc": "2.0", "id": message["id"], "result": default})

    def close(self) -> None:
        try:
            if self.process.poll() is None:
                try:
                    normal_timeout = self.timeout
                    self.timeout = min(self.timeout, 2.0)
                    self.request(99, "shutdown", {})
                    self.send({"jsonrpc": "2.0", "method": "exit"})
                except (OSError, RuntimeError, TimeoutError, queue.Empty):
                    pass
                finally:
                    self.timeout = normal_timeout
                self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)
        finally:
            for stream in (self.process.stdin, self.process.stdout):
                if stream is not None:
                    stream.close()


def _symbol_names(items) -> set[str]:
    names = set()
    for item in items or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            names.add(name)
        names.update(_symbol_names(item.get("children")))
    return names


def _native_lsp_parse(path: Path, text: str, server: dict) -> ParseResult:
    root = _project_root(path)
    executable = Path(str(server["command"][0])).resolve()
    expected_identity = str(server.get("executable_identity") or "")
    if expected_identity:
        try:
            stat = executable.stat()
        except OSError as exc:
            raise RuntimeError("the discovered language server is no longer available") from exc
        if f"{stat.st_size}:{stat.st_mtime_ns}" != expected_identity:
            raise RuntimeError("the discovered language server changed after discovery")
    client = _LspClient(list(server["command"]), root)
    uri = path.resolve().as_uri()
    root_uri = root.resolve().as_uri()
    try:
        client.request(1, "initialize", {
            "processId": None,
            "rootUri": root_uri,
            "workspaceFolders": [{"uri": root_uri, "name": root.name}],
            "capabilities": {"textDocument": {"documentSymbol": {"hierarchicalDocumentSymbolSupport": True}}},
        })
        client.send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
        client.send({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": uri, "languageId": LSP_LANGUAGE_IDS[path.suffix.lower()], "version": 1, "text": text}},
        })
        symbols = _symbol_names(client.request(2, "textDocument/documentSymbol", {"textDocument": {"uri": uri}}))
    finally:
        client.close()
    structural = TreeSitterParser()
    if structural.available and path.suffix.lower() in TREE_SITTER_LANGUAGES:
        fallback = structural.parse(path, text)
    else:
        fallback = RegexParser().parse(path, text)
    return ParseResult(
        symbols=sorted(symbols, key=str.lower),
        imports=fallback.imports,
        calls=fallback.calls,
        parser=f"lsp:{server['name']}",
    )


@dataclass
class ParseResult:
    symbols: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    parser: str = "regex"
    warnings: list[str] = field(default_factory=list)


class ParserAdapter(Protocol):
    name: str

    def parse(self, path: Path, text: str) -> ParseResult: ...


class RegexParser:
    name = "regex"

    def parse(self, _path: Path, text: str) -> ParseResult:
        symbols = {match.group(1) for pattern in SYMBOL_PATTERNS for match in pattern.finditer(text)}
        imports = {match.group(1) for pattern in IMPORT_PATTERNS for match in pattern.finditer(text)}
        calls = {
            match.group(1).split(".")[-1]
            for match in CALL_PATTERN.finditer(text)
            if match.group(1).casefold() not in CALL_EXCLUSIONS
            and match.group(1).split(".")[-1] not in symbols
        }
        return ParseResult(
            symbols=sorted(symbols, key=str.lower),
            imports=sorted(imports, key=str.lower),
            calls=sorted(calls, key=str.lower),
            parser=self.name,
        )


class TreeSitterParser:
    name = "tree-sitter"

    def __init__(self) -> None:
        try:
            from tree_sitter_language_pack import get_parser
        except ImportError:
            get_parser = None
        self._get_parser = get_parser

    @property
    def available(self) -> bool:
        return self._get_parser is not None

    def parse(self, path: Path, text: str) -> ParseResult:
        if not self.available:
            raise RuntimeError("tree-sitter-language-pack is not installed")
        language = TREE_SITTER_LANGUAGES.get(path.suffix.lower())
        if not language:
            raise RuntimeError(f"Tree-sitter language is not configured for {path.suffix or 'this file'}")
        source = text.encode("utf-8")
        tree = self._get_parser(language).parse(source)
        symbols: set[str] = set()
        imports: set[str] = set()
        calls: set[str] = set()

        def node_text(node) -> str:
            return source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

        def import_names(snippet: str) -> set[str]:
            if language == "go":
                return set(re.findall(r'(?m)^\s*(?:import\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s+)?["`]([^"`]+)["`]', snippet))
            if language == "rust":
                return {match.strip() for match in re.findall(r"\buse\s+([^;]+)", snippet) if match.strip()}
            if language == "java":
                return set(re.findall(r"\bimport\s+(?:static\s+)?([A-Za-z_][A-Za-z0-9_.*]+)\s*;", snippet))
            return set(RegexParser().parse(path, snippet).imports)

        def visit(node) -> None:
            if node.type in TREE_SITTER_SYMBOL_NODES.get(language, set()):
                name = node.child_by_field_name("name")
                if name:
                    symbols.add(node_text(name))
            if node.type in TREE_SITTER_IMPORT_NODES.get(language, set()):
                imports.update(import_names(node_text(node)))
            if node.type in TREE_SITTER_CALL_NODES.get(language, set()):
                callee = node.child_by_field_name("function") or node.child_by_field_name("name")
                if callee:
                    identifiers = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", node_text(callee))
                    if identifiers and identifiers[-1].casefold() not in CALL_EXCLUSIONS:
                        calls.add(identifiers[-1])
            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return ParseResult(
            symbols=sorted(symbols, key=str.lower),
            imports=sorted(imports, key=str.lower),
            calls=sorted(calls, key=str.lower),
            parser=self.name,
        )


class LspParser:
    """Explicit JSON adapter plus opt-in native LSP auto-discovery."""

    name = "lsp"

    def __init__(
        self,
        command: str = "",
        *,
        auto_discovery: bool = False,
        executable_finder=shutil.which,
        discovery_excluded_root: Path | None = None,
    ) -> None:
        self.command = command.strip()
        self.auto_discovery = bool(auto_discovery)
        self.detected_servers = discover_lsp_servers(
            finder=executable_finder,
            excluded_root=discovery_excluded_root,
        ) if self.auto_discovery else []

    @property
    def available(self) -> bool:
        return bool(self.command or self.detected_servers)

    def parse(self, path: Path, text: str) -> ParseResult:
        if self.command:
            request = json.dumps({"path": str(path), "text": text})
            with tempfile.TemporaryFile(mode="w+b") as output:
                completed = subprocess.run(
                    shlex.split(self.command), input=request, text=True,
                    stdout=output, stderr=subprocess.DEVNULL,
                    timeout=30, check=False, env=sanitized_parser_environment(),
                )
                supplied_stdout = getattr(completed, "stdout", None)
                if supplied_stdout is None:
                    output.seek(0)
                    raw_output = output.read(MAX_LSP_TOTAL_RESPONSE_BYTES + 1)
                else:
                    raw_output = str(supplied_stdout).encode("utf-8")
            if completed.returncode:
                raise RuntimeError(f"LSP adapter exited with code {completed.returncode}")
            if len(raw_output) > MAX_LSP_TOTAL_RESPONSE_BYTES:
                raise ValueError("LSP adapter output exceeds the safety limit")
            payload = json.loads(raw_output.decode("utf-8"))
            return ParseResult(
                symbols=sorted({str(item) for item in payload.get("symbols", [])}, key=str.lower),
                imports=sorted({str(item) for item in payload.get("imports", [])}, key=str.lower),
                calls=sorted(
                    {str(item) for item in payload.get("calls", RegexParser().parse(path, text).calls)},
                    key=str.lower,
                ),
                parser=self.name,
            )
        suffix = path.suffix.lower()
        server = next((item for item in self.detected_servers if suffix in item["suffixes"]), None)
        if server is None:
            raise RuntimeError(f"no supported language server was discovered for {suffix or 'this file'}")
        return _native_lsp_parse(path, text, server)


class ParserRegistry:
    def __init__(
        self,
        load_entry_points: bool = False,
        lsp_command: str = "",
        *,
        lsp_auto_discovery: bool = False,
        executable_finder=shutil.which,
        lsp_discovery_excluded_root: Path | None = None,
    ) -> None:
        self._parsers: dict[str, ParserAdapter] = {}
        self.register(RegexParser())
        self.register(TreeSitterParser())
        self.register(LspParser(
            lsp_command,
            auto_discovery=lsp_auto_discovery,
            executable_finder=executable_finder,
            discovery_excluded_root=lsp_discovery_excluded_root,
        ))
        if load_entry_points:
            self._load_entry_points()

    def register(self, parser: ParserAdapter) -> None:
        self._parsers[parser.name] = parser

    def _load_entry_points(self) -> None:
        try:
            points = importlib.metadata.entry_points(group="rta_smriti.parsers")
        except TypeError:
            points = importlib.metadata.entry_points().get("rta_smriti.parsers", [])
        for point in points:
            self.register(point.load()())

    def capabilities(self) -> dict[str, dict]:
        capabilities = {
            name: {"available": bool(getattr(parser, "available", True)), "source": parser.__class__.__name__}
            for name, parser in sorted(self._parsers.items())
        }
        capabilities["auto"] = {
            "available": True,
            "source": "TreeSitterThenRegex",
            "tree_sitter_available": capabilities.get("tree-sitter", {}).get("available", False),
        }
        lsp = self._parsers.get("lsp")
        if isinstance(lsp, LspParser):
            capabilities["lsp"]["auto_discovery"] = lsp.auto_discovery
            capabilities["lsp"]["detected_servers"] = lsp.detected_servers
        return capabilities

    def parse(self, path: Path, text: str, parser_name: str = "regex") -> ParseResult:
        if parser_name == "auto":
            tree_sitter = self._parsers["tree-sitter"]
            if bool(getattr(tree_sitter, "available", False)):
                try:
                    result = tree_sitter.parse(path, text)
                    result.parser = "auto:tree-sitter"
                    return result
                except (
                    OSError,
                    RuntimeError,
                    TimeoutError,
                    ValueError,
                    json.JSONDecodeError,
                    subprocess.SubprocessError,
                ):
                    pass
            result = self._parsers["regex"].parse(path, text)
            result.parser = "auto:regex"
            return result
        parser = self._parsers.get(parser_name)
        if parser is None:
            raise ValueError(f"unknown parser adapter: {parser_name}")
        try:
            return parser.parse(path, text)
        except (
            OSError,
            RuntimeError,
            TimeoutError,
            ValueError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            if parser_name == "regex":
                raise
            fallback = self._parsers["regex"].parse(path, text)
            fallback.warnings.append(f"{parser_name} unavailable; used regex: {exc}")
            return fallback
