"""Reversible, user-level login startup for the managed console."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from html import escape
from pathlib import Path

from .runtime_control import is_safe_regular_file


def _key(brain_dir: Path) -> str:
    canonical = str(brain_dir.expanduser().resolve())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _platform_support(platform_name: str, environment: dict[str, str]) -> tuple[str | None, str | None]:
    if platform_name == "win32":
        return "windows", None
    if platform_name == "darwin":
        return "macos", None
    if platform_name.startswith("linux"):
        if environment.get("WSL_DISTRO_NAME") or environment.get("WSL_INTEROP"):
            return None, "wsl"
        if not any(environment.get(name) for name in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_CURRENT_DESKTOP")):
            return None, "headless-linux"
        return "linux-desktop", None
    return None, "unsupported-platform"


def _entry_path(
    brain_dir: Path,
    *,
    platform_name: str,
    home: Path,
    environment: dict[str, str],
) -> tuple[Path | None, str | None, str | None]:
    kind, reason = _platform_support(platform_name, environment)
    if not kind:
        return None, None, reason
    suffix = _key(brain_dir)
    if kind == "windows":
        appdata = Path(environment.get("APPDATA") or home / "AppData" / "Roaming")
        path = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / f"Rta-Smriti-{suffix}.vbs"
    elif kind == "macos":
        path = home / "Library" / "LaunchAgents" / f"io.rta-smriti.console.{suffix}.plist"
    else:
        config = Path(environment.get("XDG_CONFIG_HOME") or home / ".config")
        path = config / "autostart" / f"rta-smriti-{suffix}.desktop"
    return path, kind, None


def _launch_parts(tool_root: Path, brain_dir: Path) -> list[str]:
    suffix = ["supervisor", "start", "--brain-dir", str(brain_dir.expanduser().resolve()), "--no-open"]
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), *suffix]
    source_cli = tool_root.resolve() / "rta-brain.py"
    if source_cli.is_file():
        return [str(Path(sys.executable).resolve()), str(source_cli), *suffix]
    return [str(Path(sys.executable).resolve()), "-m", "rta_brain.cli", *suffix]


def _desktop_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`") + '"'


def _windows_command_quote(value: str) -> str:
    if any(character in value for character in ('\0', '\r', '\n', '"')):
        raise ValueError("Windows startup arguments contain unsupported characters")
    backslashes = 0
    quoted = ['"']
    for character in value:
        if character == "\\":
            backslashes += 1
            continue
        quoted.append("\\" * backslashes)
        backslashes = 0
        quoted.append(character)
    quoted.append("\\" * (backslashes * 2))
    quoted.append('"')
    return "".join(quoted)


def _entry_text(kind: str, parts: list[str], key: str) -> str:
    if kind == "windows":
        command = " ".join(_windows_command_quote(part) for part in parts)
        script_command = command.replace('"', '""')
        return (
            'Set RtaSmritiStartup = GetObject("winmgmts:\\\\.\\root\\cimv2").Get("Win32_ProcessStartup").SpawnInstance_\n'
            'RtaSmritiStartup.ShowWindow = 0\n'
            'Set RtaSmritiProcess = GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_Process")\n'
            f'RtaSmritiResult = RtaSmritiProcess.Create("{script_command}", Null, RtaSmritiStartup, RtaSmritiPid)\n'
            'If RtaSmritiResult <> 0 Then WScript.Quit RtaSmritiResult\n'
        )
    if kind == "macos":
        arguments = "\n".join(f"      <string>{escape(part)}</string>" for part in parts)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>io.rta-smriti.console.{key}</string>
    <key>ProgramArguments</key>
    <array>
{arguments}
    </array>
    <key>RunAtLoad</key>
    <true/>
  </dict>
</plist>
"""
    command = " ".join(_desktop_quote(part) for part in parts)
    return f"""[Desktop Entry]
Type=Application
Name=Rta-Smriti Brain
Comment=Start the local operator console
Exec={command}
Terminal=false
X-GNOME-Autostart-enabled=true
"""


def _entry_candidates(entry: Path, kind: str) -> tuple[Path, ...]:
    if kind == "windows":
        return entry, entry.with_suffix(".cmd")
    return (entry,)


def _write_entry(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not is_safe_regular_file(path):
        raise ValueError(f"refusing linked autostart entry: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def autostart_status(
    brain_dir: Path,
    *,
    platform_name: str | None = None,
    home: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict:
    selected_platform = platform_name or sys.platform
    selected_home = (home or Path.home()).expanduser().resolve()
    selected_environment = dict(os.environ if environment is None else environment)
    entry, kind, reason = _entry_path(
        brain_dir,
        platform_name=selected_platform,
        home=selected_home,
        environment=selected_environment,
    )
    if entry is None:
        return {
            "status": "ok", "supported": False, "enabled": False,
            "platform": selected_platform, "reason": reason, "entry_path": None,
        }
    candidates = _entry_candidates(entry, kind)
    unsafe = next((candidate for candidate in candidates if candidate.exists() and not is_safe_regular_file(candidate)), None)
    preferred_enabled = is_safe_regular_file(entry)
    legacy = candidates[1] if len(candidates) > 1 else None
    legacy_enabled = bool(legacy and is_safe_regular_file(legacy))
    selected_entry = entry if preferred_enabled or not legacy_enabled else legacy
    reason = "unsafe-entry" if unsafe else ("legacy-visible-console" if legacy_enabled and not preferred_enabled else None)
    return {
        "status": "ok", "supported": True,
        "enabled": preferred_enabled or legacy_enabled,
        "platform": kind, "reason": reason,
        "entry_path": str(selected_entry),
    }


def enable_autostart(
    tool_root: Path,
    brain_dir: Path,
    *,
    platform_name: str | None = None,
    home: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict:
    selected_platform = platform_name or sys.platform
    selected_home = (home or Path.home()).expanduser().resolve()
    selected_environment = dict(os.environ if environment is None else environment)
    entry, kind, reason = _entry_path(
        brain_dir,
        platform_name=selected_platform,
        home=selected_home,
        environment=selected_environment,
    )
    if entry is None:
        return {
            "status": "unsupported", "supported": False, "enabled": False,
            "platform": selected_platform, "reason": reason, "entry_path": None,
        }
    candidates = _entry_candidates(entry, kind)
    for candidate in candidates:
        if candidate.exists() and not is_safe_regular_file(candidate):
            raise ValueError(f"refusing linked autostart entry: {candidate}")
    parts = _launch_parts(tool_root, brain_dir)
    _write_entry(entry, _entry_text(kind, parts, _key(brain_dir)))
    for legacy in candidates[1:]:
        legacy.unlink(missing_ok=True)
    return {
        "status": "ok", "supported": True, "enabled": True,
        "platform": kind, "reason": None, "entry_path": str(entry),
    }


def disable_autostart(
    brain_dir: Path,
    *,
    platform_name: str | None = None,
    home: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict:
    status = autostart_status(
        brain_dir, platform_name=platform_name, home=home, environment=environment,
    )
    entry_value = status.get("entry_path")
    if not entry_value:
        return status
    selected_platform = platform_name or sys.platform
    selected_home = (home or Path.home()).expanduser().resolve()
    selected_environment = dict(os.environ if environment is None else environment)
    preferred, kind, _reason = _entry_path(
        brain_dir, platform_name=selected_platform, home=selected_home,
        environment=selected_environment,
    )
    candidates = _entry_candidates(preferred, kind) if preferred is not None and kind is not None else (Path(entry_value),)
    for candidate in candidates:
        if candidate.exists() and not is_safe_regular_file(candidate):
            raise ValueError(f"refusing linked autostart entry: {candidate}")
    for candidate in candidates:
        candidate.unlink(missing_ok=True)
    return {**status, "enabled": False, "reason": None, "entry_path": str(preferred or entry_value)}
