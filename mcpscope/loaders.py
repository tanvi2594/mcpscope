"""Finding and reading the files mcpscope scans."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional


def loads_jsonc(text: str) -> object:
    """Parse JSON that may contain // and /* */ comments and trailing commas (VS Code style)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    out, i, n, in_string = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            out.append(c)
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


def load_json_file(path: Path) -> object:
    return loads_jsonc(Path(path).read_text(encoding="utf-8-sig"))


def extract_servers(config: object) -> Dict[str, dict]:
    """Pull server entries out of the config formats used by common MCP clients."""
    servers: Dict[str, dict] = {}
    if not isinstance(config, dict):
        return servers
    for key in ("mcpServers", "servers", "mcp_servers", "context_servers"):
        block = config.get(key)
        if isinstance(block, dict):
            for name, entry in block.items():
                if isinstance(entry, dict):
                    servers[str(name)] = entry
    # Claude Code (~/.claude.json) also stores servers per project.
    projects = config.get("projects")
    if isinstance(projects, dict):
        for project, project_config in projects.items():
            block = project_config.get("mcpServers") if isinstance(project_config, dict) else None
            if isinstance(block, dict):
                for name, entry in block.items():
                    if isinstance(entry, dict):
                        servers[f"{name} ({project})"] = entry
    return servers


def load_config_servers(path: Path) -> Dict[str, dict]:
    return extract_servers(load_json_file(path))


def load_tool_dump(path: Path) -> Dict[str, List[dict]]:
    """Load saved tool definitions. Accepted shapes:
    - a list of tools
    - {"tools": [...]} or a raw JSON-RPC response {"result": {"tools": [...]}}
    - {"server-name": {"tools": [...]}, ...} or {"server-name": [...], ...}
    """
    data = load_json_file(path)
    default = Path(path).stem
    if isinstance(data, list):
        return {default: data}
    if isinstance(data, dict):
        if isinstance(data.get("result"), dict):
            data = data["result"]
        if isinstance(data.get("tools"), list):
            return {default: data["tools"]}
        grouped = {}
        for server, value in data.items():
            if isinstance(value, list):
                grouped[str(server)] = value
            elif isinstance(value, dict) and isinstance(value.get("tools"), list):
                grouped[str(server)] = value["tools"]
        if grouped:
            return grouped
    raise ValueError("unrecognised format; expected a list of tools, {\"tools\": [...]}, "
                     "or {\"server\": {\"tools\": [...]}}")


def candidate_config_paths(cwd: Optional[Path] = None) -> List[Path]:
    """Well-known MCP config locations for popular clients, user-level and project-level."""
    home = Path.home()
    cwd = Path(cwd or os.getcwd())
    paths = [
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",  # macOS
        home / ".config" / "Claude" / "claude_desktop_config.json",                        # Linux
        home / ".claude.json",                                                             # Claude Code
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / ".gemini" / "settings.json",
        cwd / ".mcp.json",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
        cwd / ".gemini" / "settings.json",
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:
        paths.insert(0, Path(appdata) / "Claude" / "claude_desktop_config.json")  # Windows

    unique, seen = [], set()
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def discover_configs(cwd: Optional[Path] = None) -> List[Path]:
    return [p for p in candidate_config_paths(cwd) if p.is_file()]
