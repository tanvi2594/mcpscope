"""Command-line entry point: `mcpscope config | tools | live | rules`."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .live import LiveError, fetch_tools
from .loaders import discover_configs, load_config_servers, load_tool_dump
from .models import Finding, ScanStats, Severity
from .report import render
from .rules import ALL_RULES, scan_config, scan_tools
from .rules.config_rules import normalize_server


class UsageError(Exception):
    pass


def _severity(value: str) -> Optional[Severity]:
    if value.lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpscope",
        description="Security scanner for MCP (Model Context Protocol) client configs and tool definitions.",
    )
    parser.add_argument("--version", action="version", version=f"mcpscope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add_output_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text",
                       help="report format (default: text)")
        p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
        p.add_argument("--min-severity", type=_severity, default=Severity.LOW,
                       help="hide findings below this severity (default: low)")
        p.add_argument("--fail-on", type=_severity, default=Severity.HIGH,
                       help="exit with code 1 if a finding is at or above this severity; "
                            "'none' always exits 0 (default: high)")
        p.add_argument("--no-color", action="store_true", help="disable coloured output")

    p = sub.add_parser("config", help="scan MCP client config files (auto-discovers common locations)")
    p.add_argument("paths", nargs="*", help="config files to scan; default: auto-discover")
    add_output_options(p)

    p = sub.add_parser("tools", help="scan saved tool definitions (output of tools/list)")
    p.add_argument("path", help="JSON file with tool definitions")
    add_output_options(p)

    p = sub.add_parser("live", help="launch stdio servers from configs, fetch their tools, and scan everything")
    p.add_argument("paths", nargs="*", help="config files; default: auto-discover")
    p.add_argument("-s", "--server", action="append", default=[],
                   help="only scan this server (repeatable)")
    p.add_argument("--timeout", type=float, default=20.0, help="seconds to wait per server (default: 20)")
    p.add_argument("--save-tools", help="also write the fetched tool definitions to this JSON file")
    add_output_options(p)

    sub.add_parser("rules", help="list every rule mcpscope checks")
    return parser


def _config_paths(raw: List[str]) -> List[Path]:
    if raw:
        return [Path(p) for p in raw]
    found = discover_configs()
    if not found:
        raise UsageError("no MCP config files found in the usual locations; pass a path explicitly")
    return found


def run_config(args: argparse.Namespace) -> Tuple[List[Finding], ScanStats]:
    stats, findings = ScanStats(), []
    for path in _config_paths(args.paths):
        try:
            servers = load_config_servers(path)
        except (OSError, ValueError) as exc:
            if args.paths:
                raise UsageError(f"{path}: {exc}") from None
            stats.notes.append(f"could not read {path}: {exc}")
            continue
        stats.files.append(str(path))
        stats.servers += len(servers)
        findings += scan_config(servers, file=str(path))
    return findings, stats


def run_tools(args: argparse.Namespace) -> Tuple[List[Finding], ScanStats]:
    try:
        grouped = load_tool_dump(Path(args.path))
    except (OSError, ValueError) as exc:
        raise UsageError(f"{args.path}: {exc}") from None
    stats = ScanStats(files=[args.path], servers=len(grouped), tools=sum(map(len, grouped.values())))
    return scan_tools(grouped, file=args.path), stats


def run_live(args: argparse.Namespace) -> Tuple[List[Finding], ScanStats]:
    import json

    stats, findings = ScanStats(), []
    fetched: Dict[str, List[dict]] = {}
    wanted = set(args.server)

    for path in _config_paths(args.paths):
        try:
            servers = load_config_servers(path)
        except (OSError, ValueError) as exc:
            raise UsageError(f"{path}: {exc}") from None
        if wanted:
            servers = {n: s for n, s in servers.items() if n in wanted}
        stats.files.append(str(path))
        stats.servers += len(servers)
        findings += scan_config(servers, file=str(path))

        for name, raw in servers.items():
            s = normalize_server(raw)
            if not s["command"]:
                stats.notes.append(f"{name}: skipped, live scan supports stdio servers only")
                continue
            print(f"[live] {name}: starting {s['command']} ...", file=sys.stderr)
            try:
                tools = fetch_tools(s["command"], s["args"], s["env"], timeout=args.timeout)
            except LiveError as exc:
                stats.notes.append(f"{name}: {exc}")
                continue
            print(f"[live] {name}: {len(tools)} tool(s)", file=sys.stderr)
            fetched[name] = tools

    if wanted and not stats.servers:
        raise UsageError(f"no server named {', '.join(sorted(wanted))} in the scanned configs")

    stats.tools = sum(map(len, fetched.values()))
    findings += scan_tools(fetched)
    if args.save_tools:
        Path(args.save_tools).write_text(
            json.dumps({n: {"tools": t} for n, t in fetched.items()}, indent=2, ensure_ascii=False),
            encoding="utf-8")
    return findings, stats


def print_rules() -> None:
    for r in ALL_RULES:
        print(f"{r.id}  {r.severity.name:<8}  {r.title}")


HANDLERS: Dict[str, Callable[[argparse.Namespace], Tuple[List[Finding], ScanStats]]] = {
    "config": run_config,
    "tools": run_tools,
    "live": run_live,
}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")  # never crash on odd characters in a Windows console
            except (OSError, ValueError):
                pass

    if args.command == "rules":
        print_rules()
        return 0

    try:
        findings, stats = HANDLERS[args.command](args)
    except UsageError as exc:
        print(f"mcpscope: error: {exc}", file=sys.stderr)
        return 2

    shown = sorted((f for f in findings if args.min_severity is None or f.severity >= args.min_severity),
                   key=lambda f: (-f.severity, f.rule.id, f.target))
    color = (args.format == "text" and not args.output and not args.no_color
             and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
    report = render(shown, stats, args.format, color=color)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in findings):
        return 1
    return 0
