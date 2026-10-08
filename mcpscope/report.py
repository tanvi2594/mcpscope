"""Turn findings into text, JSON or SARIF (for GitHub code scanning)."""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import List

from . import __version__
from .models import Finding, ScanStats, Severity
from .rules import ALL_RULES

RESET = "\033[0m"
DIM = "\033[2m"
GREEN = "\033[32m"
SEVERITY_STYLE = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: DIM,
}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}
# GitHub uses this property to bucket alerts into critical/high/medium/low.
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                     Severity.LOW: "3.0", Severity.INFO: "0.0"}
REPO_URL = "https://github.com/YOUR_USERNAME/mcpscope"


def render(findings: List[Finding], stats: ScanStats, fmt: str, color: bool = False) -> str:
    if fmt == "json":
        return render_json(findings, stats)
    if fmt == "sarif":
        return render_sarif(findings)
    return render_text(findings, stats, color)


def render_text(findings: List[Finding], stats: ScanStats, color: bool = False) -> str:
    def paint(style: str, text: str) -> str:
        return f"{style}{text}{RESET}" if color else text

    lines = [f"mcpscope {__version__}: scanned {len(stats.files)} file(s), "
             f"{stats.servers} server(s), {stats.tools} tool(s)"]
    lines += [paint(DIM, f"  note: {note}") for note in stats.notes]
    lines.append("")

    if not findings:
        lines.append(paint(GREEN, "No findings."))
    for f in findings:
        tag = paint(SEVERITY_STYLE[f.severity], f"[{f.severity.name}]")
        lines.append(f"{tag} {f.rule.id}  {f.rule.title}")
        lines.append(f"    target   : {f.target}")
        if f.location:
            lines.append(f"    location : {f.location}")
        lines.append(f"    detail   : {f.message}")
        if f.evidence:
            lines.append(f"    evidence : {f.evidence}")
        if f.file:
            lines.append(f"    file     : {f.file}")
        lines.append("")

    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts.get(s, 0)} {s.name.lower()}"
                        for s in sorted(Severity, reverse=True) if s is not Severity.INFO)
    lines.append(f"Summary: {summary}")
    return "\n".join(lines) + "\n"


def render_json(findings: List[Finding], stats: ScanStats) -> str:
    payload = {
        "tool": "mcpscope",
        "version": __version__,
        "scanned": {"files": stats.files, "servers": stats.servers, "tools": stats.tools},
        "notes": stats.notes,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_sarif(findings: List[Finding]) -> str:
    rules = [{
        "id": r.id,
        "name": r.title.replace(" ", ""),
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.help},
        "help": {"text": r.help},
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        "properties": {"security-severity": SECURITY_SEVERITY[r.severity], "tags": ["security", "mcp"]},
    } for r in ALL_RULES]

    results = []
    for f in findings:
        text = f"{f.target}: {f.message}" + (f" [{f.location}]" if f.location else "")
        result = {
            "ruleId": f.rule.id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": text},
            "properties": {"severity": f.severity.name.lower(), "target": f.target, "evidence": f.evidence,
                           "security-severity": SECURITY_SEVERITY[f.severity]},
        }
        if f.file:
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": _relative_uri(f.file)},
                "region": {"startLine": 1},
            }}]
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcpscope", "version": __version__,
                                "informationUri": REPO_URL, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def _relative_uri(path: str) -> str:
    p = Path(path)
    try:
        p = p.resolve().relative_to(Path(os.getcwd()).resolve())
    except ValueError:
        pass
    return p.as_posix()
