"""Rules that inspect MCP tool definitions, i.e. the result of a `tools/list` call.

A tool definition looks like:
    {"name": "...", "description": "...", "inputSchema": {...JSON Schema...}}

The model reads every description in it (including the ones nested inside the
input schema), so that is where tool-poisoning payloads hide.
"""
from __future__ import annotations

import re
from typing import Dict, Iterator, List, Set, Tuple

from ..models import Finding, Severity
from .catalog import TP001, TP002, TP003, TP004, TP005, TP006, TP007, TP008

# Each entry: (pattern, explanation, severity). Ordered roughly by how damning a match is.
INJECTION_PATTERNS: List[Tuple["re.Pattern[str]", str, Severity]] = [
    (re.compile(r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|other)\s+"
                r"(?:instructions|prompts?|rules|directions)", re.I),
     "tells the model to ignore earlier instructions", Severity.HIGH),
    (re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|notify|alert)\b"
                r"[^.\n]{0,40}?\buser\b", re.I),
     "tells the model to hide something from the user", Severity.HIGH),
    (re.compile(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin)\s*>", re.I),
     "uses a pseudo-tag that is a common wrapper for smuggled instructions", Severity.HIGH),
    (re.compile(r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\s+you\b|\bnew\s+instructions?\s*:", re.I),
     "tries to change the model's role or rules", Severity.HIGH),
    (re.compile(r"\bbefore\s+(?:using|calling|running|invoking)\s+(?:this|any|the)\b[^.\n]{0,30}?\btools?\b",
                re.I),
     "tells the model to do something before using a tool", Severity.MEDIUM),
    (re.compile(r"\byou\s+(?:must|should|need\s+to)\s+(?:first\s+|also\s+|always\s+)?"
                r"(?:read|open|send|include|fetch|upload|forward)\b", re.I),
     "gives imperative instructions directly to the model", Severity.MEDIUM),
]

SENSITIVE_PATH = re.compile(
    r"\.ssh\b"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|\.aws[/\\]credentials"
    r"|(?<![\w.])\.env\b"
    r"|/etc/(?:passwd|shadow|sudoers)\b"
    r"|\.(?:netrc|npmrc|pypirc|git-credentials)\b"
    r"|\.kube[/\\]config"
    r"|\bmcp\.json\b|\bclaude_desktop_config\.json\b"
    r"|\bwallet\.dat\b|\bkeychain\b",
    re.I,
)

# Zero-width chars, bidi overrides/isolates, word joiners, BOM, soft hyphen and
# the Unicode "tag" block (U+E0000-U+E007F), which can encode a whole hidden ASCII message.
INVISIBLE = re.compile(
    "[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000E0000-\U000E007F]"
)
TAG_BLOCK = range(0xE0000, 0xE0080)

URL = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>)\]]+", re.I)
EXFIL_VERB = re.compile(r"\b(?:send|post|upload|forward|transmit|exfiltrate|leak)\b", re.I)

CONTEXT_HARVEST = re.compile(
    r"\b(?:system\s+prompt|conversation\s+history|chat\s+history|previous\s+messages"
    r"|entire\s+conversation|all\s+(?:prior|previous)\s+messages|your\s+instructions)\b",
    re.I,
)

BASE64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")

MAX_DESCRIPTION = 1500


def scan_tools(servers: Dict[str, List[dict]], file: str = "") -> List[Finding]:
    """Scan tools grouped by server name: {"server": [tool, tool, ...]}.

    Tools from all servers are scanned together so that cross-server
    shadowing (TP005) can be detected.
    """
    index: Dict[str, Set[str]] = {}
    for server, tools in servers.items():
        for tool in tools:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                index.setdefault(tool["name"], set()).add(server)

    findings: List[Finding] = []
    for server, tools in servers.items():
        for tool in tools:
            if isinstance(tool, dict):
                findings.extend(_scan_tool(server, tool, index, file))
    return findings


def _scan_tool(server: str, tool: dict, index: Dict[str, Set[str]], file: str) -> Iterator[Finding]:
    name = str(tool.get("name") or "<unnamed>")
    target = f"{server} / {name}"

    for loc, text in _text_fields(tool):
        for pattern, why, severity in INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                yield Finding(TP001, target, why, loc, _snippet(text, m.start(), m.end()), file, severity)

        m = SENSITIVE_PATH.search(text)
        if m:
            yield Finding(TP002, target, f"mentions sensitive file '{m.group(0)}'", loc,
                          _snippet(text, m.start(), m.end()), file)

        hidden = INVISIBLE.findall(text)
        if hidden:
            yield _invisible_finding(target, loc, text, hidden, file)

        for url in URL.finditer(text):
            window = text[max(0, url.start() - 150): url.end() + 150]
            verb = EXFIL_VERB.search(window)
            if verb:
                address = url.group(0).rstrip(".,;:!?")
                yield Finding(TP004, target,
                              f"'{verb.group(0)}' near external URL {address}", loc,
                              _snippet(text, url.start(), url.end()), file)
                break

        for other, other_servers in index.items():
            foreign = other_servers - {server}
            if other == name or not foreign or not _is_distinctive(other):
                continue
            m = re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", text)
            if m:
                yield Finding(TP005, target,
                              f"mentions tool '{other}' from server '{sorted(foreign)[0]}'", loc,
                              _snippet(text, m.start(), m.end()), file)

        m = CONTEXT_HARVEST.search(text)
        if m:
            yield Finding(TP006, target, f"asks for '{m.group(0)}'", loc,
                          _snippet(text, m.start(), m.end()), file)

        urls = [u.span() for u in URL.finditer(text)]
        for m in BASE64_BLOB.finditer(text):
            inside_url = any(s <= m.start() < e for s, e in urls)
            blob = m.group(0)
            if not inside_url and _looks_encoded(blob):
                yield Finding(TP007, target, f"{len(blob)}-character encoded-looking string", loc,
                              blob[:24] + "...", file)
                break

    description = tool.get("description") or ""
    if isinstance(description, str) and len(description) > MAX_DESCRIPTION:
        yield Finding(TP008, target,
                      f"description is {len(description)} characters (threshold {MAX_DESCRIPTION})",
                      "description", "", file)


def _text_fields(tool: dict) -> Iterator[Tuple[str, str]]:
    """Yield (location, text) for every model-visible string in a tool definition."""
    for key in ("name", "title", "description"):
        value = tool.get(key)
        if isinstance(value, str):
            yield key, value
    schema = tool.get("inputSchema") or tool.get("input_schema")
    if schema is not None:
        yield from _walk_schema(schema, "inputSchema")


def _walk_schema(node: object, path: str) -> Iterator[Tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}"
            if key in ("description", "title", "default") and isinstance(value, str):
                yield child, value
            else:
                yield from _walk_schema(value, child)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _walk_schema(value, f"{path}[{i}]")


def _invisible_finding(target: str, loc: str, text: str, hidden: List[str], file: str) -> Finding:
    codepoints = sorted({f"U+{ord(c):04X}" for c in hidden})
    shown = ", ".join(codepoints[:6]) + (" ..." if len(codepoints) > 6 else "")
    decoded = "".join(chr(ord(c) - 0xE0000) for c in hidden
                      if ord(c) in TAG_BLOCK and 0x20 <= ord(c) - 0xE0000 < 0x7F)
    if decoded:
        return Finding(TP003, target,
                       f"{len(hidden)} invisible character(s) ({shown}) that decode to hidden text",
                       loc, f"hidden text: {decoded[:120]!r}", file, Severity.CRITICAL)
    first = INVISIBLE.search(text)
    return Finding(TP003, target, f"{len(hidden)} invisible character(s): {shown}", loc,
                   _snippet(text, first.start(), first.end()), file)


def _is_distinctive(tool_name: str) -> bool:
    """Only names like `send_email` or `sendEmail` are worth matching; plain words
    such as `search` or `read` would produce constant false positives."""
    return len(tool_name) >= 5 and bool(
        "_" in tool_name or "-" in tool_name or re.search(r"[a-z][A-Z]", tool_name)
    )


def _looks_encoded(blob: str) -> bool:
    # Hex digests (sha256 etc.) only use one letter case, so requiring
    # upper case, lower case and digits keeps them out.
    return (any(c.isupper() for c in blob) and any(c.islower() for c in blob)
            and any(c.isdigit() for c in blob))


def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    s, e = max(0, start - pad), min(len(text), end + pad)
    excerpt = INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", text[s:e])
    excerpt = " ".join(excerpt.split())
    return ("..." if s > 0 else "") + excerpt + ("..." if e < len(text) else "")
