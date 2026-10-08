"""Every rule mcpscope can report, in one place."""
from __future__ import annotations

from ..models import Rule, Severity

# --- Tool definition rules (what the model reads) --------------------------
TP001 = Rule(
    "TP001", "Hidden instructions in tool metadata", Severity.HIGH,
    "Tool descriptions are shown to the model, usually not to the user. Text that tells the "
    "model to ignore instructions, hide actions from the user, or do extra work before a "
    "call is the core of a tool-poisoning attack.",
)
TP002 = Rule(
    "TP002", "Reference to a sensitive file", Severity.HIGH,
    "A tool description that mentions SSH keys, cloud credentials, .env files or MCP configs "
    "is a common way to trick the model into reading secrets and passing them to the tool.",
)
TP003 = Rule(
    "TP003", "Invisible Unicode characters", Severity.HIGH,
    "Zero-width, bidirectional-override and Unicode 'tag' characters render as nothing in "
    "most UIs but are read by the model. They are used to hide instructions in plain sight.",
)
TP004 = Rule(
    "TP004", "Possible data-exfiltration instruction", Severity.HIGH,
    "The text combines a URL with a verb like send/upload/forward, which is how injected "
    "instructions typically move data out to an attacker-controlled endpoint.",
)
TP005 = Rule(
    "TP005", "Cross-server tool shadowing", Severity.MEDIUM,
    "A tool's description refers to a tool from a different server. A malicious server can use "
    "this to change how a trusted tool is used (for example, rewriting an email recipient).",
)
TP006 = Rule(
    "TP006", "Request for conversation context", Severity.MEDIUM,
    "A tool asks for the system prompt or chat history, which lets a server harvest data the "
    "user never meant to share with it.",
)
TP007 = Rule(
    "TP007", "Encoded blob in tool metadata", Severity.MEDIUM,
    "Long base64-like strings have no place in a description written for a model and are often "
    "used to smuggle payloads past human review.",
)
TP008 = Rule(
    "TP008", "Unusually long tool description", Severity.LOW,
    "Very long descriptions are hard to review and give an attacker room to hide instructions.",
)

# --- Client config rules (how servers are launched) ------------------------
CF001 = Rule(
    "CF001", "Hardcoded secret in config", Severity.HIGH,
    "API keys and tokens written directly into an MCP config end up in backups, screenshots and "
    "git history. Use environment variables or your client's secret input instead.",
)
CF002 = Rule(
    "CF002", "Unpinned package or image", Severity.MEDIUM,
    "npx/uvx/docker without a fixed version runs whatever is newest at launch time, so a "
    "hijacked or malicious release would execute automatically.",
)
CF003 = Rule(
    "CF003", "Remote script piped to a shell", Severity.HIGH,
    "Downloading a script and piping it straight into a shell runs unreviewed code every time "
    "the server starts.",
)
CF004 = Rule(
    "CF004", "Unencrypted remote transport", Severity.HIGH,
    "Connecting to a non-local MCP server over http:// or ws:// exposes requests, tool results "
    "and any auth headers to anyone on the network path.",
)
CF005 = Rule(
    "CF005", "Broad filesystem access", Severity.MEDIUM,
    "The server is handed an entire drive or the whole home directory. Scope it to the folders "
    "it actually needs.",
)
CF006 = Rule(
    "CF006", "Dangerous container options", Severity.HIGH,
    "Privileged mode, the Docker socket, host networking or sensitive host mounts let a "
    "containerised server escape its sandbox.",
)
CF007 = Rule(
    "CF007", "Tools run without confirmation", Severity.MEDIUM,
    "Auto-approved tools execute with no human check, which removes the last line of defence "
    "against a poisoned or misbehaving server.",
)

ALL_RULES = [TP001, TP002, TP003, TP004, TP005, TP006, TP007, TP008,
             CF001, CF002, CF003, CF004, CF005, CF006, CF007]
BY_ID = {r.id: r for r in ALL_RULES}
