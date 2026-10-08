"""Rules that inspect MCP client configs (claude_desktop_config.json, .cursor/mcp.json, ...).

A server entry looks like either a local (stdio) server:
    {"command": "npx", "args": ["-y", "pkg"], "env": {"KEY": "value"}}
or a remote one:
    {"url": "https://example.com/mcp", "headers": {"Authorization": "Bearer ..."}}
"""
from __future__ import annotations

import os
import re
import shlex
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from ..models import Finding, Severity
from .catalog import CF001, CF002, CF003, CF004, CF005, CF006, CF007

SECRET_KEY_NAME = re.compile(
    r"api[_-]?key|token|secret|passw(?:or)?d|\bpwd\b|credential|private[_-]?key|access[_-]?key"
    r"|authorization|bearer|session[_-]?key",
    re.I,
)

# Well-known token shapes. Matching one of these is strong evidence on its own.
SECRET_VALUE_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}")),
    ("OpenAI/Anthropic-style key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}")),
]

PLACEHOLDER = re.compile(r"your[_\- ]|xxx|changeme|placeholder|example|dummy|redacted|\*{3,}|<.+>", re.I)
AUTH_SCHEME = re.compile(r"^(?:bearer|basic|token)\s+", re.I)

PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;]*\|\s*(?:iex|Invoke-Expression)\b",
    re.I,
)

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
BROAD_PATHS = {"/", "~", "$HOME", "${HOME}", "%USERPROFILE%", "/home", "/Users", "/root", "C:\\", "C:/", "C:"}
SENSITIVE_MOUNTS = {"/", "/etc", "/root", "/home", "/Users", "/var/run/docker.sock"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"}

# Flags that consume the following argument, per launcher, so we can find the package name.
UVX_VALUED = {"--from", "--with", "--python", "-p", "--index-url", "--extra-index-url", "--with-requirements"}
DOCKER_VALUED = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net",
                 "-w", "--workdir", "--entrypoint", "-u", "--user", "--env-file", "--mount",
                 "--add-host", "--label", "-l", "--platform", "--cap-add", "--cap-drop", "-m", "--memory"}


def scan_config(servers: Dict[str, dict], file: str = "") -> List[Finding]:
    findings: List[Finding] = []
    for name, raw in servers.items():
        s = normalize_server(raw)
        for check in (_secrets, _unpinned, _pipe_to_shell, _insecure_transport,
                      _broad_filesystem, _container_options, _auto_approve):
            findings.extend(check(name, s, file))
    return findings


def normalize_server(server: dict) -> dict:
    """Return a copy with predictable types: command str, args list[str], env/headers dict[str, str]."""
    s = dict(server)
    command = s.get("command")
    if isinstance(command, dict):  # Zed-style {"command": {"path": ..., "args": [...]}}
        s.setdefault("args", command.get("args", []))
        s.setdefault("env", command.get("env", {}))
        command = command.get("path", "")
    s["command"] = str(command or "")

    args = s.get("args") or []
    s["args"] = [str(a) for a in args] if isinstance(args, list) else [str(args)]

    # Some configs put the whole command line into "command".
    if not s["args"] and " " in s["command"] and not os.path.exists(s["command"]):
        try:
            parts = shlex.split(s["command"])
            s["command"], s["args"] = parts[0], parts[1:]
        except ValueError:
            pass

    for key in ("env", "headers"):
        value = s.get(key) or {}
        s[key] = {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}
    s["url"] = str(s.get("url") or s.get("serverUrl") or s.get("httpUrl") or "")
    return s


# --- CF001 -----------------------------------------------------------------

def _secrets(name: str, s: dict, file: str) -> Iterator[Finding]:
    for location, key, value in _secret_candidates(s):
        label = _classify_secret(key, value)
        if label:
            yield Finding(CF001, name, f"hardcoded {label} in {location}", location, _mask(value), file)

    if s["url"]:
        parsed = urlparse(s["url"])
        if parsed.password:
            yield Finding(CF001, name, "password embedded in server URL", "url", _mask(parsed.password), file)
        for key, values in parse_qs(parsed.query).items():
            if SECRET_KEY_NAME.search(key) and values and _classify_secret(key, values[0]):
                yield Finding(CF001, name, f"secret in URL query parameter '{key}'", "url",
                              _mask(values[0]), file)


def _secret_candidates(s: dict) -> Iterator[Tuple[str, str, str]]:
    for key, value in s["env"].items():
        yield f"env.{key}", key, value
    for key, value in s["headers"].items():
        yield f"headers.{key}", key, value

    args = s["args"]
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-") and "=" in arg:
            key, value = arg.split("=", 1)
            yield f"args[{i}]", key, value
        elif arg.startswith("-") and SECRET_KEY_NAME.search(arg) and i + 1 < len(args):
            yield f"args[{i + 1}]", arg, args[i + 1]
            skip_next = True
        else:
            yield f"args[{i}]", "", arg


def _classify_secret(key: str, value: str) -> Optional[str]:
    """Return a label if `value` looks like a real secret, otherwise None."""
    value = value.strip()
    if not value or "${" in value or value.startswith("$") or PLACEHOLDER.search(value):
        return None
    for label, pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(value):
            return label
    if not key or not SECRET_KEY_NAME.search(key):
        return None
    core = AUTH_SCHEME.sub("", value)
    looks_like_path_or_url = core.startswith(("/", "~", "./", "../")) or "://" in core or re.match(r"^[A-Za-z]:\\", core)
    if (len(core) >= 12 and " " not in core and not looks_like_path_or_url
            and any(c.isdigit() for c in core) and any(c.isalpha() for c in core)):
        return "secret"
    return None


def _mask(value: str) -> str:
    value = value.strip()
    return "****" if len(value) <= 8 else f"{value[:4]}**** ({len(value)} chars)"


# --- CF002 -----------------------------------------------------------------

def _unpinned(name: str, s: dict, file: str) -> Iterator[Finding]:
    base, args = _base(s["command"]), s["args"]
    if base in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        base, args = "npx", args[1:]

    spec, ecosystem = None, None
    if base in ("npx", "bunx"):
        spec, ecosystem = _npx_spec(args), "npm"
    elif base == "uvx":
        spec, ecosystem = _value_after(args, "--from") or _first_positional(args, UVX_VALUED), "pypi"
    elif base == "pipx" and args[:1] == ["run"]:
        spec, ecosystem = _value_after(args, "--spec") or _first_positional(args[1:], {"--spec", "--python"}), "pypi"
    elif base in ("docker", "podman") and "run" in args:
        spec, ecosystem = _first_positional(args[args.index("run") + 1:], DOCKER_VALUED), "image"

    if not spec or _is_local(spec):
        return
    pinned = {"npm": _npm_pinned, "pypi": _pypi_pinned, "image": _image_pinned}[ecosystem](spec)
    if not pinned:
        what = "image" if ecosystem == "image" else "package"
        yield Finding(CF002, name, f"{what} '{spec}' is not pinned to a fixed version", "args",
                      " ".join([s["command"], *s["args"]])[:160], file)


def _npx_spec(args: List[str]) -> Optional[str]:
    explicit = _value_after(args, "-p") or _value_after(args, "--package")
    if explicit:
        return explicit
    for arg in args:
        if arg.startswith("--package="):
            return arg.split("=", 1)[1]
    return _first_positional(args, {"-c", "--call"})


def _npm_pinned(spec: str) -> bool:
    bare = spec[1:] if spec.startswith("@") else spec  # scoped: @scope/pkg@1.2.3
    if "@" not in bare:
        return False
    version = bare.rsplit("@", 1)[1]
    return bool(version) and version not in ("latest", "next") and not version.startswith(("^", "~", ">", "*"))


def _pypi_pinned(spec: str) -> bool:
    if "==" in spec:
        return True
    return bool(re.search(r"@v?\d", spec))


def _image_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]
    return ":" in last and not last.endswith(":latest")


def _is_local(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "file:", "git+", "github:", "http")) or "\\" in spec


# --- CF003 / CF004 / CF005 ---------------------------------------------------

def _pipe_to_shell(name: str, s: dict, file: str) -> Iterator[Finding]:
    line = " ".join([s["command"], *s["args"]])
    m = PIPE_TO_SHELL.search(line)
    if m:
        yield Finding(CF003, name, "downloads a script and runs it in a shell on every start", "args",
                      m.group(0)[:160], file)


def _insecure_transport(name: str, s: dict, file: str) -> Iterator[Finding]:
    candidates = [("url", s["url"])] if s["url"] else []
    candidates += [(f"args[{i}]", a) for i, a in enumerate(s["args"]) if re.match(r"^(?:http|ws)://", a, re.I)]
    for location, url in candidates:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme.lower() in ("http", "ws") and host not in LOCAL_HOSTS and not host.endswith(".localhost"):
            yield Finding(CF004, name, f"connects to {host} without TLS", location, url[:160], file)


def _broad_filesystem(name: str, s: dict, file: str) -> Iterator[Finding]:
    if _base(s["command"]) in ("docker", "podman"):
        return  # container mounts are handled by CF006
    home = _strip_sep(os.path.expanduser("~"))
    broad = {_strip_sep(p) for p in BROAD_PATHS} | {home}
    for i, arg in enumerate(s["args"]):
        if arg and _strip_sep(arg) in broad:
            yield Finding(CF005, name, f"server is given access to '{arg}'", f"args[{i}]", arg, file)


# --- CF006 / CF007 -----------------------------------------------------------

def _container_options(name: str, s: dict, file: str) -> Iterator[Finding]:
    if _base(s["command"]) not in ("docker", "podman"):
        return
    args = s["args"]
    if "--privileged" in args:
        yield Finding(CF006, name, "container runs with --privileged (full host access)", "args", "--privileged", file)

    for i, arg in enumerate(args):
        mount = None
        if arg in ("-v", "--volume") and i + 1 < len(args):
            mount = args[i + 1]
        elif arg.startswith(("-v=", "--volume=")):
            mount = arg.split("=", 1)[1]
        if mount:
            host_path = mount.split(":", 1)[0]
            if host_path in SENSITIVE_MOUNTS or "docker.sock" in host_path:
                why = ("mounts the Docker socket (equivalent to root on the host)" if "docker.sock" in host_path
                       else f"mounts sensitive host path '{host_path}'")
                yield Finding(CF006, name, why, f"args[{i}]", mount, file)

        if arg in ("--network=host", "--net=host") or (arg in ("--network", "--net") and args[i + 1:i + 2] == ["host"]):
            yield Finding(CF006, name, "container shares the host network", f"args[{i}]", "host network",
                          file, Severity.MEDIUM)

        cap = arg.split("=", 1)[1] if arg.startswith("--cap-add=") else (
            args[i + 1] if arg == "--cap-add" and i + 1 < len(args) else None)
        if cap and cap.upper() in DANGEROUS_CAPS:
            yield Finding(CF006, name, f"container is granted capability {cap.upper()}", f"args[{i}]", cap, file)


def _auto_approve(name: str, s: dict, file: str) -> Iterator[Finding]:
    for key in ("alwaysAllow", "autoApprove", "autoApproveTools"):
        value = s.get(key)
        if isinstance(value, list) and value:
            shown = ", ".join(map(str, value[:5])) + (" ..." if len(value) > 5 else "")
            yield Finding(CF007, name, f"{len(value)} tool(s) run without asking", key, shown, file)
        elif value is True:
            yield Finding(CF007, name, "every tool runs without asking", key, "true", file)
    if s.get("trust") is True:  # Gemini CLI: bypasses all confirmations for this server
        yield Finding(CF007, name, "server is trusted, so every tool runs without asking", "trust", "true", file)


# --- helpers -----------------------------------------------------------------

def _base(command: str) -> str:
    base = re.split(r"[\\/]", command)[-1].lower()
    for suffix in (".cmd", ".exe", ".bat"):
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def _first_positional(args: List[str], valued: set) -> Optional[str]:
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in valued:
            skip = True
        elif not arg.startswith("-"):
            return arg
    return None


def _value_after(args: List[str], flag: str) -> Optional[str]:
    if flag in args:
        i = args.index(flag)
        if i + 1 < len(args):
            return args[i + 1]
    return None


def _strip_sep(path: str) -> str:
    stripped = path.rstrip("/\\")
    return stripped or path[:1]  # keep "/" as "/"
