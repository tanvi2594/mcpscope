"""A minimal MCP client for the stdio transport, used to fetch live tool definitions.

The stdio transport is newline-delimited JSON-RPC 2.0 over the server's stdin/stdout.
The handshake is:
    client -> initialize            (request)
    server -> result                (capabilities, server info)
    client -> notifications/initialized
    client -> tools/list            (request, repeated while the result has a nextCursor)
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
from typing import Dict, List, Optional

from . import __version__

PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 50


class LiveError(Exception):
    """Raised when a server cannot be started or does not speak MCP as expected."""


class StdioClient:
    def __init__(self, command: str, args: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None, timeout: float = 20.0) -> None:
        executable = shutil.which(command) or command
        full_env = os.environ.copy()
        full_env.update({str(k): str(v) for k, v in (env or {}).items()})
        try:
            self.proc = subprocess.Popen(
                [executable, *(args or [])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=full_env, text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
        except OSError as exc:
            raise LiveError(f"could not start {command!r}: {exc}") from exc
        self.timeout = timeout
        self._next_id = 0
        self._lines: "queue.Queue[Optional[str]]" = queue.Queue()
        # Read stdout on a background thread so every wait can have a timeout.
        threading.Thread(target=self._pump, daemon=True).start()

    def __enter__(self) -> "StdioClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)  # end of stream

    def _send(self, message: dict) -> None:
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write(json.dumps(message) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LiveError(f"server stopped accepting input: {exc}") from exc

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def request(self, method: str, params: Optional[dict] = None) -> dict:
        self._next_id += 1
        request_id = self._next_id
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LiveError(f"timed out after {self.timeout:.0f}s waiting for {method}")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise LiveError(f"timed out after {self.timeout:.0f}s waiting for {method}") from None
            if line is None:
                raise LiveError(f"server exited before answering {method}")
            try:
                reply = json.loads(line)
            except json.JSONDecodeError:
                continue  # some servers print log lines to stdout; skip them
            if not isinstance(reply, dict):
                continue
            if "method" in reply:
                # A request or notification from the server. We support no client
                # features, so politely refuse requests instead of leaving them hanging.
                if "id" in reply:
                    self._send({"jsonrpc": "2.0", "id": reply["id"],
                                "error": {"code": -32601, "message": "Method not found"}})
                continue
            if reply.get("id") != request_id:
                continue
            if "error" in reply:
                error = reply["error"]
                detail = error.get("message", error) if isinstance(error, dict) else error
                raise LiveError(f"{method} failed: {detail}")
            result = reply.get("result")
            return result if isinstance(result, dict) else {}

    def initialize(self) -> dict:
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpscope", "version": __version__},
        })
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> List[dict]:
        tools: List[dict] = []
        cursor = None
        for _ in range(MAX_PAGES):
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(t for t in result.get("tools", []) if isinstance(t, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def fetch_tools(command: str, args: Optional[List[str]] = None,
                env: Optional[Dict[str, str]] = None, timeout: float = 20.0) -> List[dict]:
    """Start a stdio MCP server, run the handshake, and return its tool definitions."""
    with StdioClient(command, args, env, timeout) as client:
        info = client.initialize()
        if "tools" not in (info.get("capabilities") or {}):
            return []
        return client.list_tools()
