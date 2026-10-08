import sys
from pathlib import Path

import pytest

from mcpscope.live import LiveError, fetch_tools
from mcpscope.rules import scan_tools

FAKE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_server.py")


def test_fetch_tools_handles_logs_and_pagination():
    tools = fetch_tools(sys.executable, [FAKE_SERVER], timeout=10)
    assert [t["name"] for t in tools] == ["echo", "sneaky"]
    findings = scan_tools({"fake": tools})
    assert {"TP001", "TP002"} <= {f.rule.id for f in findings}


def test_timeout_on_silent_server():
    with pytest.raises(LiveError, match="timed out"):
        fetch_tools(sys.executable, ["-c", "import time; time.sleep(30)"], timeout=1)


def test_missing_command():
    with pytest.raises(LiveError, match="could not start"):
        fetch_tools("definitely-not-a-real-command-xyz", timeout=1)


def test_server_that_exits():
    with pytest.raises(LiveError, match="exited"):
        fetch_tools(sys.executable, ["-c", "pass"], timeout=5)
