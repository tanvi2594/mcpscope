import json
from pathlib import Path

from mcpscope.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_tools_command_json(capsys):
    code = main(["tools", str(EXAMPLES / "poisoned_tools.json"), "-f", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    rules = {f["rule_id"] for f in report["findings"]}
    assert {"TP001", "TP002", "TP003", "TP004", "TP005", "TP006"} <= rules


def test_clean_examples_pass(capsys):
    assert main(["tools", str(EXAMPLES / "clean_tools.json")]) == 0
    assert main(["config", str(EXAMPLES / "safe_config.json")]) == 0
    assert "No findings." in capsys.readouterr().out


def test_risky_config_and_fail_on_none(capsys):
    assert main(["config", str(EXAMPLES / "risky_config.json")]) == 1
    out = capsys.readouterr().out
    for rule in ("CF001", "CF002", "CF003", "CF004", "CF005", "CF006", "CF007"):
        assert rule in out
    assert main(["config", str(EXAMPLES / "risky_config.json"), "--fail-on", "none"]) == 0


def test_sarif_output(tmp_path):
    out = tmp_path / "r.sarif"
    main(["config", str(EXAMPLES / "risky_config.json"), "-f", "sarif", "-o", str(out)])
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


def test_missing_file_is_usage_error(capsys):
    assert main(["config", "does-not-exist.json"]) == 2


def test_live_with_fake_server(tmp_path, capsys):
    import sys
    config = tmp_path / "mcp.json"
    fake = Path(__file__).parent / "fixtures" / "fake_server.py"
    config.write_text(json.dumps({"mcpServers": {"fake": {"command": sys.executable, "args": [str(fake)]}}}))
    code = main(["live", str(config), "-f", "json", "--save-tools", str(tmp_path / "tools.json")])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["scanned"]["tools"] == 2
    assert json.loads((tmp_path / "tools.json").read_text())["fake"]["tools"]
