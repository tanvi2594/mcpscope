from mcpscope.loaders import extract_servers, loads_jsonc
from mcpscope.rules import scan_config


def ids(findings):
    return {f.rule.id for f in findings}


def scan(server):
    return scan_config({"s": server})


# Built at runtime so no realistic-looking token is ever committed to the repo.
FAKE_GITHUB_TOKEN = "gh" + "p_" + "A1b2C3d4E5" * 4


def test_hardcoded_secret_in_env():
    findings = scan({"command": "node", "args": ["x.js"], "env": {"SERVICE_API_KEY": "a8f3k29dLq0ZpX7vB1nM"}})
    assert "CF001" in ids(findings)
    assert "a8f3" in findings[0].evidence and "Lq0Z" not in findings[0].evidence  # masked


def test_known_token_shape_is_detected_anywhere():
    findings = scan({"command": "server", "args": ["--gh", FAKE_GITHUB_TOKEN]})
    assert any("GitHub token" in f.message for f in findings)


def test_references_and_placeholders_are_not_secrets():
    for value in ("${GITHUB_TOKEN}", "${input:token}", "$TOKEN", "your-api-key-here", "<token>", ""):
        assert "CF001" not in ids(scan({"command": "node", "env": {"API_TOKEN": value}})), value


def test_non_secret_values_under_secret_names():
    assert "CF001" not in ids(scan({"command": "node", "env": {"TOKEN_PATH": "/home/me/.config/tok1"}}))
    assert "CF001" not in ids(scan({"command": "node", "env": {"AUTH_TOKEN_TTL": "3600"}}))


def test_secret_in_url():
    assert "CF001" in ids(scan({"url": "https://api.example.com/mcp?api_key=Zx81kfP02mQa77LtY3"}))


def test_unpinned_npx():
    assert "CF002" in ids(scan({"command": "npx", "args": ["-y", "@scope/server-thing"]}))
    assert "CF002" in ids(scan({"command": "npx", "args": ["-y", "some-server@latest"]}))


def test_pinned_npx_scoped_and_unscoped():
    assert "CF002" not in ids(scan({"command": "npx", "args": ["-y", "@scope/server-thing@1.4.2"]}))
    assert "CF002" not in ids(scan({"command": "npx.cmd", "args": ["-y", "some-server@0.3.0"]}))


def test_uvx_and_docker_pinning():
    assert "CF002" in ids(scan({"command": "uvx", "args": ["mcp-server-fetch"]}))
    assert "CF002" not in ids(scan({"command": "uvx", "args": ["mcp-server-fetch==2025.1.17"]}))
    assert "CF002" in ids(scan({"command": "docker", "args": ["run", "-i", "-e", "X", "mcp/fetch"]}))
    assert "CF002" not in ids(scan({"command": "docker", "args": ["run", "-i", "mcp/fetch:1.2.0"]}))
    assert "CF002" not in ids(scan({"command": "docker", "args": ["run", "localhost:5000/img@sha256:abc"]}))


def test_local_scripts_are_not_packages():
    assert "CF002" not in ids(scan({"command": "npx", "args": ["./my-server.js"]}))


def test_pipe_to_shell():
    assert "CF003" in ids(scan({"command": "bash", "args": ["-c", "curl -fsSL https://x.sh | sh"]}))


def test_insecure_remote_url():
    assert "CF004" in ids(scan({"url": "http://tools.example.org/mcp"}))
    assert "CF004" in ids(scan({"command": "npx", "args": ["mcp-remote@0.1.0", "http://tools.example.org/sse"]}))
    assert "CF004" not in ids(scan({"url": "http://localhost:3000/mcp"}))
    assert "CF004" not in ids(scan({"url": "https://tools.example.org/mcp"}))


def test_broad_filesystem():
    assert "CF005" in ids(scan({"command": "npx", "args": ["-y", "fs@1.0.0", "/"]}))
    assert "CF005" in ids(scan({"command": "npx", "args": ["-y", "fs@1.0.0", "~"]}))
    assert "CF005" not in ids(scan({"command": "npx", "args": ["-y", "fs@1.0.0", "/home/me/notes"]}))


def test_dangerous_docker_options():
    findings = scan({"command": "docker", "args": [
        "run", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "--network", "host", "--cap-add=SYS_ADMIN", "img:1.0"]})
    messages = " ".join(f.message for f in findings if f.rule.id == "CF006")
    for expected in ("privileged", "Docker socket", "host network", "SYS_ADMIN"):
        assert expected in messages


def test_auto_approve():
    assert "CF007" in ids(scan({"command": "x", "alwaysAllow": ["run_command"]}))
    assert "CF007" in ids(scan({"command": "x", "trust": True}))
    assert "CF007" not in ids(scan({"command": "x", "alwaysAllow": []}))


def test_command_string_with_inline_args():
    assert "CF002" in ids(scan({"command": "npx -y @scope/server-thing"}))


def test_jsonc_and_client_formats():
    text = """{
      // comment
      "servers": {"a": {"command": "x", "args": ["http://not-a-comment"],},},
      /* block */
      "projects": {"/repo": {"mcpServers": {"b": {"command": "y"}}}}
    }"""
    servers = extract_servers(loads_jsonc(text))
    assert set(servers) == {"a", "b (/repo)"}
    assert servers["a"]["args"] == ["http://not-a-comment"]
