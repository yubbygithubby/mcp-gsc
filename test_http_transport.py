"""Protocol-level HTTP tests; Google calls are mocked and no login is needed."""
import asyncio
import json
import threading
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from test_gsc_server import _load_module


READ_TOOLS = {
    "get_capabilities", "list_properties", "get_site_details",
    "get_search_analytics", "get_performance_overview", "compare_search_periods",
    "get_search_by_page_query", "get_advanced_search_analytics",
    "inspect_url_enhanced", "batch_url_inspection", "check_indexing_issues",
    "get_sitemaps", "list_sitemaps_enhanced", "get_sitemap_details",
    "manage_sitemaps", "get_creator_info",
}


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("GSC_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*")
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "http://127.0.0.1:*")
    return _load_module({"MCP_TRANSPORT": "streamable-http"})


@pytest.fixture
def client(server):
    server.configure_http()
    with TestClient(server.mcp.streamable_http_app(), base_url="http://127.0.0.1:3001") as client:
        client.headers["accept"] = "application/json, text/event-stream"
        yield client


def rpc(client, method, params=None):
    return client.post("/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params or {},
    })


def test_initialize_discover_and_call(client, server):
    response = rpc(client, "initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "copilot-cowork", "version": "1.0"},
    })
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "mcp-session-id" not in response.headers
    initialized = response.json()["result"]
    assert "tools" in initialized["capabilities"]
    client.headers["mcp-protocol-version"] = initialized["protocolVersion"]
    response = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response.status_code == 202

    response = rpc(client, "tools/list")
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == READ_TOOLS
    assert all(tool["annotations"]["readOnlyHint"] for tool in tools)
    assert all(tool["annotations"]["destructiveHint"] is False for tool in tools)

    service = MagicMock()
    service.sites().list().execute.return_value = {
        "siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}],
    }
    with patch.object(server, "get_gsc_service", return_value=service):
        response = rpc(client, "tools/call", {"name": "list_properties", "arguments": {}})
    result = response.json()["result"]
    assert result.get("isError", False) is False
    data = json.loads(result["content"][0]["text"])
    assert data["properties"][0]["site_url"] == "sc-domain:example.com"


@pytest.mark.parametrize("name", [
    "add_site", "delete_site", "submit_sitemap", "delete_sitemap", "reauthenticate",
])
def test_write_and_account_tools_cannot_be_called(client, server, monkeypatch, name):
    monkeypatch.setenv("GSC_ALLOW_DESTRUCTIVE", "true")
    with patch.object(server, "get_gsc_service") as get_service:
        result = rpc(client, "tools/call", {"name": name, "arguments": {}}).json()["result"]
    assert result["isError"] is True
    get_service.assert_not_called()


@pytest.mark.parametrize("action", ["submit", "delete", " SUBMIT ", " DELETE "])
def test_sitemap_manager_rejects_writes(client, server, action):
    with patch.object(server, "get_gsc_service") as get_service:
        response = rpc(client, "tools/call", {
            "name": "manage_sitemaps", "arguments": {
                "site_url": "https://example.com/", "action": action,
                "sitemap_url": "https://example.com/sitemap.xml",
            },
        })
    assert "Invalid action" in response.json()["result"]["content"][0]["text"]
    get_service.assert_not_called()


@pytest.mark.parametrize("action", ["list", "details"])
def test_sitemap_manager_reads(client, server, action):
    service = MagicMock()
    service.sitemaps().list().execute.return_value = {"sitemap": []}
    service.sitemaps().get().execute.return_value = {"path": "https://example.com/sitemap.xml"}
    with patch.object(server, "get_gsc_service", return_value=service):
        result = rpc(client, "tools/call", {
            "name": "manage_sitemaps", "arguments": {
                "site_url": "https://example.com/", "action": action,
                "sitemap_url": "https://example.com/sitemap.xml",
            },
        }).json()["result"]
    assert result.get("isError", False) is False
    if action == "list":
        assert "No sitemaps" in result["content"][0]["text"]
    else:
        assert json.loads(result["content"][0]["text"])["sitemap_url"] == "https://example.com/sitemap.xml"
    service.sitemaps().submit.assert_not_called()
    service.sitemaps().delete.assert_not_called()


def test_capabilities_matches_discovery(client, server):
    with patch.object(server, "get_gsc_service", side_effect=RuntimeError("Login required")):
        response = rpc(client, "tools/call", {"name": "get_capabilities", "arguments": {}})
    data = json.loads(response.json()["result"]["content"][0]["text"])
    assert data["mode"] == "read_only"
    assert data["auth_status"] == "not_authenticated"
    assert {tool["name"] for tool in data["tools"]} == READ_TOOLS


def test_remote_missing_token_does_not_open_browser(server, tmp_path):
    with patch.object(server, "TOKEN_FILE", str(tmp_path / "missing-token.json")), \
         patch.object(server, "InstalledAppFlow") as flow:
        with pytest.raises(RuntimeError, match="locally"):
            server.get_gsc_service_oauth()
    flow.from_client_secrets_file.assert_not_called()
    assert server.SCOPES == ["https://www.googleapis.com/auth/webmasters.readonly"]


def test_remote_refresh_failure_does_not_open_browser(server, tmp_path):
    token = tmp_path / "expired-token.json"
    token.write_text("{}")
    creds = MagicMock(valid=False, expired=True, refresh_token="expired-refresh-token")
    creds.refresh.side_effect = RuntimeError("Revoked")
    with patch.object(server, "TOKEN_FILE", str(token)), \
         patch.object(server.Credentials, "from_authorized_user_file", return_value=creds), \
         patch.object(server, "InstalledAppFlow") as flow:
        with pytest.raises(RuntimeError, match="locally"):
            server.get_gsc_service_oauth()
    flow.from_client_secrets_file.assert_not_called()


def test_host_and_origin_checks(client):
    assert client.post("/mcp", json={}, headers={"host": "attacker.example"}).status_code == 421
    assert client.post("/mcp", json={}, headers={"origin": "https://attacker.example"}).status_code == 403


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.1", "gsc-mcp.agregated.com.au"])
def test_nonlocal_bind_rejected(server, monkeypatch, host):
    monkeypatch.setenv("MCP_HOST", host)
    with pytest.raises(ValueError, match="Public HTTP binding"):
        server.configure_http()


def test_no_legacy_sse_routes(client):
    assert client.get("/sse").status_code == 404
    assert client.post("/messages/", json={}).status_code == 404


def test_google_call_does_not_block_other_http_work(server):
    release = threading.Event()
    service = MagicMock()
    service.sites().list().execute.side_effect = lambda: (release.wait(0.5) and {"siteEntry": []})

    async def check():
        task = asyncio.create_task(server.list_properties())
        await asyncio.sleep(0.02)
        assert not task.done(), "A blocking Google request stalled the event loop"
        release.set()
        await task

    timer = threading.Timer(0.2, release.set)
    timer.start()
    try:
        with patch.object(server, "get_gsc_service", return_value=service):
            asyncio.run(check())
    finally:
        release.set()
        timer.join()


@pytest.mark.parametrize("transport,expected", [
    ("stdio", "stdio"), ("streamable-http", "streamable-http"), ("http", "streamable-http"),
])
def test_entrypoint_transport(server, transport, expected):
    with patch.object(server, "TRANSPORT", transport), patch.object(server.mcp, "run") as run:
        server.main([])
    run.assert_called_once_with(transport=expected)


@pytest.mark.parametrize("transport", ["sse", "unknown"])
def test_unsupported_transport_fails(server, transport):
    with patch.object(server, "TRANSPORT", transport), pytest.raises(ValueError, match="MCP_TRANSPORT"):
        server.main([])


@pytest.mark.parametrize("port", ["abc", "0", "65536"])
def test_invalid_port_fails(server, monkeypatch, port):
    monkeypatch.setenv("MCP_PORT", port)
    with pytest.raises(ValueError, match="MCP_PORT"):
        server.main([])
