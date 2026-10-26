"""Public OAuth boundary tests without contacting Google."""

import asyncio
import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from mcp.shared.auth import OAuthClientInformationFull
from starlette.testclient import TestClient

from google_auth_provider import GoogleAuthProvider, MCP_SCOPE
from test_gsc_server import _load_module


@pytest.fixture
def public_config(tmp_path):
    url = "https://gsc-mcp.agregated.com.au/mcp"
    secrets = tmp_path / "google-web.json"
    secrets.write_text(json.dumps({"web": {
        "client_id": "google-client", "client_secret": "google-secret",
        "redirect_uris": ["https://gsc-mcp.agregated.com.au/google/callback"],
    }}))
    return {
        "MCP_TRANSPORT": "streamable-http", "MCP_PUBLIC_URL": url,
        "MCP_GOOGLE_CLIENT_SECRETS_FILE": str(secrets),
        "MCP_ALLOWED_EMAILS": "alice@example.com,bob@example.com",
        "MCP_TOKEN_DB": str(tmp_path / "auth.sqlite3"),
        "MCP_TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "GSC_CONFIG_DIR": str(tmp_path),
    }


def test_public_endpoint_requires_token_and_dcr_works(public_config, monkeypatch):
    for key, value in public_config.items():
        monkeypatch.setenv(key, value)
    server = _load_module(public_config)
    monkeypatch.setenv("MCP_HOST", "0.0.0.0")
    server.configure_http()
    with TestClient(server.mcp.streamable_http_app(), base_url="https://gsc-mcp.agregated.com.au") as client:
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert response.status_code == 401
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == public_config["MCP_PUBLIC_URL"]
        registration = client.post("/register", json={
            "redirect_uris": ["http://127.0.0.1:54321/callback"],
            "client_name": "Codex test", "token_endpoint_auth_method": "none",
        })
        assert registration.status_code == 201
        assert registration.json()["scope"] == MCP_SCOPE


def test_complete_google_to_mcp_login(public_config, monkeypatch):
    for key, value in public_config.items():
        monkeypatch.setenv(key, value)
    server = _load_module(public_config)
    server.configure_http()
    verifier = "v" * 50
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    with TestClient(server.mcp.streamable_http_app(), base_url="https://gsc-mcp.agregated.com.au") as client:
        registration = client.post("/register", json={
            "redirect_uris": ["http://127.0.0.1:54321/callback"],
            "client_name": "Codex test", "token_endpoint_auth_method": "none",
        }).json()
        authorization = client.get("/authorize", params={
            "response_type": "code", "client_id": registration["client_id"],
            "redirect_uri": "http://127.0.0.1:54321/callback",
            "code_challenge": challenge, "code_challenge_method": "S256",
            "state": "client-state", "resource": public_config["MCP_PUBLIC_URL"],
        }, follow_redirects=False)
        assert authorization.status_code == 302
        google_state = parse_qs(urlparse(authorization.headers["location"]).query)["state"][0]
        google_tokens = {
            "access_token": "google-access", "refresh_token": "google-refresh",
            "expires_in": 3600, "scope": "openid email https://www.googleapis.com/auth/webmasters.readonly",
        }
        with patch.object(server.AUTH_PROVIDER, "_google_exchange", return_value=("google-a", "alice@example.com", google_tokens)):
            callback = client.get("/google/callback", params={"state": google_state, "code": "google-code"})
        assert callback.status_code == 200
        approval = callback.text.split('name="approval" value="')[1].split('"')[0]
        allowed = client.post("/google/approve", data={"approval": approval}, follow_redirects=False)
        assert allowed.status_code == 302
        redirect = urlparse(allowed.headers["location"])
        assert redirect.hostname == "127.0.0.1"
        assert parse_qs(redirect.query)["state"] == ["client-state"]
        mcp_code = parse_qs(redirect.query)["code"][0]
        token = client.post("/token", data={
            "grant_type": "authorization_code", "client_id": registration["client_id"],
            "code": mcp_code, "code_verifier": verifier,
            "redirect_uri": "http://127.0.0.1:54321/callback",
        })
        assert token.status_code == 200, token.text
        bearer = token.json()["access_token"]
        assert client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        }, headers={"authorization": "Bearer " + bearer, "accept": "application/json, text/event-stream"}).status_code == 200
        service = MagicMock()
        service.sites().list().execute.return_value = {"siteEntry": []}
        with patch.object(server.AUTH_PROVIDER, "get_service", return_value=service) as get_service:
            tool_call = client.post("/mcp", json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "list_properties", "arguments": {}},
            }, headers={"authorization": "Bearer " + bearer, "accept": "application/json, text/event-stream"})
        assert tool_call.status_code == 200
        assert tool_call.json()["result"].get("isError") is not True
        get_service.assert_called_once_with("google-a")
        assert client.post("/token", data={
            "grant_type": "authorization_code", "client_id": registration["client_id"],
            "code": mcp_code, "code_verifier": verifier,
            "redirect_uri": "http://127.0.0.1:54321/callback",
        }).status_code == 400


def test_google_accounts_are_isolated_and_refresh_rotates(public_config):
    provider = GoogleAuthProvider(
        public_config["MCP_PUBLIC_URL"], public_config["MCP_GOOGLE_CLIENT_SECRETS_FILE"],
        public_config["MCP_ALLOWED_EMAILS"], public_config["MCP_TOKEN_DB"],
        public_config["MCP_TOKEN_ENCRYPTION_KEY"],
    )
    client = OAuthClientInformationFull(
        client_id="codex", redirect_uris=["http://127.0.0.1:54321/callback"],
        scope=MCP_SCOPE, token_endpoint_auth_method="none",
    )
    asyncio.run(provider.register_client(client))
    for subject, email in [("google-a", "alice@example.com"), ("google-b", "bob@example.com")]:
        provider._put("google", subject, {
            "email": email,
            "credentials": provider.fernet.encrypt(json.dumps({
                "token": subject, "refresh_token": "refresh-" + subject,
                "expiry": time.time() + 3600,
            }).encode()).decode(),
        })
    alice = provider._issue("codex", "google-a", [MCP_SCOPE])
    bob = provider._issue("codex", "google-b", [MCP_SCOPE])
    assert asyncio.run(provider.load_access_token(alice.access_token)).subject == "google-a"
    assert asyncio.run(provider.load_access_token(bob.access_token)).subject == "google-b"
    with patch("google_auth_provider.build", side_effect=lambda *args, **kwargs: kwargs["credentials"].token):
        assert provider.get_service("google-a") == "google-a"
        assert provider.get_service("google-b") == "google-b"
    old = asyncio.run(provider.load_refresh_token(client, alice.refresh_token))
    rotated = asyncio.run(provider.exchange_refresh_token(client, old, [MCP_SCOPE]))
    assert asyncio.run(provider.load_refresh_token(client, alice.refresh_token)) is None
    assert asyncio.run(provider.load_access_token(alice.access_token)) is None
    assert asyncio.run(provider.load_access_token(rotated.access_token)).subject == "google-a"
    provider.allowed_emails.remove("alice@example.com")
    assert asyncio.run(provider.load_access_token(rotated.access_token)) is None
    with pytest.raises(PermissionError):
        provider.get_service("google-a")


def test_public_mode_never_uses_local_credentials(public_config, monkeypatch):
    for key, value in public_config.items():
        monkeypatch.setenv(key, value)
    server = _load_module(public_config)
    with patch.object(server, "get_access_token", return_value=None), \
         patch.object(server, "get_gsc_service_oauth") as local_oauth:
        with pytest.raises(PermissionError, match="authenticated"):
            server.get_gsc_service()
    local_oauth.assert_not_called()


def test_public_mode_fails_closed_without_settings(public_config, monkeypatch):
    monkeypatch.delenv("MCP_ALLOWED_EMAILS", raising=False)
    config = {key: value for key, value in public_config.items() if key != "MCP_ALLOWED_EMAILS"}
    with pytest.raises(ValueError, match="MCP_ALLOWED_EMAILS"):
        _load_module(config)
