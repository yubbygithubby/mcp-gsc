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
from google.auth.exceptions import RefreshError
from mcp.server.auth.provider import TokenError
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
    stale_refresh = asyncio.run(provider.load_refresh_token(client, rotated.refresh_token))
    original_grant_allowed = provider._grant_allowed

    def reapprove_during_refresh(value):
        allowed = original_grant_allowed(value)
        user = provider._get("google", "google-a")
        user["grant"] = "new-approval"
        provider._put("google", "google-a", user)
        return allowed

    with patch.object(provider, "_grant_allowed", side_effect=reapprove_during_refresh):
        with pytest.raises(TokenError):
            asyncio.run(provider.exchange_refresh_token(client, stale_refresh, [MCP_SCOPE]))
    assert asyncio.run(provider.load_access_token(rotated.access_token)) is None
    assert asyncio.run(provider.load_access_token(provider._issue("codex", "google-a", [MCP_SCOPE]).access_token)) is not None
    provider.allowed_emails.remove("alice@example.com")
    assert asyncio.run(provider.load_access_token(rotated.access_token)) is None
    with pytest.raises(PermissionError):
        provider.get_service("google-a")


def test_revoked_google_grant_challenges_mcp_client(public_config, monkeypatch):
    for key, value in public_config.items():
        monkeypatch.setenv(key, value)
    server = _load_module(public_config)
    server.configure_http()
    provider = server.AUTH_PROVIDER
    provider._put("google", "google-a", {
        "email": "alice@example.com",
        "credentials": provider.fernet.encrypt(json.dumps({
            "token": "expired", "refresh_token": "revoked", "expiry": time.time() - 1,
        }).encode()).decode(),
    })
    old_tokens = provider._issue("copilot", "google-a", [MCP_SCOPE])
    bearer = old_tokens.access_token
    oauth_client = OAuthClientInformationFull(
        client_id="copilot", redirect_uris=["http://127.0.0.1/callback"],
        scope=MCP_SCOPE, token_endpoint_auth_method="none",
    )
    old_refresh = asyncio.run(provider.load_refresh_token(oauth_client, old_tokens.refresh_token))
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"authorization": "Bearer " + bearer, "accept": "application/json, text/event-stream"}
    with patch("google_auth_provider.Credentials.refresh", side_effect=RefreshError(
        "temporarily_unavailable", {"error": "temporarily_unavailable"},
    )):
        with pytest.raises(RefreshError):
            asyncio.run(provider.load_access_token(bearer))
    assert provider._get("google", "google-a") is not None
    with TestClient(server.mcp.streamable_http_app(), base_url="https://gsc-mcp.agregated.com.au") as client:
        with patch("google_auth_provider.Credentials.refresh", side_effect=RefreshError(
            "invalid_grant: Token has been expired or revoked", {"error": "invalid_grant"},
        )):
            response = client.post("/mcp", json=request, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
        assert 'resource_metadata="https://gsc-mcp.agregated.com.au/.well-known/oauth-protected-resource/mcp"' in response.headers["www-authenticate"]
        assert provider._get("google", "google-a") is None
        assert client.post("/mcp", json=request, headers=headers).status_code == 401
        provider._put("google", "google-a", {
            "email": "alice@example.com", "grant": "new-approval",
            "credentials": provider.fernet.encrypt(json.dumps({
                "token": "new-access", "refresh_token": "new-refresh", "expiry": time.time() + 3600,
            }).encode()).decode(),
        })
        assert client.post("/mcp", json=request, headers=headers).status_code == 401
        assert asyncio.run(provider.load_access_token(bearer)) is None
        assert asyncio.run(provider.load_refresh_token(oauth_client, old_tokens.refresh_token)) is None
        with pytest.raises(TokenError):
            asyncio.run(provider.exchange_refresh_token(oauth_client, old_refresh, [MCP_SCOPE]))
        assert asyncio.run(provider.load_access_token(provider._issue("copilot", "google-a", [MCP_SCOPE]).access_token)) is not None


def test_old_google_refresh_cannot_delete_new_approval(public_config):
    provider = GoogleAuthProvider(
        public_config["MCP_PUBLIC_URL"], public_config["MCP_GOOGLE_CLIENT_SECRETS_FILE"],
        public_config["MCP_ALLOWED_EMAILS"], public_config["MCP_TOKEN_DB"],
        public_config["MCP_TOKEN_ENCRYPTION_KEY"],
    )
    provider._put("google", "google-a", {
        "email": "alice@example.com", "grant": "old-approval",
        "credentials": provider.fernet.encrypt(json.dumps({
            "token": "old-access", "refresh_token": "revoked", "expiry": time.time() - 1,
        }).encode()).decode(),
    })
    old_token = provider._issue("copilot", "google-a", [MCP_SCOPE]).access_token

    def reapprove(_credentials, _request):
        provider._put("google", "google-a", {
            "email": "alice@example.com", "grant": "new-approval",
            "credentials": provider.fernet.encrypt(json.dumps({
                "token": "new-access", "refresh_token": "new-refresh", "expiry": time.time() + 3600,
            }).encode()).decode(),
        })
        raise RefreshError("invalid_grant", {"error": "invalid_grant"})

    with patch("google_auth_provider.Credentials.refresh", autospec=True, side_effect=reapprove):
        assert asyncio.run(provider.load_access_token(old_token)) is None
    assert provider._google_credentials("google-a").token == "new-access"
    assert asyncio.run(provider.load_access_token(provider._issue("copilot", "google-a", [MCP_SCOPE]).access_token)) is not None


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
