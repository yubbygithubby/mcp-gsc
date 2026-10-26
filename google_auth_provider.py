"""Google sign-in and per-user credentials for the public MCP transport."""

import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from urllib.parse import urlencode

import requests
from cryptography.fernet import Fernet
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
    RefreshToken, TokenError, construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

GOOGLE_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
MCP_SCOPE = "gsc.read"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


class GoogleAuthProvider:
    def __init__(self, public_url, client_secrets_path, allowed_emails, database_path, encryption_key):
        self.public_url = public_url.rstrip("/")
        self.origin = self.public_url.removesuffix("/mcp")
        with open(client_secrets_path, encoding="utf-8") as file:
            web = json.load(file)["web"]
        self.google_client_id = web["client_id"]
        self.google_client_secret = web["client_secret"]
        self.callback_url = self.origin + "/google/callback"
        if self.callback_url not in web.get("redirect_uris", []):
            raise ValueError(f"Google OAuth web client must include redirect URI {self.callback_url}")
        self.allowed_emails = {email.strip().lower() for email in allowed_emails.split(",") if email.strip()}
        if not self.allowed_emails:
            raise ValueError("MCP_ALLOWED_EMAILS must contain at least one email address")
        self.fernet = Fernet(encryption_key)
        self.database_path = database_path
        if not os.path.isdir(os.path.dirname(os.path.abspath(database_path))):
            raise ValueError("MCP_TOKEN_DB parent directory must exist")
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT, key TEXT, value BLOB NOT NULL, expires REAL, PRIMARY KEY(kind,key))")
            db.execute("CREATE INDEX IF NOT EXISTS records_expiry ON records(expires)")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.database_path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def _put(self, kind, key, value, expires=None):
        with self._db() as db:
            db.execute("DELETE FROM records WHERE expires < ?", (time.time(),))
            db.execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?)", (kind, key, self.fernet.encrypt(json.dumps(value).encode()), expires))

    def _get(self, kind, key):
        with self._db() as db:
            row = db.execute("SELECT value,expires FROM records WHERE kind=? AND key=?", (kind, key)).fetchone()
        return json.loads(self.fernet.decrypt(row[0])) if row and (row[1] is None or row[1] > time.time()) else None

    def _take(self, kind, key):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value,expires FROM records WHERE kind=? AND key=?", (kind, key)).fetchone()
            db.execute("DELETE FROM records WHERE kind=? AND key=?", (kind, key))
        return json.loads(self.fernet.decrypt(row[0])) if row and (row[1] is None or row[1] > time.time()) else None

    def _delete(self, kind, key):
        with self._db() as db:
            db.execute("DELETE FROM records WHERE kind=? AND key=?", (kind, key))

    async def get_client(self, client_id):
        value = self._get("client", client_id)
        return OAuthClientInformationFull.model_validate(value) if value else None

    async def register_client(self, client_info):
        self._put("client", client_info.client_id, client_info.model_dump(mode="json"))

    async def authorize(self, client, params: AuthorizationParams):
        if params.resource and params.resource.rstrip("/") != self.public_url:
            raise AuthorizeError("invalid_request", "Resource must be this MCP server")
        if params.scopes and MCP_SCOPE not in params.scopes:
            raise AuthorizeError("invalid_scope", f"Required scope: {MCP_SCOPE}")
        state = secrets.token_urlsafe(32)
        self._put("pending", _digest(state), {
            "client_id": client.client_id, "params": params.model_dump(mode="json"),
        }, time.time() + 600)
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
            "client_id": self.google_client_id,
            "redirect_uri": self.callback_url,
            "response_type": "code",
            "scope": "openid email " + GOOGLE_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        })

    def _google_exchange(self, code):
        response = requests.post(GOOGLE_TOKEN_URL, data={
            "code": code, "client_id": self.google_client_id,
            "client_secret": self.google_client_secret,
            "redirect_uri": self.callback_url, "grant_type": "authorization_code",
        }, timeout=20)
        response.raise_for_status()
        tokens = response.json()
        claims = id_token.verify_oauth2_token(tokens["id_token"], GoogleRequest(), self.google_client_id)
        if not claims.get("email_verified"):
            raise ValueError("Google email is not verified")
        email = claims["email"].lower()
        if email not in self.allowed_emails:
            raise PermissionError("This Google account is not allowed")
        if GOOGLE_SCOPE not in tokens.get("scope", "").split():
            raise PermissionError("Search Console read access was not granted")
        return claims["sub"], email, tokens

    async def google_callback(self, request: Request):
        state = request.query_params.get("state", "")
        pending = self._take("pending", _digest(state)) if state else None
        if not pending:
            return HTMLResponse("Sign-in request expired. Reconnect from your MCP client.", status_code=400)
        params = AuthorizationParams.model_validate(pending["params"])
        if request.query_params.get("error"):
            return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state), status_code=302)
        code = request.query_params.get("code")
        if not code:
            return HTMLResponse("Google did not return an authorization code.", status_code=400)
        try:
            import asyncio
            subject, email, tokens = await asyncio.to_thread(self._google_exchange, code)
        except (requests.RequestException, ValueError, KeyError, PermissionError):
            return HTMLResponse("Google sign-in failed or this account is not allowed.", status_code=403)
        # Store the Google refresh token only after an explicit final approval.
        approval = secrets.token_urlsafe(32)
        self._put("approval", _digest(approval), {
            "pending": pending, "subject": subject, "email": email, "tokens": tokens,
        }, time.time() + 600)
        client = await self.get_client(pending["client_id"])
        name = client.client_name if client and client.client_name else "MCP client"
        from html import escape
        return HTMLResponse(
            "<h1>Connect Search Console?</h1>"
            f"<p>{escape(name)} requests read-only access as {escape(email)}.</p>"
            f"<p>Return to: {escape(str(params.redirect_uri))}</p>"
            f"<p>It will receive access to properties visible to this Google account.</p>"
            f'<form method="post" action="/google/approve"><input type="hidden" name="approval" value="{approval}">'
            '<button type="submit">Allow connection</button></form>',
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    async def google_approve(self, request: Request):
        form = await request.form()
        approval = form.get("approval", "")
        data = self._take("approval", _digest(approval)) if isinstance(approval, str) and approval else None
        if not data:
            return HTMLResponse("Approval expired. Reconnect from your MCP client.", status_code=400)
        pending = data["pending"]
        params = AuthorizationParams.model_validate(pending["params"])
        subject, email, tokens = data["subject"], data["email"], data["tokens"]
        existing = self._get("google", subject)
        old_refresh = None
        if existing:
            old_refresh = json.loads(self.fernet.decrypt(existing["credentials"])).get("refresh_token")
        refresh = tokens.get("refresh_token") or old_refresh
        if not refresh:
            return HTMLResponse("Google did not grant offline access. Reconnect and approve access.", status_code=400)
        google_creds = {
            "token": tokens["access_token"], "refresh_token": refresh,
            "expiry": time.time() + int(tokens.get("expires_in", 3600)),
        }
        self._put("google", subject, {
            "email": email, "credentials": self.fernet.encrypt(json.dumps(google_creds).encode()).decode(),
        })
        auth_code = secrets.token_urlsafe(32)
        code_record = AuthorizationCode(
            code=auth_code, scopes=params.scopes or [MCP_SCOPE], expires_at=time.time() + 300,
            client_id=pending["client_id"], code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=self.public_url, subject=subject,
        )
        self._put("code", _digest(auth_code), code_record.model_dump(mode="json"), code_record.expires_at)
        return RedirectResponse(
            construct_redirect_uri(str(params.redirect_uri), code=auth_code, state=params.state),
            status_code=302, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    async def load_authorization_code(self, client, authorization_code):
        value = self._get("code", _digest(authorization_code))
        return AuthorizationCode.model_validate(value) if value and value["client_id"] == client.client_id else None

    def _issue(self, client_id, subject, scopes):
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = time.time()
        self._put("access", _digest(access), AccessToken(
            token=access, client_id=client_id, scopes=scopes, expires_at=int(now + 3600),
            resource=self.public_url, subject=subject,
        ).model_dump(mode="json"), now + 3600)
        self._put("refresh", _digest(refresh), RefreshToken(
            token=refresh, client_id=client_id, scopes=scopes, expires_at=int(now + 30 * 86400),
            subject=subject,
        ).model_dump(mode="json"), now + 30 * 86400)
        pair = {"access": _digest(access), "refresh": _digest(refresh)}
        self._put("pair", pair["access"], pair, now + 30 * 86400)
        self._put("pair", pair["refresh"], pair, now + 30 * 86400)
        return OAuthToken(access_token=access, refresh_token=refresh, expires_in=3600, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client, authorization_code):
        value = self._take("code", _digest(authorization_code.code))
        if not value or value["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "Authorization code was already used")
        return self._issue(client.client_id, value["subject"], value["scopes"])

    async def load_refresh_token(self, client, refresh_token):
        value = self._get("refresh", _digest(refresh_token))
        return RefreshToken.model_validate(value) if value and value["client_id"] == client.client_id else None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        value = self._take("refresh", _digest(refresh_token.token))
        if not value or value["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "Refresh token was already used")
        if not self._allowed(value["subject"]):
            raise TokenError("invalid_grant", "Account is no longer allowed")
        self._revoke_pair(_digest(refresh_token.token))
        return self._issue(client.client_id, value["subject"], scopes)

    def _allowed(self, subject):
        user = self._get("google", subject)
        return bool(user and user["email"] in self.allowed_emails)

    async def load_access_token(self, token):
        value = self._get("access", _digest(token))
        return AccessToken.model_validate(value) if value and self._allowed(value["subject"]) and value["resource"] == self.public_url else None

    async def revoke_token(self, token):
        self._revoke_pair(_digest(token.token))

    def _revoke_pair(self, token_hash):
        pair = self._get("pair", token_hash)
        if pair:
            for kind in ("access", "refresh"):
                self._delete(kind, pair[kind])
                self._delete("pair", pair[kind])

    def get_service(self, subject):
        user = self._get("google", subject)
        if not user or user["email"] not in self.allowed_emails:
            raise PermissionError("This Google account is no longer allowed")
        saved = json.loads(self.fernet.decrypt(user["credentials"]))
        creds = Credentials(
            token=saved["token"], refresh_token=saved["refresh_token"],
            token_uri=GOOGLE_TOKEN_URL, client_id=self.google_client_id,
            client_secret=self.google_client_secret, scopes=[GOOGLE_SCOPE],
        )
        if saved["expiry"] < time.time() + 60:
            creds.refresh(GoogleRequest())
            saved.update(token=creds.token, expiry=creds.expiry.timestamp())
            self._put("google", subject, {
                "email": user["email"],
                "credentials": self.fernet.encrypt(json.dumps(saved).encode()).decode(),
            })
        return build("searchconsole", "v1", credentials=creds, cache_discovery=False)
