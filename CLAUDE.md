# CLAUDE.md

Context for AI coding assistants (Claude, Cursor, Copilot, etc.) working in this repo.

## What this is

MCP server that connects Google Search Console to AI assistants.
Single file: `gsc_server.py` (~1,670 lines). Built with FastMCP — no custom framework.

## Running locally

```bash
uv sync
uv run python gsc_server.py
```

## Auth

Two modes, selected from the configured credentials:

1. **OAuth (default):** Place `client_secrets.json` in the repo root. On first local stdio run, a browser window opens for Google login. The token is saved in the user config directory and auto-refreshes when expired.
2. **Service account:** Set `GSC_CREDENTIALS_PATH` to the path of your service account JSON key file.

Set `GSC_SKIP_OAUTH=true` to force service account mode and skip OAuth entirely.

## Key environment variables

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Set to `streamable-http` for `/mcp` over HTTP (`http` is an alias) |
| `MCP_HOST` | `127.0.0.1` | Bind address; non-loopback requires public Google sign-in mode |
| `MCP_PORT` | `3001` | Port to bind when `MCP_TRANSPORT=streamable-http` |
| `GSC_DATA_STATE` | `all` | `all` = matches GSC dashboard; `final` = confirmed data only (2–3 day lag) |
| `MCP_ALLOWED_HOSTS` | loopback hosts | Comma-separated Host allowlist |
| `MCP_ALLOWED_ORIGINS` | loopback origins | Comma-separated Origin allowlist |
| `MCP_PUBLIC_URL` | — | HTTPS `/mcp` URL enabling Google sign-in and team access |
| `MCP_GOOGLE_CLIENT_SECRETS_FILE` | — | Google OAuth Web client JSON with `/google/callback` redirect |
| `MCP_ALLOWED_EMAILS` | — | Comma-separated allowed Google account emails |
| `MCP_TOKEN_DB` | — | Persistent private SQLite database for public OAuth |
| `MCP_TOKEN_ENCRYPTION_KEY` | — | Stable Fernet key for public OAuth data |
| `GSC_CREDENTIALS_PATH` | — | Path to service account JSON key file |
| `GSC_OAUTH_CLIENT_SECRETS_FILE` | `client_secrets.json` | Path to OAuth client secrets file |
| `GSC_SKIP_OAUTH` | `false` | Set `true` to skip OAuth and use service account only |

## Adding a new tool

1. Add an async function with `@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))`. Only read-only tools belong in this fork.
2. Use `await asyncio.to_thread(get_gsc_service)` for auth; it selects the configured credential type
3. Return `json.dumps(result)` not formatted text strings (LLMs work better with structured data)
4. Run blocking Google calls in a thread and return a plain string error message on failure

```python
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def my_new_tool(site_url: str) -> str:
    """One-line description shown to the AI as the tool's purpose."""
    try:
        service = await asyncio.to_thread(get_gsc_service)
        result = await asyncio.to_thread(service.someApi().someMethod(siteUrl=site_url).execute)
        return json.dumps(result)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error: {str(e)}"
```

## Running tests

```bash
uv sync --frozen --group dev
uv run --frozen pytest -q
```

No credentials needed — all Google API calls are mocked with `unittest.mock`.

## Fork constraints

GSC scope is `webmasters.readonly`. Write tools have been removed and `manage_sitemaps` only accepts `list`/`details`. Reauthentication is a local CLI command (`python gsc_server.py --reauthenticate`), never an MCP tool. Public HTTP authenticates each user through Google and issues separate MCP tokens; local HTTP remains loopback only. The HTTP transport is stateless with JSON responses at `/mcp`; legacy SSE is unsupported. Keep Host/Origin checks enabled. Public deployment needs TLS, the team email allowlist, a Google Web OAuth client, and persistent token storage.
