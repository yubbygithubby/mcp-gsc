from typing import Any, Dict, List, Optional
from quota_usage import usage_report, execute_tracked, EFFICIENCY_INSTRUCTIONS
import argparse
import asyncio
import logging
import os
import json
import sys
import shutil
import tempfile
import threading
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# Fail loudly on unsupported Python. The mcp/FastMCP dependency requires 3.11+.
# On Python 3.10 or older the server dies during import, and when it is launched
# by a GUI client (e.g. Claude Desktop) that failure is silent — no tools appear
# and no log file is written, which is impossible to diagnose. See issue #19.
if sys.version_info < (3, 11):
    sys.exit(
        "mcp-gsc requires Python 3.11 or newer, but you are running "
        f"{sys.version_info.major}.{sys.version_info.minor}. "
        "Install Python 3.11+ (https://www.python.org/downloads/) and recreate "
        "your virtual environment, or use the uvx install method which manages "
        "the Python version for you."
    )

from platformdirs import user_config_dir

import google.auth
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Suppress the noisy file_cache warning from google-api-python-client.
# Some MCP hosts (e.g. GitHub Copilot CLI) treat any stderr output as a
# fatal error, so this prevents false crashes.
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)

# MCP
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request as StarletteRequest
from urllib.parse import urlparse

from google_auth_provider import GoogleAuthProvider, MCP_SCOPE

TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
IS_REMOTE = TRANSPORT != "stdio"
PUBLIC_URL = os.environ.get("MCP_PUBLIC_URL", "").strip()
if PUBLIC_URL:
    parsed_public_url = urlparse(PUBLIC_URL)
    if (TRANSPORT not in {"http", "streamable-http"} or parsed_public_url.scheme != "https"
            or not parsed_public_url.hostname or parsed_public_url.path != "/mcp"
            or parsed_public_url.query or parsed_public_url.fragment or parsed_public_url.username
            or parsed_public_url.password):
        raise ValueError("MCP_PUBLIC_URL must be an HTTPS URL ending in /mcp and requires HTTP transport")
    required = ["MCP_GOOGLE_CLIENT_SECRETS_FILE", "MCP_ALLOWED_EMAILS", "MCP_TOKEN_DB", "MCP_TOKEN_ENCRYPTION_KEY"]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError("Public mode requires " + ", ".join(missing))
    AUTH_PROVIDER = GoogleAuthProvider(
        PUBLIC_URL, os.environ["MCP_GOOGLE_CLIENT_SECRETS_FILE"],
        os.environ["MCP_ALLOWED_EMAILS"], os.environ["MCP_TOKEN_DB"],
        os.environ["MCP_TOKEN_ENCRYPTION_KEY"],
    )
    AUTH_SETTINGS = AuthSettings(
        issuer_url=f"{parsed_public_url.scheme}://{parsed_public_url.netloc}",
        resource_server_url=PUBLIC_URL,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[MCP_SCOPE], default_scopes=[MCP_SCOPE],
        ),
        required_scopes=[MCP_SCOPE],
    )
else:
    AUTH_PROVIDER = None
    AUTH_SETTINGS = None

# Stateless requests avoid session affinity when the server is eventually hosted.
# JSON responses are part of Streamable HTTP; legacy SSE endpoints are not used.
mcp = FastMCP(
    "gsc-server",
    instructions=EFFICIENCY_INSTRUCTIONS,
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
    auth_server_provider=AUTH_PROVIDER,
    auth=AUTH_SETTINGS,
)

if AUTH_PROVIDER:
    @mcp.custom_route("/google/callback", methods=["GET"])
    async def google_callback(request: StarletteRequest):
        return await AUTH_PROVIDER.google_callback(request)

    @mcp.custom_route("/google/approve", methods=["POST"])
    async def google_approve(request: StarletteRequest):
        return await AUTH_PROVIDER.google_approve(request)

def _expand_path(path: Optional[str]) -> Optional[str]:
    """Expand ``~`` and environment variables in a path, returning None for empty input.

    This lets users write ``GSC_CREDENTIALS_PATH=~/creds.json`` or
    ``GSC_CREDENTIALS_PATH=$HOME/creds.json`` without hitting silent lookup failures.
    """
    if not path:
        return None
    return os.path.expandvars(os.path.expanduser(path))


# Path to your service account JSON or user credentials JSON
# First check if GSC_CREDENTIALS_PATH environment variable is set
# Then try looking in the script directory and current working directory as fallbacks
GSC_CREDENTIALS_PATH = _expand_path(os.environ.get("GSC_CREDENTIALS_PATH"))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POSSIBLE_CREDENTIAL_PATHS = [
    GSC_CREDENTIALS_PATH,  # First try the environment variable if set
    os.path.join(SCRIPT_DIR, "service_account_credentials.json"),
    os.path.join(os.getcwd(), "service_account_credentials.json"),
    # Add any other potential paths here
]

# OAuth client secrets file path
OAUTH_CLIENT_SECRETS_FILE = _expand_path(os.environ.get("GSC_OAUTH_CLIENT_SECRETS_FILE"))
# Track whether the user explicitly set the env var (vs. using the SCRIPT_DIR fallback).
# Needed so get_gsc_service() can fail-fast when the explicit path is wrong, while
# leaving the fallback behavior unchanged for clone-install users.
GSC_OAUTH_CLIENT_SECRETS_FILE_EXPLICIT = OAUTH_CLIENT_SECRETS_FILE is not None
if not OAUTH_CLIENT_SECRETS_FILE:
    OAUTH_CLIENT_SECRETS_FILE = os.path.join(SCRIPT_DIR, "client_secrets.json")

# Token file path for storing OAuth tokens.
# Stored in the user config directory so it survives uvx updates (which replace SCRIPT_DIR).
# Override with GSC_CONFIG_DIR env var for Docker/power users.
_CONFIG_DIR = os.environ.get("GSC_CONFIG_DIR") or user_config_dir("mcp-gsc")
os.makedirs(_CONFIG_DIR, exist_ok=True)
TOKEN_FILE = os.path.join(_CONFIG_DIR, "token.json")

# Silently migrate token from old location (SCRIPT_DIR) on first run after upgrade.
# Existing users never need to re-authenticate.
_OLD_TOKEN = os.path.join(SCRIPT_DIR, "token.json")
if os.path.exists(_OLD_TOKEN) and not os.path.exists(TOKEN_FILE):
    shutil.move(_OLD_TOKEN, TOKEN_FILE)

# Environment variable to skip OAuth authentication
SKIP_OAUTH = os.environ.get("GSC_SKIP_OAUTH", "").lower() in ("true", "1", "yes")

# Data state for search analytics queries.
# "all"   → includes fresh/unconfirmed data, matches the GSC dashboard (default)
# "final" → only confirmed data, which lags 2-3 days behind the dashboard
_raw_data_state = os.environ.get("GSC_DATA_STATE", "all").lower().strip()
if _raw_data_state not in ("all", "final"):
    raise ValueError(
        f"Invalid GSC_DATA_STATE value '{_raw_data_state}'. "
        "Accepted values are 'all' (default, matches GSC dashboard) or 'final' (2-3 day lag)."
    )
DATA_STATE = _raw_data_state

SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]
_OAUTH_LOCK = threading.Lock()


def _date_range(days: int):
    if days < 1:
        raise ValueError("days must be at least 1")
    end = datetime.now(ZoneInfo("America/Los_Angeles")).date()
    return end - timedelta(days=days - 1), end


def _save_token(creds):
    """Replace the OAuth token only after the new credentials are safely written."""
    token_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(TOKEN_FILE), prefix="token-", suffix=".json", delete=False) as token:
            token_path = token.name
            token.write(creds.to_json())
        os.replace(token_path, TOKEN_FILE)
    finally:
        if token_path and os.path.exists(token_path):
            os.remove(token_path)

def get_gsc_service():
    """
    Returns an authorized Search Console service object.
    Uses OAuth when configured, otherwise a service account.
    """
    if AUTH_PROVIDER:
        access = get_access_token()
        if not access or not access.subject:
            raise PermissionError("An authenticated Google account is required")
        return AUTH_PROVIDER.get_service(access.subject)

    # Fail-fast if credential env vars are set but point to files that don't exist.
    # Without this, a typo'd or uvx-incompatible path would silently fall through to
    # SCRIPT_DIR/cwd fallbacks (which don't work under uvx) and emit a misleading
    # "file not found" error with no mention of the env var the user actually set.
    # We rely on the module-level captured values (GSC_CREDENTIALS_PATH,
    # GSC_OAUTH_CLIENT_SECRETS_FILE_EXPLICIT) rather than re-reading os.environ at
    # call time, because the env var may have been cleared by the caller after module
    # import (e.g. by test frameworks or MCP hosts that scope env vars narrowly).
    use_oauth = not SKIP_OAUTH and (
        os.path.exists(TOKEN_FILE)
        or os.path.exists(OAUTH_CLIENT_SECRETS_FILE)
        or GSC_OAUTH_CLIENT_SECRETS_FILE_EXPLICIT
    )
    if not use_oauth and GSC_CREDENTIALS_PATH and not os.path.exists(GSC_CREDENTIALS_PATH):
        raise FileNotFoundError(
            f"GSC_CREDENTIALS_PATH is set to {GSC_CREDENTIALS_PATH!r} but the file "
            f"does not exist. "
            f"If running via uvx, this MUST be an absolute path to your service account "
            f"credentials JSON file — placing the file in your project folder is not "
            f"sufficient because uvx runs the code from an internal cache directory."
        )
    if use_oauth and GSC_OAUTH_CLIENT_SECRETS_FILE_EXPLICIT and not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
        raise FileNotFoundError(
            f"GSC_OAUTH_CLIENT_SECRETS_FILE is set to {OAUTH_CLIENT_SECRETS_FILE!r} "
            f"but the file does not exist. "
            f"If running via uvx, this MUST be an absolute path to your OAuth "
            f"client_secrets.json file."
        )

    # A configured OAuth identity must not silently switch to a service account.
    if use_oauth:
        with _OAUTH_LOCK:
            return get_gsc_service_oauth()
    
    # Try service account authentication
    for cred_path in ([GSC_CREDENTIALS_PATH] if GSC_CREDENTIALS_PATH else POSSIBLE_CREDENTIAL_PATHS[1:]):
        if cred_path and os.path.exists(cred_path):
            creds = service_account.Credentials.from_service_account_file(
                cred_path, scopes=SCOPES
            )
            return build("searchconsole", "v1", credentials=creds, cache_discovery=False)
    
    # If we get here, none of the authentication methods worked.
    # Note: uvx users can't place files "in the script directory" because uvx runs
    # the code from ~/.cache/uv/archive-v0/<hash>/lib/python*/site-packages/ — an
    # internal cache they cannot reach. They must use env vars with absolute paths.
    raise FileNotFoundError(
        f"Authentication failed. Please either:\n"
        f"1. Set up OAuth by setting GSC_OAUTH_CLIENT_SECRETS_FILE to an absolute path, "
        f"or (for clone installs) placing a client_secrets.json file in the script "
        f"directory, then run 'python gsc_server.py --reauthenticate' locally "
        f"to complete authentication, or\n"
        f"2. Set GSC_CREDENTIALS_PATH to an absolute path, or (for clone installs) "
        f"place a service account credentials file in one of these locations: "
        f"{', '.join([p for p in POSSIBLE_CREDENTIAL_PATHS[1:] if p])}\n"
        f"\n"
        f"If you installed via uvx, the 'script directory' is an internal uv cache "
        f"that you cannot access — you MUST use the environment variables with "
        f"absolute paths."
    )

def get_gsc_service_oauth():
    """
    Returns an authorized Search Console service object using OAuth.
    """
    creds = None
    
    # Check if token file exists
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
            # If token file is corrupted, delete it
            if os.path.exists(TOKEN_FILE):
                os.remove(TOKEN_FILE)
            creds = None
    
    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                # Keep the old token if a transient refresh failure prevents login.
                creds = None
            else:
                _save_token(creds)
        
        # Start new OAuth flow if we don't have valid credentials
        if not creds or not creds.valid:
            if IS_REMOTE:
                raise RuntimeError(
                    "Google credentials are unavailable or expired. Complete Google login "
                    "locally with `python gsc_server.py --reauthenticate` before starting "
                    "the local HTTP server. Public mode uses browser sign-in for each user."
                )

            # Check if client secrets file exists
            if not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
                raise FileNotFoundError(
                    f"OAuth client secrets file not found. Please place a client_secrets.json file in the script directory "
                    f"or set the GSC_OAUTH_CLIENT_SECRETS_FILE environment variable."
                )

            # Start OAuth flow — opens a browser window on macOS even from MCP subprocess.
            flow = InstalledAppFlow.from_client_secrets_file(OAUTH_CLIENT_SECRETS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
            
            # Save the credentials for future use
            _save_token(creds)
    
    # Build and return the service
    return build("searchconsole", "v1", credentials=creds, cache_discovery=False)


def _site_not_found_error(site_url: str) -> str:
    """Return a helpful message when a GSC property returns 404."""
    lines = [f"Property '{site_url}' not found (404). Possible causes:\n"]
    lines.append(
        "1. The site_url doesn't exactly match what is in GSC. "
        "Run list_properties to get the exact string to use."
    )
    if site_url.startswith("sc-domain:"):
        lines.append(
            "2. Domain properties require the service account to be explicitly added "
            "under GSC Settings > Users and permissions for that specific domain property. "
            "OAuth users must also have verified access to it."
        )
    else:
        lines.append(
            "2. If your property is a domain property (covers all subdomains), "
            "the correct format is 'sc-domain:example.com', not a full URL."
        )
    lines.append(
        "3. The authenticated account may not have access to this property."
    )
    return "\n".join(lines)


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_capabilities() -> str:
    """
    Get a full list of all available tools, current auth status, and how to get started.
    ALWAYS call this first when asked what tools are available, what this server can do,
    or how to get started. Returns the registered read-only tools in a single call.
    Also shows if authentication is needed.
    """
    try:
        await asyncio.to_thread(get_gsc_service)
        auth_status = "authenticated"
        auth_error = None
    except Exception as exc:
        auth_status = "not_authenticated"
        auth_error = str(exc)

    tools = await mcp.list_tools()
    return json.dumps({
        "mode": "read_only",
        "auth_status": auth_status,
        "auth_error": auth_error,
        "tools": [{"name": tool.name, "description": tool.description} for tool in tools],
        "getting_started": [
            ("Your MCP client is connected with your Google account. "
             "Call list_properties to see properties available to you."
             if AUTH_PROVIDER else
             "For local testing, configure credentials on the server. "
             "Run `python gsc_server.py --reauthenticate` locally for Google login."),
            "Call list_properties to get the exact site_url for other tools.",
        ],
    })


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def list_properties() -> str:
    """
    List all Google Search Console (GSC) properties and sites the user has access to.
    Use this to see all verified sites, domain properties, and URL-prefix properties
    in the connected Google Search Console account. Always call this first to get the
    exact site_url needed for other tools.
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        site_list = await asyncio.to_thread(lambda: execute_tracked(service.sites().list(), "other"))

        # site_list is typically something like:
        # {
        #   "siteEntry": [
        #       {"siteUrl": "...", "permissionLevel": "..."},
        #       ...
        #   ]
        # }
        sites = site_list.get("siteEntry", [])

        if not sites:
            return "No Search Console properties found."

        return json.dumps({
            "count": len(sites),
            "properties": [
                {
                    "site_url": site.get("siteUrl", "Unknown"),
                    "permission_level": site.get("permissionLevel", "Unknown"),
                }
                for site in sites
            ],
        })
    except FileNotFoundError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error retrieving properties: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_search_analytics(site_url: str, days: int = 28, dimensions: str = "query", row_limit: int = 20) -> str:
    """
    Get search analytics data for a specific property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        days: Number of days to look back (default: 28)
        dimensions: Dimensions to group by (default: query). Options: query, page, device, country, date
                   You can provide multiple dimensions separated by comma (e.g., "query,page")
        row_limit: Number of rows to return (default: 20, max: 500). Use 5-20 for quick overviews,
                   50-200 for deeper analysis, up to 500 for comprehensive reports. For bulk exports
                   beyond 500 rows, use get_advanced_search_analytics which supports pagination.
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Calculate date range
        start_date, end_date = _date_range(days)
        
        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        # Build request
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": dimension_list,
            "rowLimit": min(max(1, row_limit), 500),
            "dataState": DATA_STATE
        }
        
        # Execute request
        response = await asyncio.to_thread(lambda: execute_tracked(service.searchanalytics().query(siteUrl=site_url, body=request), "search_analytics"))
        
        if not response.get("rows"):
            return f"No search analytics data found for {site_url} in the last {days} days."

        rows = []
        for row in response.get("rows", []):
            entry = {}
            for i, dim in enumerate(dimension_list):
                entry[dim] = row.get("keys", [])[i] if i < len(row.get("keys", [])) else None
            entry["clicks"] = row.get("clicks", 0)
            entry["impressions"] = row.get("impressions", 0)
            entry["ctr"] = round(row.get("ctr", 0), 4)
            entry["position"] = round(row.get("position", 0), 1)
            rows.append(entry)

        return json.dumps({
            "site_url": site_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "dimensions": dimension_list,
            "row_count": len(rows),
            "rows": rows,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving search analytics: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_site_details(site_url: str) -> str:
    """
    Get detailed information about a specific Search Console property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Get site details
        site_info = await asyncio.to_thread(lambda: execute_tracked(service.sites().get(siteUrl=site_url), "other"))
        
        result = {
            "site_url": site_url,
            "permission_level": site_info.get("permissionLevel", "Unknown"),
        }

        if "siteVerificationInfo" in site_info:
            verify_info = site_info["siteVerificationInfo"]
            result["verification"] = {
                "state": verify_info.get("verificationState", "Unknown"),
                "verified_user": verify_info.get("verifiedUser"),
                "method": verify_info.get("verificationMethod"),
            }

        if "ownershipInfo" in site_info:
            owner_info = site_info["ownershipInfo"]
            result["ownership"] = {
                "owner": owner_info.get("owner", "Unknown"),
                "verification_method": owner_info.get("verificationMethod"),
            }

        return json.dumps(result)
    except Exception as e:
        return f"Error retrieving site details: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_sitemaps(site_url: str) -> str:
    """
    List all sitemaps for a specific Search Console property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Get sitemaps list
        sitemaps = await asyncio.to_thread(lambda: execute_tracked(service.sitemaps().list(siteUrl=site_url), "other"))
        
        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}."

        sitemap_list = []
        for sitemap in sitemaps.get("sitemap", []):
            last_downloaded = sitemap.get("lastDownloaded")
            if last_downloaded:
                try:
                    dt = datetime.fromisoformat(last_downloaded.replace("Z", "+00:00"))
                    last_downloaded = dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pass

            errors = int(sitemap.get("errors", 0))
            warnings = int(sitemap.get("warnings", 0))

            status = "Valid"
            if errors > 0:
                status = "Has errors"
            elif warnings > 0:
                status = "Has warnings"

            submitted_urls = None
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        submitted_urls = content.get("submitted")
                        break

            sitemap_list.append({
                "path": sitemap.get("path", "Unknown"),
                "last_downloaded": last_downloaded,
                "status": status,
                "submitted_urls": submitted_urls,
                "errors": errors,
                "warnings": warnings,
            })

        return json.dumps({
            "site_url": site_url,
            "count": len(sitemap_list),
            "sitemaps": sitemap_list,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving sitemaps: {str(e)}"

def _rich_results_summary(inspection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Shape the richResultsResult of a URL inspection into a reportable summary.

    Shared by inspect_url_enhanced and batch_url_inspection so both tools report the
    same thing for the same page.

    Issues are nested under detectedItems[].items[].issues[] and the message key is
    "issueMessage". Reading a top-level "richResultsIssues" key -- which the API never
    returns -- made this list always empty, hiding every rich-result problem.
    """
    if "richResultsResult" not in inspection:
        return None

    rich = inspection["richResultsResult"]
    return {
        "verdict": rich.get("verdict", "UNKNOWN"),
        "detected_types": [
            item.get("richResultType", "Unknown")
            for item in rich.get("detectedItems", [])
        ],
        "issues": [
            {
                "type": detected.get("richResultType", "Unknown"),
                "item": item.get("name"),
                "severity": issue.get("severity"),
                "message": issue.get("issueMessage"),
            }
            for detected in rich.get("detectedItems", [])
            for item in detected.get("items", [])
            for issue in item.get("issues", [])
        ],
    }

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def inspect_url_enhanced(site_url: str, page_url: str) -> str:
    """
    Enhanced URL inspection to check indexing status and rich results in Google.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        page_url: The specific URL to inspect
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Build request
        request = {
            "inspectionUrl": page_url,
            "siteUrl": site_url
        }
        
        # Execute request
        response = await asyncio.to_thread(lambda: execute_tracked(service.urlInspection().index().inspect(body=request), "url_inspection"))
        
        if not response or "inspectionResult" not in response:
            return f"No inspection data found for {page_url}."

        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})

        last_crawled = None
        if "lastCrawlTime" in index_status:
            try:
                crawl_time = datetime.fromisoformat(index_status["lastCrawlTime"].replace("Z", "+00:00"))
                last_crawled = crawl_time.strftime("%Y-%m-%d %H:%M")
            except Exception:
                last_crawled = index_status["lastCrawlTime"]

        rich_results = _rich_results_summary(inspection)

        return json.dumps({
            "page_url": page_url,
            "site_url": site_url,
            "inspection_result_link": inspection.get("inspectionResultLink"),
            "verdict": index_status.get("verdict", "UNKNOWN"),
            "coverage_state": index_status.get("coverageState"),
            "last_crawled": last_crawled,
            "page_fetch_state": index_status.get("pageFetchState"),
            "robots_txt_state": index_status.get("robotsTxtState"),
            "indexing_state": index_status.get("indexingState"),
            "google_canonical": index_status.get("googleCanonical"),
            "user_canonical": index_status.get("userCanonical"),
            "crawled_as": index_status.get("crawledAs"),
            "referring_urls": index_status.get("referringUrls", [])[:5],
            "rich_results": rich_results,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error inspecting URL: {str(e)}"

# Max URLs inspected concurrently in batch_url_inspection. The URL Inspection API
# allows 600 queries/minute per site, so 10 in-flight is comfortably within limits.
_BATCH_INSPECTION_CONCURRENCY = 10


def _inspect_single_url(site_url: str, page_url: str) -> Dict[str, Any]:
    """Inspect one URL and shape the result into a row.

    Builds its own Search Console service so it is safe to run in a worker thread —
    google-api-python-client's underlying http transport is not thread-safe to share
    across threads. Never raises: failures are returned as an ``error`` row so one bad
    URL doesn't sink the whole batch.
    """
    try:
        service = get_gsc_service()
        request = {"inspectionUrl": page_url, "siteUrl": site_url}
        response = execute_tracked(service.urlInspection().index().inspect(body=request), "url_inspection")

        if not response or "inspectionResult" not in response:
            return {"url": page_url, "error": "No inspection data found"}

        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})

        verdict = index_status.get("verdict", "UNKNOWN")
        coverage = index_status.get("coverageState", "Unknown")
        last_crawl = "Never"

        if "lastCrawlTime" in index_status:
            try:
                crawl_time = datetime.fromisoformat(index_status["lastCrawlTime"].replace('Z', '+00:00'))
                last_crawl = crawl_time.strftime('%Y-%m-%d')
            except Exception:
                last_crawl = index_status["lastCrawlTime"]

        # Rich results, in the same shape inspect_url_enhanced reports.
        return {
            "url": page_url,
            "index_verdict": verdict,
            "coverage_state": coverage,
            "last_crawled": last_crawl,
            "rich_results": _rich_results_summary(inspection),
        }
    except Exception as e:
        return {"url": page_url, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def batch_url_inspection(site_url: str, urls: str) -> str:
    """
    Inspect multiple URLs in batch (within API limits).

    URLs are inspected concurrently, so a full batch stays well under the MCP
    client's request timeout even on slower sc-domain:* properties.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        urls: List of URLs to inspect, one per line
    """
    try:
        # Validate auth once up front. This also refreshes the OAuth token a single
        # time so the concurrent workers below reuse it without racing on token.json.
        await asyncio.to_thread(get_gsc_service)

        # Parse URLs
        url_list = [url.strip() for url in urls.split('\n') if url.strip()]

        if not url_list:
            return "No URLs provided for inspection."

        if len(url_list) > 10:
            return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."

        # Inspect concurrently. The URL Inspection API is slow (especially on
        # sc-domain:* properties); running 10 URLs sequentially blew past the MCP
        # client's default 60s timeout (#31). google-api-python-client is blocking,
        # so each call runs in a worker thread with its own service instance.
        semaphore = asyncio.Semaphore(_BATCH_INSPECTION_CONCURRENCY)

        async def _run(page_url: str) -> Dict[str, Any]:
            async with semaphore:
                return await asyncio.to_thread(_inspect_single_url, site_url, page_url)

        # asyncio.gather preserves the order of url_list.
        results = await asyncio.gather(*[_run(u) for u in url_list])

        return json.dumps({
            "site_url": site_url,
            "count": len(results),
            "results": list(results),
        })

    except Exception as e:
        return f"Error performing batch inspection: {str(e)}"

def _check_indexing_single_url(site_url: str, page_url: str) -> Dict[str, Optional[str]]:
    """Inspect one URL and classify it into indexing-issue buckets.

    Builds its own service so it is safe to run in a worker thread. Never raises:
    failures are recorded under ``not_indexed``. Returns one string (or None) per
    category so the caller can aggregate results in input order.
    """
    result: Dict[str, Optional[str]] = {
        "not_indexed": None,
        "canonical_issues": None,
        "robots_blocked": None,
        "fetch_issues": None,
        "indexed": None,
    }
    try:
        service = get_gsc_service()
        request = {"inspectionUrl": page_url, "siteUrl": site_url}
        response = execute_tracked(service.urlInspection().index().inspect(body=request), "url_inspection")

        if not response or "inspectionResult" not in response:
            result["not_indexed"] = f"{page_url} - No inspection data found"
            return result

        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})

        verdict = index_status.get("verdict", "UNKNOWN")
        coverage = index_status.get("coverageState", "Unknown")

        if verdict != "PASS" or "not indexed" in coverage.lower() or "excluded" in coverage.lower():
            result["not_indexed"] = f"{page_url} - {coverage}"
        else:
            result["indexed"] = page_url

        google_canonical = index_status.get("googleCanonical", "")
        user_canonical = index_status.get("userCanonical", "")
        if google_canonical and user_canonical and google_canonical != user_canonical:
            result["canonical_issues"] = (
                f"{page_url} - Google chose: {google_canonical} instead of user-declared: {user_canonical}"
            )

        robots_state = index_status.get("robotsTxtState", "")
        if robots_state == "BLOCKED":
            result["robots_blocked"] = page_url

        fetch_state = index_status.get("pageFetchState", "")
        if fetch_state != "SUCCESSFUL":
            result["fetch_issues"] = f"{page_url} - {fetch_state}"
    except Exception as e:
        result["not_indexed"] = f"{page_url} - Error: {str(e)}"
    return result


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def check_indexing_issues(site_url: str, urls: str) -> str:
    """
    Check for specific indexing issues across multiple URLs.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        urls: List of URLs to check, one per line
    """
    try:
        # Validate auth once up front (also refreshes the token so the concurrent
        # workers below reuse it without racing on token.json).
        await asyncio.to_thread(get_gsc_service)

        # Parse URLs
        url_list = [url.strip() for url in urls.split('\n') if url.strip()]

        if not url_list:
            return "No URLs provided for inspection."

        if len(url_list) > 10:
            return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."

        # Inspect concurrently — same reasoning as batch_url_inspection (#31): the
        # sequential loop timed out on sc-domain:* properties near the 10-URL cap.
        semaphore = asyncio.Semaphore(_BATCH_INSPECTION_CONCURRENCY)

        async def _run(page_url: str) -> Dict[str, Optional[str]]:
            async with semaphore:
                return await asyncio.to_thread(_check_indexing_single_url, site_url, page_url)

        # asyncio.gather preserves url_list order.
        per_url = await asyncio.gather(*[_run(u) for u in url_list])

        # Aggregate the per-URL classifications by category, in input order.
        issues_summary = {
            "not_indexed": [],
            "canonical_issues": [],
            "robots_blocked": [],
            "fetch_issues": [],
            "indexed": []
        }
        for entry in per_url:
            for category, value in entry.items():
                if value is not None:
                    issues_summary[category].append(value)

        return json.dumps({
            "site_url": site_url,
            "summary": {
                "total_checked": len(url_list),
                "indexed": len(issues_summary["indexed"]),
                "not_indexed": len(issues_summary["not_indexed"]),
                "canonical_issues": len(issues_summary["canonical_issues"]),
                "robots_blocked": len(issues_summary["robots_blocked"]),
                "fetch_issues": len(issues_summary["fetch_issues"]),
            },
            "issues": {
                "not_indexed": issues_summary["not_indexed"],
                "canonical_issues": issues_summary["canonical_issues"],
                "robots_blocked": issues_summary["robots_blocked"],
                "fetch_issues": issues_summary["fetch_issues"],
            },
            "indexed_urls": issues_summary["indexed"],
        })

    except Exception as e:
        return f"Error checking indexing issues: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_performance_overview(site_url: str, days: int = 28) -> str:
    """
    Get a performance overview for a specific property.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        days: Number of days to look back (default: 28)
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Calculate date range
        start_date, end_date = _date_range(days)
        
        # Get total metrics
        total_request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": [],  # No dimensions for totals
            "rowLimit": 1,
            "dataState": DATA_STATE
        }
        
        total_response = await asyncio.to_thread(lambda: execute_tracked(service.searchanalytics().query(siteUrl=site_url, body=total_request), "search_analytics"))
        
        # Get by date for trend
        date_request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["date"],
            "rowLimit": days,
            "dataState": DATA_STATE
        }
        
        date_response = await asyncio.to_thread(lambda: execute_tracked(service.searchanalytics().query(siteUrl=site_url, body=date_request), "search_analytics"))
        
        if not total_response.get("rows"):
            return f"No performance data available for {site_url} in the last {days} days."

        totals_row = total_response["rows"][0]
        totals = {
            "clicks": totals_row.get("clicks", 0),
            "impressions": totals_row.get("impressions", 0),
            "ctr": round(totals_row.get("ctr", 0), 4),
            "position": round(totals_row.get("position", 0), 1),
        }

        daily_trend = []
        if date_response.get("rows"):
            sorted_rows = sorted(date_response["rows"], key=lambda x: x["keys"][0])
            for row in sorted_rows:
                daily_trend.append({
                    "date": row["keys"][0],
                    "clicks": row.get("clicks", 0),
                    "impressions": row.get("impressions", 0),
                    "ctr": round(row.get("ctr", 0), 4),
                    "position": round(row.get("position", 0), 1),
                })

        return json.dumps({
            "site_url": site_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "totals": totals,
            "daily_trend": daily_trend,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving performance overview: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_advanced_search_analytics(
    site_url: str, 
    start_date: str = None, 
    end_date: str = None, 
    dimensions: str = "query", 
    search_type: str = "WEB",
    row_limit: int = 1000,
    start_row: int = 0,
    sort_by: str = "clicks",
    sort_direction: str = "descending",
    filter_dimension: str = None,
    filter_operator: str = "contains", 
    filter_expression: str = None,
    filters: str = None,
    data_state: str = None
) -> str:
    """
    Get advanced search analytics data with sorting, filtering, and pagination.
    Sorting only reorders the returned click-ranked page of rows.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        start_date: Start date in YYYY-MM-DD format (defaults to 28 days ago)
        end_date: End date in YYYY-MM-DD format (defaults to today)
        dimensions: Dimensions to group by, comma-separated (e.g., "query,page,device")
        search_type: Type of search results (WEB, IMAGE, VIDEO, NEWS, DISCOVER)
        row_limit: Maximum number of rows to return (max 25000)
        start_row: Starting row for pagination
        sort_by: Metric to sort by (clicks, impressions, ctr, position). Applied
                 client-side to the returned rows, since Google only sorts by clicks.
        sort_direction: Sort direction (ascending or descending). For position,
                 ascending puts the best (lowest) average position first.
        filter_dimension: Single filter dimension (query, page, country, device). Use 'filters' instead for multiple filters.
        filter_operator: Single filter operator (contains, equals, notContains, notEquals)
        filter_expression: Single filter expression value
        filters: JSON array of filter objects for AND logic across multiple dimensions. Overrides
                 filter_dimension/filter_operator/filter_expression when provided. Each object must
                 have 'dimension', 'operator', and 'expression' keys. Valid dimensions: query, page,
                 country, device. Valid operators: contains, equals, notContains, notEquals.
                 Example: [{"dimension":"country","operator":"equals","expression":"usa"},
                           {"dimension":"device","operator":"equals","expression":"MOBILE"}]
        data_state: Data freshness — "all" (default, matches GSC dashboard) or "final" (confirmed data only, 2-3 day lag)
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Calculate date range if not provided
        if not end_date:
            end_date = _date_range(28)[1].strftime("%Y-%m-%d")
        if not start_date:
            start_date = (datetime.strptime(end_date, "%Y-%m-%d").date() - timedelta(days=27)).strftime("%Y-%m-%d")
        
        # Resolve and validate data_state (per-call override or fall back to global setting)
        resolved_data_state = (data_state or DATA_STATE).lower().strip()
        if resolved_data_state not in ("all", "final"):
            return (
                f"Invalid data_state value '{data_state}'. "
                "Accepted values are 'all' (matches GSC dashboard) or 'final' (2-3 day lag)."
            )
        
        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        # Build request
        request = {
            "startDate": start_date,
            "endDate": end_date,
            "dimensions": dimension_list,
            "rowLimit": min(row_limit, 25000),  # Cap at API maximum
            "startRow": start_row,
            "searchType": search_type.upper(),
            "dataState": resolved_data_state
        }
        
        # Sorting is applied client-side below. The Search Analytics query API has no
        # orderBy field (it always returns rows sorted by clicks descending), so an
        # orderBy in the request body was silently ignored (#54).
        
        # Build filter groups — multi-filter JSON takes priority over single-filter params
        active_filters = []
        if filters:
            try:
                filter_list = json.loads(filters)
            except json.JSONDecodeError:
                return "Invalid filters JSON. Please provide a valid JSON array of filter objects."
            if not isinstance(filter_list, list) or len(filter_list) == 0:
                return "Invalid filters value. Expected a non-empty JSON array of filter objects."
            for f in filter_list:
                if not all(k in f for k in ("dimension", "operator", "expression")):
                    return (
                        "Each filter object must have 'dimension', 'operator', and 'expression' keys. "
                        f"Invalid filter: {f}"
                    )
            request["dimensionFilterGroups"] = [{"filters": filter_list}]
            active_filters = filter_list
        elif filter_dimension and filter_expression:
            single_filter = {
                "dimension": filter_dimension,
                "operator": filter_operator,
                "expression": filter_expression
            }
            request["dimensionFilterGroups"] = [{"filters": [single_filter]}]
            active_filters = [single_filter]
        
        # Execute request
        response = await asyncio.to_thread(lambda: execute_tracked(service.searchanalytics().query(siteUrl=site_url, body=request), "search_analytics"))
        
        if not response.get("rows"):
            no_data_msg = (
                f"No search analytics data found for {site_url} with the specified parameters.\n\n"
                f"Parameters used:\n"
                f"- Date range: {start_date} to {end_date}\n"
                f"- Dimensions: {dimensions}\n"
                f"- Search type: {search_type}\n"
            )
            if active_filters:
                no_data_msg += "- Filters:\n"
                for f in active_filters:
                    no_data_msg += f"    {f['dimension']} {f['operator']} '{f['expression']}'\n"
            else:
                no_data_msg += "- No filter applied\n"
            return no_data_msg
        
        rows = []
        for row in response.get("rows", []):
            entry = {}
            for i, dim in enumerate(dimension_list):
                entry[dim] = row.get("keys", [])[i] if i < len(row.get("keys", [])) else None
            entry["clicks"] = row.get("clicks", 0)
            entry["impressions"] = row.get("impressions", 0)
            entry["ctr"] = round(row.get("ctr", 0), 4)
            entry["position"] = round(row.get("position", 0), 1)
            rows.append(entry)

        # Sort the returned rows client-side. Google only sorts by clicks descending
        # server-side, so without this the sort_by/sort_direction args were silently
        # ignored (#54). Sorting applies within the returned page of rows.
        valid_sort_metrics = ("clicks", "impressions", "ctr", "position")
        if sort_by in valid_sort_metrics:
            reverse = sort_direction.lower() != "ascending"
            rows.sort(key=lambda r: r.get(sort_by, 0), reverse=reverse)

        has_more = len(response.get("rows", [])) == row_limit
        return json.dumps({
            "site_url": site_url,
            "date_range": {"start": start_date, "end": end_date},
            "search_type": search_type,
            "sort_scope": "returned_rows",
            "dimensions": dimension_list,
            "filters_applied": active_filters,
            "pagination": {
                "start_row": start_row,
                "row_count": len(rows),
                "has_more": has_more,
                "next_start_row": start_row + row_limit if has_more else None,
            },
            "rows": rows,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving advanced search analytics: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def compare_search_periods(
    site_url: str,
    period1_start: str,
    period1_end: str,
    period2_start: str,
    period2_end: str,
    dimensions: str = "query",
    limit: int = 10
) -> str:
    """
    Compare search analytics data between two time periods.

    Direction: Period 1 is the period you are analyzing and Period 2 is the baseline
    you compare it against. All deltas are Period 1 relative to Period 2, and the
    percentage baseline is Period 2. A positive value means Period 1 outperformed
    Period 2 — more clicks/impressions, higher CTR, or a better (lower) average
    position. For a current-vs-previous comparison, pass the current period as
    Period 1 and the previous period as Period 2. Percentages are null when the
    Period 2 baseline is zero.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        period1_start: Start date for period 1 / the analyzed period (YYYY-MM-DD)
        period1_end: End date for period 1 / the analyzed period (YYYY-MM-DD)
        period2_start: Start date for period 2 / the baseline period (YYYY-MM-DD)
        period2_end: End date for period 2 / the baseline period (YYYY-MM-DD)
        dimensions: Dimensions to group by (default: query)
        limit: Number of top results to compare (default: 10)
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        # Build requests for both periods
        period1_request = {
            "startDate": period1_start,
            "endDate": period1_end,
            "dimensions": dimension_list,
            "rowLimit": 1000,  # Get more to ensure we can match items between periods
            "dataState": DATA_STATE
        }
        
        period2_request = {
            "startDate": period2_start,
            "endDate": period2_end,
            "dimensions": dimension_list,
            "rowLimit": 1000,
            "dataState": DATA_STATE
        }
        
        # Execute requests
        period1_response = await asyncio.to_thread(lambda: execute_tracked(service.searchanalytics().query(siteUrl=site_url, body=period1_request), "search_analytics"))
        period2_response = await asyncio.to_thread(lambda: execute_tracked(service.searchanalytics().query(siteUrl=site_url, body=period2_request), "search_analytics"))
        
        period1_rows = period1_response.get("rows", [])
        period2_rows = period2_response.get("rows", [])
        
        if not period1_rows and not period2_rows:
            return f"No data found for either period for {site_url}."
        
        # Create dictionaries for easy lookup
        period1_data = {tuple(row.get("keys", [])): row for row in period1_rows}
        period2_data = {tuple(row.get("keys", [])): row for row in period2_rows}
        
        # Find common keys and calculate differences
        all_keys = set(period1_data.keys()) | set(period2_data.keys())
        comparison_data = []
        
        for key in all_keys:
            p1_row = period1_data.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})
            p2_row = period2_data.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})
            
            # Differences are Period 1 relative to Period 2, with Period 2 as the
            # baseline. A positive value always means Period 1 outperformed Period 2
            # (more clicks/impressions, higher CTR, or a better — i.e. lower — position).
            click_diff = p1_row.get("clicks", 0) - p2_row.get("clicks", 0)
            click_pct = (click_diff / p2_row.get("clicks", 1)) * 100 if p2_row.get("clicks", 0) > 0 else float('inf')
            
            imp_diff = p1_row.get("impressions", 0) - p2_row.get("impressions", 0)
            imp_pct = (imp_diff / p2_row.get("impressions", 1)) * 100 if p2_row.get("impressions", 0) > 0 else float('inf')
            
            ctr_diff = p1_row.get("ctr", 0) - p2_row.get("ctr", 0)
            pos_diff = (p2_row.get("position", 0) - p1_row.get("position", 0)
                        if key in period1_data and key in period2_data else None)
            
            comparison_data.append({
                "key": key,
                "p1_clicks": p1_row.get("clicks", 0),
                "p2_clicks": p2_row.get("clicks", 0),
                "click_diff": click_diff,
                "click_pct": click_pct,
                "p1_impressions": p1_row.get("impressions", 0),
                "p2_impressions": p2_row.get("impressions", 0),
                "imp_diff": imp_diff,
                "imp_pct": imp_pct,
                "p1_ctr": p1_row.get("ctr", 0),
                "p2_ctr": p2_row.get("ctr", 0),
                "ctr_diff": ctr_diff,
                "p1_position": p1_row.get("position", 0),
                "p2_position": p2_row.get("position", 0),
                "pos_diff": pos_diff
            })
        
        # Sort by absolute click difference
        comparison_data.sort(key=lambda x: abs(x["click_diff"]), reverse=True)

        serialisable = []
        for item in comparison_data[:limit]:
            click_pct = item["click_pct"] if item["click_pct"] != float("inf") else None
            imp_pct = item["imp_pct"] if item["imp_pct"] != float("inf") else None
            serialisable.append({
                "key": list(item["key"]),
                "p1_clicks": item["p1_clicks"],
                "p2_clicks": item["p2_clicks"],
                "click_diff": item["click_diff"],
                "click_pct": round(click_pct, 1) if click_pct is not None else None,
                "p1_impressions": item["p1_impressions"],
                "p2_impressions": item["p2_impressions"],
                "imp_diff": item["imp_diff"],
                "imp_pct": round(imp_pct, 1) if imp_pct is not None else None,
                "p1_ctr": round(item["p1_ctr"], 4),
                "p2_ctr": round(item["p2_ctr"], 4),
                "ctr_diff": round(item["ctr_diff"], 4),
                "p1_position": round(item["p1_position"], 1) if item["key"] in period1_data else None,
                "p2_position": round(item["p2_position"], 1) if item["key"] in period2_data else None,
                "position_diff": round(item["pos_diff"], 1) if item["pos_diff"] is not None else None,
            })

        return json.dumps({
            "site_url": site_url,
            "period1": {"start": period1_start, "end": period1_end},
            "period2": {"start": period2_start, "end": period2_end},
            "dimensions": dimension_list,
            "total_items": len(comparison_data),
            "showing": len(serialisable),
            "comparison": serialisable,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error comparing search periods: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_search_by_page_query(
    site_url: str,
    page_url: str,
    days: int = 28,
    row_limit: int = 20
) -> str:
    """
    Get search analytics data for a specific page, broken down by query.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        page_url: The specific page URL to analyze
        days: Number of days to look back (default: 28)
        row_limit: Number of rows to return (default: 20, max: 500). Use 5-20 for quick overviews,
                   50-200 for deeper analysis, up to 500 for comprehensive reports. For bulk exports
                   beyond 500 rows, use get_advanced_search_analytics which supports pagination.
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Calculate date range
        start_date, end_date = _date_range(days)
        
        # Build request with page filter
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["query"],
            "dimensionFilterGroups": [{
                "filters": [{
                    "dimension": "page",
                    "operator": "equals",
                    "expression": page_url
                }]
            }],
            "rowLimit": min(max(1, row_limit), 500),
            # Note: the Search Analytics query API has no orderBy field — it always
            # returns rows sorted by clicks descending (which is what we want here).
            "dataState": DATA_STATE
        }
        
        # Execute request
        response = await asyncio.to_thread(lambda: execute_tracked(service.searchanalytics().query(siteUrl=site_url, body=request), "search_analytics"))
        
        if not response.get("rows"):
            return f"No search data found for page {page_url} in the last {days} days."
        
        rows = []
        for row in response.get("rows", []):
            rows.append({
                "query": row.get("keys", ["Unknown"])[0],
                "clicks": row.get("clicks", 0),
                "impressions": row.get("impressions", 0),
                "ctr": round(row.get("ctr", 0), 4),
                "position": round(row.get("position", 0), 1),
            })

        total_clicks = sum(r["clicks"] for r in rows)
        total_impressions = sum(r["impressions"] for r in rows)

        return json.dumps({
            "site_url": site_url,
            "page_url": page_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "totals": {
                "clicks": total_clicks,
                "impressions": total_impressions,
                "avg_ctr": round(total_clicks / total_impressions, 4) if total_impressions > 0 else 0,
            },
            "row_count": len(rows),
            "rows": rows,
        })
    except Exception as e:
        return f"Error retrieving page query data: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def list_sitemaps_enhanced(site_url: str, sitemap_index: str = None) -> str:
    """
    List all sitemaps for a specific Search Console property with detailed information.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        sitemap_index: Optional sitemap index URL to list child sitemaps
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Get sitemaps list
        if sitemap_index:
            sitemaps = await asyncio.to_thread(lambda: execute_tracked(service.sitemaps().list(siteUrl=site_url, sitemapIndex=sitemap_index), "other"))
            source = f"child sitemaps from index: {sitemap_index}"
        else:
            sitemaps = await asyncio.to_thread(lambda: execute_tracked(service.sitemaps().list(siteUrl=site_url), "other"))
            source = "all submitted sitemaps"
        
        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}" + (f" in index {sitemap_index}" if sitemap_index else ".")

        def _fmt_date(raw):
            if not raw:
                return None
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return raw

        sitemap_list = []
        for sitemap in sitemaps.get("sitemap", []):
            errors = int(sitemap.get("errors", 0))
            warnings = int(sitemap.get("warnings", 0))
            url_count = None
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        url_count = content.get("submitted")
                        break
            sitemap_list.append({
                "path": sitemap.get("path", "Unknown"),
                "last_submitted": _fmt_date(sitemap.get("lastSubmitted")),
                "last_downloaded": _fmt_date(sitemap.get("lastDownloaded")),
                "type": "Index" if sitemap.get("isSitemapsIndex", False) else "Sitemap",
                "is_pending": sitemap.get("isPending", False),
                "url_count": url_count,
                "errors": errors,
                "warnings": warnings,
            })

        pending_count = sum(1 for s in sitemap_list if s["is_pending"])

        return json.dumps({
            "site_url": site_url,
            "sitemap_index": sitemap_index,
            "count": len(sitemap_list),
            "pending_count": pending_count,
            "sitemaps": sitemap_list,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error retrieving sitemaps: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_sitemap_details(site_url: str, sitemap_url: str) -> str:
    """
    Get detailed information about a specific sitemap.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        sitemap_url: The full URL of the sitemap to inspect
    """
    try:
        service = await asyncio.to_thread(get_gsc_service)
        
        # Get sitemap details
        details = await asyncio.to_thread(lambda: execute_tracked(service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url), "other"))
        
        if not details:
            return f"No details found for sitemap {sitemap_url}."

        def _fmt_date(raw):
            if not raw:
                return None
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return raw

        is_index = details.get("isSitemapsIndex", False)
        content_breakdown = [
            {
                "type": content.get("type", "unknown").upper(),
                "submitted": content.get("submitted", 0),
                "indexed": content.get("indexed"),
            }
            for content in details.get("contents", [])
        ]

        return json.dumps({
            "sitemap_url": sitemap_url,
            "site_url": site_url,
            "type": "Index" if is_index else "Sitemap",
            "status": "pending" if details.get("isPending", False) else "processed",
            "last_submitted": _fmt_date(details.get("lastSubmitted")),
            "last_downloaded": _fmt_date(details.get("lastDownloaded")),
            "errors": int(details.get("errors", 0)),
            "warnings": int(details.get("warnings", 0)),
            "content_breakdown": content_breakdown,
            "is_index": is_index,
        })
    except Exception as e:
        return f"Error retrieving sitemap details: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def manage_sitemaps(site_url: str, action: str, sitemap_url: str = None, sitemap_index: str = None) -> str:
    """
    Read sitemap lists or details without changing Search Console.
    
    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Domain properties cover all subdomains — use the
                  domain property as site_url and filter by page to analyze a specific subdomain.
        action: The read action to perform (list or details)
        sitemap_url: The full URL of the sitemap (required for details)
        sitemap_index: Optional sitemap index URL for listing child sitemaps (only used with 'list' action)
    """
    try:
        # Validate inputs
        action = action.lower().strip()
        valid_actions = ["list", "details"]
        
        if action not in valid_actions:
            return f"Invalid action: {action}. Please use one of: {', '.join(valid_actions)}"
        
        if action == "details" and not sitemap_url:
            return f"The {action} action requires a sitemap_url parameter."
        
        # Perform the requested action
        if action == "list":
            return await list_sitemaps_enhanced(site_url, sitemap_index)
        elif action == "details":
            return await get_sitemap_details(site_url, sitemap_url)
    
    except Exception as e:
        return f"Error managing sitemaps: {str(e)}"

@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True,
))
@usage_report
async def get_creator_info() -> str:
    """
    Provides information about Amin Foroutan, the creator of the MCP-GSC tool.
    """
    creator_info = """
# About the Creator: Amin Foroutan

Amin Foroutan is an SEO consultant with over a decade of experience, specializing in technical SEO, Python-driven tools, and data analysis for SEO performance.

## Connect with Amin:

- **LinkedIn**: [Amin Foroutan](https://www.linkedin.com/in/ma-foroutan/)
- **Personal Website**: [aminforoutan.com](https://aminforoutan.com/)
- **YouTube**: [Amin Forout](https://www.youtube.com/channel/UCW7tPXg-rWdH4YzLrcAdBIw)
- **X (Twitter)**: [@aminfseo](https://x.com/aminfseo)

## Notable Projects:

Amin has created several popular SEO tools including:
- Advanced GSC Visualizer (6.4K+ users)
- SEO Render Insight Tool (3.5K+ users)
- Google AI Overview Impact Analysis (1.2K+ users)
- Google AI Overview Citation Analysis (900+ users)
- SEMRush Enhancer (570+ users)
- SEO Page Inspector (115+ users)

## Expertise:

Amin combines technical SEO knowledge with programming skills to create innovative solutions for SEO challenges.
"""
    return creator_info

async def reauthenticate() -> str:
    """
    Authenticate a new Google account and replace the saved OAuth token.
    Useful when you need to switch to a different Google account.
    """
    try:
        had_token = os.path.exists(TOKEN_FILE)

        # Check if OAuth client secrets file exists
        if not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
            return (
                "Error: OAuth client secrets file not found. "
                "Cannot start new authentication flow. "
                "Please ensure client_secrets.json is present or set the "
                "GSC_OAUTH_CLIENT_SECRETS_FILE environment variable."
            )

        # Trigger new OAuth flow — opens a browser window on the local machine.
        # run_local_server() works on macOS even from an MCP subprocess because
        # macOS can open browsers via webbrowser.open() regardless of TTY state.
        flow = InstalledAppFlow.from_client_secrets_file(OAUTH_CLIENT_SECRETS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)

        _save_token(creds)

        msg = "Successfully authenticated with a new Google account."
        if had_token:
            msg = "Previous session replaced. " + msg
        return msg

    except Exception as e:
        return f"Error during reauthentication: {str(e)}"


def configure_http():
    """Configure the single /mcp endpoint without disabling Host/Origin checks."""
    host = os.environ.get("MCP_HOST", "127.0.0.1").strip()
    if not AUTH_PROVIDER and host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Public HTTP binding requires MCP_PUBLIC_URL and Google sign-in settings")
    mcp.settings.host = host
    try:
        port = int(os.environ.get("MCP_PORT", "3001"))
    except ValueError as exc:
        raise ValueError("MCP_PORT must be an integer between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise ValueError("MCP_PORT must be an integer between 1 and 65535")
    mcp.settings.port = port

    def values(name, defaults):
        raw = os.environ.get(name)
        return [value.strip() for value in raw.split(",") if value.strip()] if raw else defaults

    public_host = [urlparse(PUBLIC_URL).netloc] if AUTH_PROVIDER else ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    public_origin = [AUTH_PROVIDER.origin] if AUTH_PROVIDER else [
        "http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*",
    ]
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=values("MCP_ALLOWED_HOSTS", public_host),
        allowed_origins=values("MCP_ALLOWED_ORIGINS", public_origin),
    )


def main(argv=None):
    """Run stdio or Streamable HTTP; Google login is a separate local command."""
    parser = argparse.ArgumentParser(description="Read-only Google Search Console MCP server")
    parser.add_argument("--reauthenticate", action="store_true", help="Run Google login locally and exit")
    args = parser.parse_args(argv)
    if args.reauthenticate:
        result = asyncio.run(reauthenticate())
        print(result)
        if result.startswith("Error"):
            raise SystemExit(1)
        return

    if TRANSPORT == "stdio":
        mcp.run(transport="stdio")
    elif TRANSPORT in {"streamable-http", "http"}:
        configure_http()
        mcp.run(transport="streamable-http")
    else:
        raise ValueError(
            f"Unknown MCP_TRANSPORT '{TRANSPORT}'. "
            "Use 'stdio' (default) or 'streamable-http' ('http' is an alias). "
            "Legacy SSE transport is no longer supported."
        )


if __name__ == "__main__":
    main()
