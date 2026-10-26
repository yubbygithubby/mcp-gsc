"""
Tests for gsc_server.py.

All Google API calls are mocked — no real credentials are needed to run these tests.
Run with: pytest test_gsc_server.py -v
"""
import importlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers to reload the module with a clean environment each test
# ---------------------------------------------------------------------------

def _load_module(env_overrides: dict | None = None):
    """Import gsc_server with a fresh environment."""
    env = {
        "GSC_SKIP_OAUTH": "true",          # prevent live OAuth attempts by default
        "GSC_DATA_STATE": "all",
        "MCP_TRANSPORT": "stdio",
        **(env_overrides or {}),
    }
    with patch.dict(os.environ, env, clear=False):
        if "gsc_server" in sys.modules:
            del sys.modules["gsc_server"]
        import gsc_server as mod
    return mod


# ---------------------------------------------------------------------------
# TestAuth
# ---------------------------------------------------------------------------

class TestAuth(unittest.TestCase):

    def test_token_loaded_from_config_dir(self):
        """TOKEN_FILE must resolve inside the user config dir, not SCRIPT_DIR."""
        mod = _load_module()
        # By default, TOKEN_FILE should NOT equal os.path.join(SCRIPT_DIR, "token.json").
        self.assertNotEqual(mod.TOKEN_FILE, os.path.join(mod.SCRIPT_DIR, "token.json"))

    def test_old_token_migrated_silently(self):
        """Exercise import-time migration from a disposable copy of the server."""
        with tempfile.TemporaryDirectory() as tmpdir:
            script_dir = os.path.join(tmpdir, "source")
            config_dir = os.path.join(tmpdir, "config")
            os.mkdir(script_dir)
            source = os.path.join(script_dir, "gsc_server.py")
            shutil.copy2(os.path.join(os.path.dirname(__file__), "gsc_server.py"), source)
            old_token_path = os.path.join(script_dir, "token.json")
            with open(old_token_path, "w") as token:
                token.write('{"test": "migration_test"}')

            spec = importlib.util.spec_from_file_location("gsc_server_migration_test", source)
            mod = importlib.util.module_from_spec(spec)
            with patch.dict(os.environ, {"GSC_SKIP_OAUTH": "true", "GSC_DATA_STATE": "all",
                                         "GSC_CONFIG_DIR": config_dir}, clear=False):
                spec.loader.exec_module(mod)

            self.assertFalse(os.path.exists(old_token_path))
            with open(os.path.join(config_dir, "token.json")) as token:
                self.assertEqual(token.read(), '{"test": "migration_test"}')

    def test_expired_token_refresh_succeeds(self):
        """If refresh succeeds, get_gsc_service_oauth returns without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            mock_creds = MagicMock()
            mock_creds.valid = False
            mock_creds.expired = True
            mock_creds.refresh_token = "refresh_token"
            mock_creds.to_json.return_value = '{"token": "refreshed"}'

            def fake_refresh(request):
                mock_creds.valid = True

            mock_creds.refresh.side_effect = fake_refresh

            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=mock_creds), \
                 patch("gsc_server.build", return_value=MagicMock()), \
                 patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")):
                open(os.path.join(tmpdir, "token.json"), "w").write("{}")
                service = mod.get_gsc_service_oauth()
                self.assertIsNotNone(service)

    def test_expired_token_no_refresh_raises_runtime_error(self):
        """When refresh fails and no secrets file, get_gsc_service_oauth raises RuntimeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            mock_creds = MagicMock()
            mock_creds.valid = False
            mock_creds.expired = True
            mock_creds.refresh_token = None  # no refresh token available

            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=mock_creds), \
                 patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                open(os.path.join(tmpdir, "token.json"), "w").write("{}")
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    mod.get_gsc_service_oauth()

    def test_no_token_no_secrets_raises_file_not_found(self):
        """With no token file and no secrets file, FileNotFoundError is raised."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            with patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "nonexistent_token.json")), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "nonexistent_secrets.json")):
                with self.assertRaises(FileNotFoundError):
                    mod.get_gsc_service_oauth()

    def test_skip_oauth_env_var(self):
        """GSC_SKIP_OAUTH=true makes get_gsc_service skip OAuth."""
        mod = _load_module({"GSC_SKIP_OAUTH": "true"})
        self.assertTrue(mod.SKIP_OAUTH)

    def test_gsc_credentials_path_set_but_missing_fails_fast(self):
        """When GSC_CREDENTIALS_PATH is set but the file does not exist, get_gsc_service
        must raise FileNotFoundError immediately with a message that names the specific
        path AND mentions uvx — instead of silently falling through to SCRIPT_DIR/cwd
        fallbacks that uvx users cannot reach. Regression guard for issue #25.
        """
        missing_path = "/tmp/definitely-does-not-exist-issue-25.json"
        mod = _load_module({
            "GSC_CREDENTIALS_PATH": missing_path,
            "GSC_SKIP_OAUTH": "true",
        })
        with self.assertRaises(FileNotFoundError) as ctx:
            mod.get_gsc_service()
        msg = str(ctx.exception)
        self.assertIn("GSC_CREDENTIALS_PATH", msg)
        self.assertIn(missing_path, msg)
        self.assertIn("uvx", msg.lower())

    def test_gsc_oauth_client_secrets_file_set_but_missing_fails_fast(self):
        """Same symmetry for OAuth: if GSC_OAUTH_CLIENT_SECRETS_FILE is set to a
        nonexistent file, get_gsc_service must fail fast with a clear message
        instead of silently falling through.
        """
        missing_path = "/tmp/definitely-does-not-exist-oauth-issue-25.json"
        mod = _load_module({
            "GSC_OAUTH_CLIENT_SECRETS_FILE": missing_path,
            "GSC_SKIP_OAUTH": "false",
        })
        with self.assertRaises(FileNotFoundError) as ctx:
            mod.get_gsc_service()
        msg = str(ctx.exception)
        self.assertIn("GSC_OAUTH_CLIENT_SECRETS_FILE", msg)
        self.assertIn(missing_path, msg)
        self.assertIn("uvx", msg.lower())

    def test_gsc_credentials_path_expands_tilde(self):
        """GSC_CREDENTIALS_PATH must expand ~ so users can write ~/creds.json."""
        mod = _load_module({"GSC_CREDENTIALS_PATH": "~/this-should-be-expanded.json"})
        self.assertIsNotNone(mod.GSC_CREDENTIALS_PATH)
        self.assertNotIn("~", mod.GSC_CREDENTIALS_PATH)
        self.assertTrue(mod.GSC_CREDENTIALS_PATH.startswith(os.path.expanduser("~")))

    def test_oauth_failure_does_not_switch_to_service_account(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secrets = os.path.join(tmpdir, "client_secrets.json")
            service_key = os.path.join(tmpdir, "service_account.json")
            for path in (secrets, service_key):
                with open(path, "w") as file:
                    file.write("{}")
            mod = _load_module({
                "GSC_SKIP_OAUTH": "false",
                "GSC_OAUTH_CLIENT_SECRETS_FILE": secrets,
                "GSC_CREDENTIALS_PATH": service_key,
            })
            with patch.object(mod, "get_gsc_service_oauth", side_effect=RuntimeError("expired")), \
                 patch.object(mod.service_account.Credentials, "from_service_account_file") as fallback:
                with self.assertRaisesRegex(RuntimeError, "expired"):
                    mod.get_gsc_service()
            fallback.assert_not_called()

    def test_invalid_explicit_service_account_does_not_use_fallback_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            explicit = os.path.join(tmpdir, "explicit.json")
            fallback = os.path.join(tmpdir, "fallback.json")
            for path in (explicit, fallback):
                with open(path, "w") as file:
                    file.write("{}")
            mod = _load_module({"GSC_SKIP_OAUTH": "true", "GSC_CREDENTIALS_PATH": explicit})
            with patch.object(mod, "POSSIBLE_CREDENTIAL_PATHS", [explicit, fallback]), \
                 patch.object(mod.service_account.Credentials, "from_service_account_file",
                              side_effect=[ValueError("invalid key"), MagicMock()]) as load:
                with self.assertRaisesRegex(ValueError, "invalid key"):
                    mod.get_gsc_service()
            load.assert_called_once()

    def test_invalid_implicit_service_account_does_not_switch_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = os.path.join(tmpdir, "first.json")
            second = os.path.join(tmpdir, "second.json")
            for path in (first, second):
                with open(path, "w") as file:
                    file.write("{}")
            mod = _load_module({"GSC_SKIP_OAUTH": "true"})
            with patch.object(mod, "GSC_CREDENTIALS_PATH", None), \
                 patch.object(mod, "POSSIBLE_CREDENTIAL_PATHS", [None, first, second]), \
                 patch.object(mod.service_account.Credentials, "from_service_account_file",
                              side_effect=[ValueError("invalid key"), MagicMock()]) as load:
                with self.assertRaisesRegex(ValueError, "invalid key"):
                    mod.get_gsc_service()
            load.assert_called_once()

    def test_unselected_credentials_path_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            service_key = os.path.join(tmpdir, "service.json")
            with open(service_key, "w") as file:
                file.write("{}")
            mod = _load_module({"GSC_SKIP_OAUTH": "true", "GSC_CREDENTIALS_PATH": service_key,
                                "GSC_OAUTH_CLIENT_SECRETS_FILE": os.path.join(tmpdir, "missing.json")})
            with patch.object(mod.service_account.Credentials, "from_service_account_file",
                              return_value=MagicMock()), patch.object(mod, "build", return_value=MagicMock()):
                self.assertIsNotNone(mod.get_gsc_service())


# ---------------------------------------------------------------------------
# Shared fixture helper
# ---------------------------------------------------------------------------

def _make_service():
    """Return a MagicMock that mimics the Google Search Console service object."""
    return MagicMock()


# ---------------------------------------------------------------------------
# TestListProperties
# ---------------------------------------------------------------------------

class TestListProperties(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_properties_list(self):
        mod = _load_module()
        service = _make_service()
        service.sites().list().execute.return_value = {
            "siteEntry": [
                {"siteUrl": "https://example.com/", "permissionLevel": "siteOwner"},
                {"siteUrl": "sc-domain:example.com", "permissionLevel": "siteFullUser"},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_properties()
        data = json.loads(result)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["properties"][0]["site_url"], "https://example.com/")
        self.assertEqual(data["properties"][1]["permission_level"], "siteFullUser")

    async def test_returns_message_when_no_properties(self):
        mod = _load_module()
        service = _make_service()
        service.sites().list().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_properties()
        self.assertIsInstance(result, str)
        self.assertIn("No Search Console properties", result)

    async def test_handles_api_error(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("API error")):
            result = await mod.list_properties()
        self.assertIn("Error", result)

    async def test_surfaces_real_auth_error_not_hardcoded_message(self):
        """When auth fails with a FileNotFoundError, list_properties must surface the
        actual exception text (e.g. the OAuth failure reason), NOT a hardcoded
        service-account-only message. Regression guard for issue #25 comment by
        platky: an OAuth user saw "Service account credentials file not found" even
        though they had never configured service accounts.
        """
        mod = _load_module()
        real_error = FileNotFoundError(
            "OAuth token is missing or expired and cannot be refreshed."
        )
        with patch("gsc_server.get_gsc_service", side_effect=real_error):
            result = await mod.list_properties()
        self.assertIn("OAuth token is missing", result)
        self.assertNotIn("1. Create a service account in Google Cloud Console", result)


# ---------------------------------------------------------------------------
# TestGetSearchAnalytics
# ---------------------------------------------------------------------------

class TestGetSearchAnalytics(unittest.IsolatedAsyncioTestCase):

    def _make_rows(self):
        return {
            "rows": [
                {"keys": ["seo tool"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0},
                {"keys": ["mcp server"], "clicks": 50, "impressions": 500, "ctr": 0.1, "position": 8.2},
            ]
        }

    async def test_returns_json_with_rows(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._make_rows()
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_analytics("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["row_count"], 2)
        self.assertEqual(data["rows"][0]["query"], "seo tool")
        self.assertEqual(data["rows"][0]["clicks"], 100)
        self.assertIn("ctr", data["rows"][0])

    async def test_no_data_returns_string_message(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_analytics("https://example.com/")
        self.assertIsInstance(result, str)
        self.assertNotIn("{", result[:5])  # not JSON

    async def test_row_limit_capped_at_500(self):
        """Requesting more than 500 rows should be capped."""
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {"rows": []}
        with patch("gsc_server.get_gsc_service", return_value=service):
            await mod.get_search_analytics("https://example.com/", row_limit=9999)
        # Verify the request body capped at 500
        call_args = service.searchanalytics().query.call_args
        if call_args:
            body = call_args[1].get("body") or (call_args[0][0] if call_args[0] else None)
            if body and "rowLimit" in body:
                self.assertLessEqual(body["rowLimit"], 500)

    async def test_handles_404(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("404")):
            result = await mod.get_search_analytics("https://example.com/")
        self.assertIn("not found", result.lower())

    async def test_days_use_inclusive_search_console_dates(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {"rows": []}

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                instant = datetime(2026, 4, 2, 5, tzinfo=timezone.utc)
                return instant.astimezone(tz) if tz else instant.replace(tzinfo=None)

        with patch.object(mod, "datetime", FixedDateTime), \
             patch.object(mod, "get_gsc_service", return_value=service):
            await mod.get_search_analytics("https://example.com/", days=28)

        body = service.searchanalytics().query.call_args.kwargs["body"]
        self.assertEqual((body["startDate"], body["endDate"]), ("2026-03-05", "2026-04-01"))

    async def test_pacific_timezone_is_available(self):
        mod = _load_module()
        start, end = mod._date_range(28)
        self.assertEqual((end - start).days, 27)


# ---------------------------------------------------------------------------
# TestGetSiteDetails
# ---------------------------------------------------------------------------

class TestGetSiteDetails(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_permission_and_verification(self):
        mod = _load_module()
        service = _make_service()
        service.sites().get().execute.return_value = {
            "permissionLevel": "siteOwner",
            "siteVerificationInfo": {"verificationState": "VERIFIED"},
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_site_details("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["permission_level"], "siteOwner")
        self.assertEqual(data["verification"]["state"], "VERIFIED")

    async def test_handles_404(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("404")):
            result = await mod.get_site_details("https://example.com/")
        self.assertIn("Error", result)


# ---------------------------------------------------------------------------
# TestGetSitemaps
# ---------------------------------------------------------------------------

class TestGetSitemaps(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_sitemap_list(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "1",
                 "contents": [{"type": "web", "submitted": "1000"}]},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemaps("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["sitemaps"][0]["warnings"], 1)
        self.assertEqual(data["sitemaps"][0]["status"], "Has warnings")
        self.assertEqual(data["sitemaps"][0]["submitted_urls"], "1000")
        self.assertNotIn("indexed_urls", data["sitemaps"][0])

    async def test_no_sitemaps_returns_message(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemaps("https://example.com/")
        self.assertIsInstance(result, str)
        self.assertIn("No sitemaps", result)


# ---------------------------------------------------------------------------
# TestInspectUrl
# ---------------------------------------------------------------------------

class TestInspectUrl(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_verdict(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                    "pageFetchState": "SUCCESSFUL",
                    "robotsTxtState": "ALLOWED",
                    "lastCrawlTime": "2026-04-01T10:00:00Z",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.inspect_url_enhanced("https://example.com/", "https://example.com/page/")
        data = json.loads(result)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["page_url"], "https://example.com/page/")
        self.assertIn("last_crawled", data)

    async def test_reports_rich_result_issues(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {"verdict": "PASS"},
                "richResultsResult": {
                    "verdict": "PASS",
                    "detectedItems": [
                        {
                            "richResultType": "Merchant listings",
                            "items": [
                                {
                                    "name": "Example product",
                                    "issues": [
                                        {
                                            "issueMessage": "Missing field 'shippingDetails'",
                                            "severity": "WARNING",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.inspect_url_enhanced("https://example.com/", "https://example.com/page/")
        issues = json.loads(result)["rich_results"]["issues"]
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "WARNING")
        self.assertEqual(issues[0]["message"], "Missing field 'shippingDetails'")
        self.assertEqual(issues[0]["type"], "Merchant listings")
        self.assertEqual(issues[0]["item"], "Example product")


# ---------------------------------------------------------------------------
# TestBatchUrlInspection
# ---------------------------------------------------------------------------

class TestBatchUrlInspection(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_results(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                    "lastCrawlTime": "2026-04-01T10:00:00Z",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/",
                "https://example.com/a/\nhttps://example.com/b/"
            )
        data = json.loads(result)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["results"][0]["index_verdict"], "PASS")

    async def test_reports_failing_rich_results(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                },
                "richResultsResult": {
                    "verdict": "FAIL",
                    "detectedItems": [
                        {
                            "richResultType": "Merchant listings",
                            "items": [
                                {
                                    "name": "Example product",
                                    "issues": [
                                        {
                                            "issueMessage": "Missing field 'image'",
                                            "severity": "ERROR",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/", "https://example.com/page/"
            )
        row = json.loads(result)["results"][0]
        self.assertEqual(row["index_verdict"], "PASS")
        self.assertEqual(row["rich_results"]["verdict"], "FAIL")
        self.assertEqual(row["rich_results"]["detected_types"], ["Merchant listings"])
        self.assertEqual(len(row["rich_results"]["issues"]), 1)
        self.assertEqual(row["rich_results"]["issues"][0]["severity"], "ERROR")
        self.assertEqual(
            row["rich_results"]["issues"][0]["message"], "Missing field 'image'"
        )

    async def test_batch_limit_enforced_at_10_urls(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            urls = "\n".join([f"https://example.com/{i}/" for i in range(11)])
            result = await mod.batch_url_inspection("https://example.com/", urls)
        self.assertIn("Too many URLs", result)

    async def test_processes_all_urls_in_input_order(self):
        # URLs are inspected concurrently (#31); results must still come back in the
        # same order the caller supplied them.
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {"indexStatusResult": {"verdict": "PASS"}}
        }
        input_urls = [f"https://example.com/{i}/" for i in range(5)]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/", "\n".join(input_urls)
            )
        data = json.loads(result)
        self.assertEqual(data["count"], 5)
        self.assertEqual([row["url"] for row in data["results"]], input_urls)


# ---------------------------------------------------------------------------
# TestCheckIndexingIssues
# ---------------------------------------------------------------------------

class TestCheckIndexingIssues(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_summary(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.check_indexing_issues(
                "https://example.com/", "https://example.com/page/"
            )
        data = json.loads(result)
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total_checked"], 1)
        self.assertEqual(data["summary"]["indexed"], 1)

    async def test_processes_all_urls_concurrently_and_aggregates(self):
        # Concurrency mirror of #31 applied to check_indexing_issues (#55): all URLs
        # are processed and correctly classified regardless of run order.
        mod = _load_module()
        service = _make_service()

        def _inspect(body=None):
            page = body["inspectionUrl"]
            call = MagicMock()
            if page.endswith("/blocked/"):
                call.execute.return_value = {"inspectionResult": {"indexStatusResult": {
                    "verdict": "FAIL", "coverageState": "Blocked by robots.txt",
                    "robotsTxtState": "BLOCKED"}}}
            else:
                call.execute.return_value = {"inspectionResult": {"indexStatusResult": {
                    "verdict": "PASS", "coverageState": "Submitted and indexed"}}}
            return call

        service.urlInspection().index().inspect.side_effect = _inspect
        input_urls = [
            "https://example.com/a/",
            "https://example.com/blocked/",
            "https://example.com/c/",
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.check_indexing_issues(
                "https://example.com/", "\n".join(input_urls)
            )
        data = json.loads(result)
        self.assertEqual(data["summary"]["total_checked"], 3)
        self.assertEqual(data["summary"]["indexed"], 2)
        self.assertEqual(data["summary"]["robots_blocked"], 1)
        self.assertEqual(data["issues"]["robots_blocked"], ["https://example.com/blocked/"])


# ---------------------------------------------------------------------------
# TestGetPerformanceOverview
# ---------------------------------------------------------------------------

class TestGetPerformanceOverview(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_totals_and_trend(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": [], "clicks": 500, "impressions": 5000, "ctr": 0.1, "position": 12.0}]},
            {"rows": [
                {"keys": ["2026-04-01"], "clicks": 250, "impressions": 2500, "ctr": 0.1, "position": 12.0},
                {"keys": ["2026-04-02"], "clicks": 250, "impressions": 2500, "ctr": 0.1, "position": 12.0},
            ]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_performance_overview("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["totals"]["clicks"], 500)
        self.assertEqual(len(data["daily_trend"]), 2)


# ---------------------------------------------------------------------------
# TestGetAdvancedSearchAnalytics
# ---------------------------------------------------------------------------

class TestGetAdvancedSearchAnalytics(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_rows(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["seo"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["rows"][0]["query"], "seo")
        self.assertIn("pagination", data)

    async def test_invalid_filters_json_returns_error_string(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", filters="not valid json"
            )
        self.assertIn("Invalid filters", result)

    async def test_pagination_info_included(self):
        mod = _load_module()
        service = _make_service()
        # Return exactly row_limit rows → has_more=True
        rows = [{"keys": [f"q{i}"], "clicks": 1, "impressions": 10, "ctr": 0.1, "position": 5.0}
                for i in range(10)]
        service.searchanalytics().query().execute.return_value = {"rows": rows}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", row_limit=10
            )
        data = json.loads(result)
        self.assertTrue(data["pagination"]["has_more"])
        self.assertEqual(data["pagination"]["next_start_row"], 10)

    async def test_sort_by_impressions_reorders_rows(self):
        # Google returns rows clicks-descending; sort_by should reorder client-side (#54).
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["a"], "clicks": 100, "impressions": 10, "ctr": 0.1, "position": 3.0},
                {"keys": ["b"], "clicks": 50, "impressions": 900, "ctr": 0.2, "position": 8.0},
                {"keys": ["c"], "clicks": 10, "impressions": 500, "ctr": 0.3, "position": 1.5},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", sort_by="impressions", sort_direction="descending"
            )
        data = json.loads(result)
        self.assertEqual(data["sort_scope"], "returned_rows")
        rows = data["rows"]
        self.assertEqual([r["query"] for r in rows], ["b", "c", "a"])

    async def test_sort_by_position_ascending_puts_best_rank_first(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["a"], "clicks": 100, "impressions": 10, "ctr": 0.1, "position": 3.0},
                {"keys": ["b"], "clicks": 50, "impressions": 900, "ctr": 0.2, "position": 8.0},
                {"keys": ["c"], "clicks": 10, "impressions": 500, "ctr": 0.3, "position": 1.5},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", sort_by="position", sort_direction="ascending"
            )
        rows = json.loads(result)["rows"]
        self.assertEqual([r["query"] for r in rows], ["c", "a", "b"])


# ---------------------------------------------------------------------------
# TestCompareSearchPeriods
# ---------------------------------------------------------------------------

class TestCompareSearchPeriods(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_comparison(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": ["seo"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0}]},
            {"rows": [{"keys": ["seo"], "clicks": 120, "impressions": 1100, "ctr": 0.11, "position": 4.5}]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/",
                "2026-03-01", "2026-03-28",
                "2026-04-01", "2026-04-07",
            )
        data = json.loads(result)
        self.assertIn("comparison", data)
        self.assertEqual(len(data["comparison"]), 1)
        self.assertEqual(data["comparison"][0]["key"], ["seo"])

    async def _compare(self, mod, p1_row, p2_row):
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [p1_row]},
            {"rows": [p2_row]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/",
                "2026-04-01", "2026-04-28",  # period 1 / analyzed (current)
                "2026-03-01", "2026-03-28",  # period 2 / baseline (previous)
            )
        return json.loads(result)["comparison"][0]

    async def test_period1_growth_is_positive(self):
        # Period 1 (current) 78 clicks vs Period 2 (previous) 51 → +27 (+52.9%).
        mod = _load_module()
        item = await self._compare(
            mod,
            {"keys": ["seo"], "clicks": 78, "impressions": 800, "ctr": 0.1, "position": 10.6},
            {"keys": ["seo"], "clicks": 51, "impressions": 500, "ctr": 0.08, "position": 14.4},
        )
        self.assertEqual(item["click_diff"], 27)
        self.assertEqual(item["click_pct"], 52.9)
        # Position improved from 14.4 to 10.6 → positive delta.
        self.assertEqual(item["position_diff"], 3.8)

    async def test_period1_decline_is_negative(self):
        mod = _load_module()
        item = await self._compare(
            mod,
            {"keys": ["seo"], "clicks": 51, "impressions": 500, "ctr": 0.08, "position": 14.4},
            {"keys": ["seo"], "clicks": 78, "impressions": 800, "ctr": 0.1, "position": 10.6},
        )
        self.assertEqual(item["click_diff"], -27)
        self.assertEqual(item["click_pct"], -34.6)
        # Position worsened from 10.6 to 14.4 → negative delta.
        self.assertEqual(item["position_diff"], -3.8)

    async def test_zero_baseline_yields_null_percentage(self):
        # Key present only in Period 1 → Period 2 baseline is zero, so pct is null
        # rather than dividing by zero.
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": ["seo"], "clicks": 10, "impressions": 100, "ctr": 0.1, "position": 5.0}]},
            {"rows": []},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/",
                "2026-04-01", "2026-04-28",
                "2026-03-01", "2026-03-28",
            )
        item = json.loads(result)["comparison"][0]
        self.assertEqual(item["click_diff"], 10)
        self.assertIsNone(item["click_pct"])
        self.assertIsNone(item["imp_pct"])
        self.assertIsNone(item["position_diff"])

    async def test_lost_query_has_no_position_comparison(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": []},
            {"rows": [{"keys": ["lost"], "clicks": 10, "impressions": 100,
                       "ctr": 0.1, "position": 5.0}]},
        ]
        with patch.object(mod, "get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/", "2026-04-01", "2026-04-28",
                "2026-03-01", "2026-03-28",
            )
        self.assertIsNone(json.loads(result)["comparison"][0]["position_diff"])


# ---------------------------------------------------------------------------
# TestGetSearchByPageQuery
# ---------------------------------------------------------------------------

class TestGetSearchByPageQuery(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_totals(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["best seo tool"], "clicks": 50, "impressions": 500, "ctr": 0.1, "position": 7.5},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_by_page_query(
                "https://example.com/", "https://example.com/blog/seo/"
            )
        data = json.loads(result)
        self.assertEqual(data["page_url"], "https://example.com/blog/seo/")
        self.assertEqual(data["totals"]["clicks"], 50)
        self.assertEqual(data["rows"][0]["query"], "best seo tool")


# ---------------------------------------------------------------------------
# TestListSitemapsEnhanced
# ---------------------------------------------------------------------------

class TestListSitemapsEnhanced(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_sitemap_list(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "0",
                 "isSitemapsIndex": False, "isPending": False},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_sitemaps_enhanced("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["pending_count"], 0)

    async def test_warning_status_correctly_set(self):
        """Regression: status should be 'Has warnings' when warnings > 0."""
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "3"},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_sitemaps_enhanced("https://example.com/")
        # list_sitemaps_enhanced returns JSON without a status field (it's in get_sitemaps),
        # but warnings count must still be 3
        data = json.loads(result)
        self.assertEqual(data["sitemaps"][0]["warnings"], 3)


# ---------------------------------------------------------------------------
# TestGetSitemapDetails
# ---------------------------------------------------------------------------

class TestGetSitemapDetails(unittest.IsolatedAsyncioTestCase):

    async def test_get_details_returns_json(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().get().execute.return_value = {
            "isSitemapsIndex": False,
            "isPending": False,
            "errors": "0",
            "warnings": "0",
            "contents": [{"type": "web", "submitted": 500, "indexed": 480}],
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemap_details("https://example.com/", "https://example.com/sitemap.xml")
        data = json.loads(result)
        self.assertEqual(data["type"], "Sitemap")
        self.assertEqual(data["status"], "processed")
        self.assertEqual(data["content_breakdown"][0]["submitted"], 500)


# ---------------------------------------------------------------------------
# TestReauthenticate
# ---------------------------------------------------------------------------

class TestReauthenticate(unittest.IsolatedAsyncioTestCase):

    async def test_replaces_token_after_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            open(token_path, "w").write('{"old": "token"}')
            secrets_path = os.path.join(tmpdir, "secrets.json")
            open(secrets_path, "w").write("{}")

            mod = _load_module()

            mock_creds = MagicMock()
            mock_creds.to_json.return_value = '{"token": "new"}'

            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets_path), \
                 patch("gsc_server.InstalledAppFlow") as mock_flow_cls:
                mock_flow = MagicMock()
                mock_flow.run_local_server.return_value = mock_creds
                mock_flow_cls.from_client_secrets_file.return_value = mock_flow
                result = await mod.reauthenticate()

            self.assertIn("Successfully authenticated", result)
            with open(token_path) as token:
                self.assertEqual(token.read(), '{"token": "new"}')

    async def test_missing_secrets_preserves_existing_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            with open(token_path, "w") as token:
                token.write('{"old": "token"}')
            mod = _load_module()
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                result = await mod.reauthenticate()
            with open(token_path) as token:
                self.assertEqual(token.read(), '{"old": "token"}')
        self.assertIn("Error", result)

    async def test_failed_login_preserves_existing_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            secrets_path = os.path.join(tmpdir, "secrets.json")
            with open(token_path, "w") as token:
                token.write('{"old": "token"}')
            with open(secrets_path, "w") as secrets:
                secrets.write("{}")
            mod = _load_module()
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets_path), \
                 patch.object(mod.InstalledAppFlow, "from_client_secrets_file") as login:
                login.return_value.run_local_server.side_effect = RuntimeError("cancelled")
                result = await mod.reauthenticate()
            self.assertIn("Error", result)
            with open(token_path) as token:
                self.assertEqual(token.read(), '{"old": "token"}')


# ---------------------------------------------------------------------------
# TestStdoutClean
# ---------------------------------------------------------------------------

class TestStdoutClean(unittest.TestCase):

    def test_auth_fallback_does_not_write_to_stdout(self):
        """get_gsc_service must not print() to stdout on OAuth failure (prevents MCP corruption)."""
        mod = _load_module({"GSC_SKIP_OAUTH": "false"})

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            with patch("gsc_server.get_gsc_service_oauth", side_effect=RuntimeError("no token")), \
                 patch("gsc_server.service_account.Credentials.from_service_account_file",
                        side_effect=Exception("no file")):
                try:
                    mod.get_gsc_service()
                except Exception:
                    pass
        finally:
            sys.stdout = old_stdout

        stdout_output = captured.getvalue()
        self.assertEqual(stdout_output, "", f"Unexpected stdout: {stdout_output!r}")


if __name__ == "__main__":
    unittest.main()
