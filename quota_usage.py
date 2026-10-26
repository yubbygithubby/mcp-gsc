"""Per-tool request accounting, without claiming a global Google quota balance."""
from contextvars import ContextVar
from functools import wraps
import json
import threading

EFFICIENCY_INSTRUCTIONS = """
Manage Search Console requests efficiently. Reuse results already fetched in this
conversation when their property, dates, filters and freshness satisfy the request.
Fetch aggregate reports before drilling into individual pages. Prefer one grouped
query over separate queries for every page; paginate only as needed. Use the
shortest date range that answers the question. Avoid repeatedly fetching large
page-and-query reports. Inspect only relevant URLs, deduplicate them, and reuse
inspection results instead of running both inspection tools on the same URLs.
Before a large audit, explain the expected request count and inspection daily share.
On quota errors stop the affected workflow; do not retry in a tight loop. For a
short-term Search Analytics load error, wait 15 minutes before trying again.
Summarize api_usage counts across the tools used for each user request. Report
observed requests, not an invented remaining balance. Search Analytics has a
published 1,200 requests/minute/property limit; inspection has 2,000/day/property
and 600/minute/property. All users and other applications share property quotas.
Google also applies user/project and unpublished load limits. Per-call counts
cannot establish quota remaining. No extra quota-check API call is needed.
"""

_current = ContextVar("gsc_request_usage", default=None)


def execute_tracked(request, category):
    usage = _current.get()
    if usage is not None:
        with usage["lock"]:
            usage["counts"][category] += 1
    return request.execute()


def usage_report(func):
    @wraps(func)
    async def wrapped(*args, **kwargs):
        if _current.get() is not None:
            return await func(*args, **kwargs)
        usage = {"lock": threading.Lock(), "counts": {
            "search_analytics": 0, "url_inspection": 0, "other": 0}}
        token = _current.set(usage)
        try:
            result = await func(*args, **kwargs)
        finally:
            _current.reset(token)
        report = {
            "source": "observed_requests_this_tool_call",
            "attempted_requests": usage["counts"],
            "remaining_property_quota": None,
            "note": "Counts include failed attempts; other users/apps are not observed. "
                    "Google quota remaining and processing-load usage are unknown.",
        }
        try:
            data = json.loads(result)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict):
            data["api_usage"] = report
            return json.dumps(data)
        return result + "\n" + json.dumps({"api_usage": report})
    return wrapped
