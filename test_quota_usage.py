import asyncio
import json
from unittest.mock import Mock

from quota_usage import execute_tracked, usage_report


def test_parallel_workers_and_nested_tools_count_once():
    @usage_report
    async def child():
        await asyncio.to_thread(execute_tracked, Mock(), "url_inspection")
        return "{}"

    @usage_report
    async def parent():
        await asyncio.gather(*(child() for _ in range(10)))
        return "{}"

    result = json.loads(asyncio.run(parent()))
    assert result["api_usage"]["attempted_requests"]["url_inspection"] == 10
    assert result["api_usage"]["remaining_property_quota"] is None


def test_failed_attempts_and_concurrent_calls_are_isolated():
    @usage_report
    async def report():
        try:
            await asyncio.to_thread(execute_tracked,
                                    Mock(execute=Mock(side_effect=RuntimeError("quota"))),
                                    "search_analytics")
        except RuntimeError:
            pass
        return "quota error"

    async def run():
        return await asyncio.gather(report(), report())

    for result in asyncio.run(run()):
        usage = json.loads(result.split("\n", 1)[1])["api_usage"]
        assert usage["attempted_requests"]["search_analytics"] == 1
