---
name: indexing-audit
description: Audit indexing status across top pages. Use when asked about crawling,
  indexing issues, or whether pages are indexed by Google.
---

# Indexing Audit

Audit the indexing status of the top pages on a site and produce a prioritized action list.

## Steps

1. Call `list_properties` to confirm the exact `site_url`.
2. Call `get_search_analytics` with `dimensions=page` and `row_limit=20` to identify the 20 most-clicked pages.
3. Extract the list of page URLs from the results.
4. Call `check_indexing_issues` with up to 10 URLs at a time. Run twice if needed to cover all 20 pages.
5. Use `indexed_urls` and the `not_indexed`, `canonical_issues`, `robots_blocked`, and `fetch_issues` lists to categorize pages. A page can appear in more than one issue list.
   Treat `not_indexed` entries containing ` - Error:` as unknown inspection results; retry them instead of reporting an indexing loss.
6. Call `inspect_url_enhanced` for pages with issues when you need the exact `coverage_state`, `page_fetch_state`, `robots_txt_state`, `google_canonical`, or `user_canonical`.

## Output format

Present as a prioritized action list:

1. **Critical** — Not indexed pages that previously had clicks
2. **High** — Canonical mismatches on high-traffic pages
3. **Medium** — Robots.txt or fetch blocks
4. **Low** — Soft exclusions on low-traffic pages

Include a summary table: page URL | indexing status | issue | recommended action.
