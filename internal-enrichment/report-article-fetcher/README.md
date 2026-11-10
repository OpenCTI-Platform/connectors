# OpenCTI Report Article Fetcher

Fills the **Content** of a report with the full article behind its external
reference. Its main use is the reports an RSS feed ingestion creates, which
only carry the feed's teaser: by default, only those are enriched
(`match_single_reference` extends it to any report with one external
reference).

| Type | Internal enrichment, scope `Report` |
|---|---|
| Playbook | Compatible: always sends the report back, filled or unchanged |

## What it does

1. **Finds the article link.** By default, only the external reference written
   by the RSS ingestion is used: its `source_name` is the report name and its
   description ends with `Retrieved <date>.`. With `match_single_reference`, a
   report with exactly one external reference is accepted too, whatever created
   it. A report with no candidate, or several, is left unchanged. External references are shared by every report citing the
   same URL, so the trigger is the report, never the reference.
2. **Fetches the page over plain HTTP.** Every address the host resolves to must
   be public (no loopback, private, link-local or metadata address), at each
   redirect, and so must the address the connection actually reaches, which
   defeats DNS rebinding. HTML only, 5 MB at most, 20 s timeout, `<meta refresh>` stubs
   followed.
3. **Keeps the article body** with [trafilatura](https://trafilatura.readthedocs.io)
   (Apache-2.0): no menus, footers, cookie banners or comments; tables, lists,
   code and links kept.
   Three layouts that would lose indicators are reworked first: tables nested in
   wrapper `<div>`s (Google Docs exports) are lifted out, the `embed` classes
   around tables (Webflow) are dropped, and indicators listed one per `<div>`
   become a list.
4. **Checks it is the article**: not an anti-bot or consent page, at least 500
   characters, and matching the report (page title, the report name's words at
   the top of the text, or the URL slug). When the report's content is already
   filled, the article must also be 1.5 times longer than it, so a full text is
   never replaced by less; an empty content replaces nothing.
5. **Writes the body to the report's content** through a bundle, so confidence
   levels and playbooks apply. The description is left as it is.

## Trigger it

Through a playbook (*report created*, filtered on the feed's author or the
ingestion's user, then this connector) or by manual enrichment. Keep
`CONNECTOR_AUTO=false`: in automatic mode every report created would be tried.

## Configuration

The generic `OPENCTI_*` and `CONNECTOR_*` variables are those of every internal
enrichment connector (see `docker-compose.yml`). The connector's own settings,
all optional, use the `REPORT_ARTICLE_FETCHER_` prefix:

| Variable | Default | Description |
|---|---|---|
| `REPORT_ARTICLE_FETCHER_USER_AGENT` | `OpenCTI Report Article Fetcher` | User-Agent sent when fetching article pages |
| `REPORT_ARTICLE_FETCHER_REQUEST_TIMEOUT` | `20` | Timeout of one page request, in seconds |
| `REPORT_ARTICLE_FETCHER_MAX_DOWNLOAD_SIZE` | `5000000` | Largest page downloaded, in bytes |
| `REPORT_ARTICLE_FETCHER_MIN_LENGTH` | `500` | Shortest article accepted, in characters of text |
| `REPORT_ARTICLE_FETCHER_LENGTH_RATIO` | `1.5` | How many times longer than the report's current content the article must be |
| `REPORT_ARTICLE_FETCHER_MIN_TITLE_SIMILARITY` | `0.6` | Lowest match accepted between the report name and the page, from 0 to 1 |
| `REPORT_ARTICLE_FETCHER_MATCH_SINGLE_REFERENCE` | `false` | Also enrich reports not created by an RSS ingestion when they have exactly one external reference |

## Evaluation

Run on the 3 latest items of the 69 RSS feeds of the XTM Hub catalog and 14
other security feeds (2026-11-03): every page reachable over plain HTTP was
fetched, no headless browser needed, in 0.1 to 3 s. On 162 pages fetched by
both this connector and Import External Reference, the same pages were
retrieved; the whole-page Markdown of Import External Reference held a median
45% of non-article text (menus, footers, related posts), which this connector
leaves out, with as many indicators kept.

## Known limits

- Sponsored blocks inside an article are kept (Bleeping Computer).
- A feed item linking to an anchor of an index page is accepted (XPN).
- Pages behind an anti-bot challenge or a consent wall are not fetched: the
  connector never tries to get around them.
- PDF articles are not handled.
