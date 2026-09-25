# OpenCTI DNSlytics Connector

| Status            | Date | Comment |
|-------------------|------|---------|
| Community         | -    | -       |

Run [DNSlytics](https://dnslytics.com) domain searches from OpenCTI and ingest the matching domains with their IPs, Autonomous System and hosting provider.

## Table of Contents

- [Introduction](#introduction)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing without spending credits](#testing-without-spending-credits)
- [Limits](#limits)

## Introduction

An investigator hunting lookalike news sites runs a query such as `(name:*daily* OR name:*news*) AND (name:*armenia*)` on search.dnslytics.com. This connector runs the same query from OpenCTI. The query is stored as a hunting rule: an **Indicator** with pattern type `dnslytics`. Enriching the Indicator brings the matching domains into the graph, each with its IPs, its AS and a `provider:<AS name>` label.

## How it works

One enrichment of an Indicator with `pattern_type` = `dnslytics`:

1. **Search.** One call to `GET /v2/dataset/domains?q=<pattern>&page=1` (10 credits). The pattern is sent verbatim. All hits on page 1 are ingested, up to 1,000. There is no paging.
2. **Hosting** (when `DNSLYTICS_RESOLVE_HOSTING=true`). Each active domain is resolved (DNS A and AAAA, free). The unique IPs are sent to DNSlytics IP2ASN (free) to get the announcing AS.
3. **Output**, per hit:

| From | Object | Link |
|---|---|---|
| `domain` | Domain-Name, external reference `https://search.dnslytics.com/domain/<domain>` | Indicator `based-on` Domain-Name |
| `active` | label `dnslytics:active` / `dnslytics:dropped` | on the Domain-Name |
| DNS A / AAAA | IPv4-Addr / IPv6-Addr | Domain-Name `resolves-to` IP |
| IP2ASN | Autonomous-System (`number`, `name`) | IP `belongs-to` AS |
| AS name | label `provider:<AS name>` | on the Domain-Name, one per distinct provider |

Every created object is marked with `DNSLYTICS_OUTPUT_TLP_LEVEL` and created by the `DNSlytics` organization. Ids are deterministic, so re-enriching the same Indicator creates no duplicates.

For every active domain that resolves, the `resolves-to` and `belongs-to` relationships and the `provider:` label are mandatory, with one exception:

- **IP not announced in global routing.** No AS exists, so the domain keeps its `resolves-to` link but gets no `belongs-to` and no `provider:` label. This is a **warning**: the work succeeds and its message lists these domains.
- **IP2ASN failed, or the AS has no name.** This is an **error**. The bundle is still sent, but the work is marked in error and lists the incomplete domains.

The work message is the run summary, for example `created 1000 of 40000 matches, 10 credits`. The connector creates no Note.

Indicators with another pattern type (STIX, YARA, ...) get the answer `not a DNSlytics query` and no API call is made.

### The `dnslytics` pattern type

The OpenCTI UI only offers pattern types listed in the `pattern_type_ov` vocabulary. At start-up, the connector checks that `dnslytics` is in it and creates it if missing. This is idempotent.

If the connector's user cannot manage vocabularies, the connector logs one warning and keeps running. Add the entry by hand in **Settings > Vocabularies > pattern_type_ov**, or give the connector's group the capability to manage vocabularies.

## Installation

### Requirements

- OpenCTI Platform >= 7.260921.0
- A DNSlytics API key with premium credits (10 credits per enrichment)

### Docker deployment

Use the [docker-compose.yml](docker-compose.yml) and set the variables below. Keep `CONNECTOR_AUTO=false`: each run costs 10 credits.

### Manual deployment

```bash
cd src
pip install -r requirements.txt
python main.py
```

The configuration is read from environment variables (or an `.env` file).

## Configuration

See [`__metadata__/CONNECTOR_CONFIG_DOC.md`](__metadata__/CONNECTOR_CONFIG_DOC.md) for the full, generated list. Regenerate it with `make connector_config_schema` after any change to `src/connector/settings.py`.

| Variable | Default | Meaning |
|---|---|---|
| `DNSLYTICS_API_KEY` | required | DNSlytics API key |
| `DNSLYTICS_RESOLVE_HOSTING` | `true` | Resolve IPs, look up the AS, set the `provider:` label. `false`: domains and active/dropped label only. |
| `DNSLYTICS_MAX_TLP_LEVEL` | `green` | Do not enrich Indicators marked above this level |
| `DNSLYTICS_OUTPUT_TLP_LEVEL` | `clear` | Marking on every created object |
| `DNSLYTICS_API_BASE_URL` | `https://api.dnslytics.net` | Leave unchanged. For tests only: point it at the local mock server (see below). |

Plus the standard `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`, `CONNECTOR_NAME`, `CONNECTOR_SCOPE` (default `Indicator`), `CONNECTOR_LOG_LEVEL` and `CONNECTOR_AUTO`.

## Usage

**One click.** Create an Indicator with pattern type `dnslytics` and the query as pattern, for example:

- Name: `Storm-1516 Armenian news lookalikes`
- Pattern: `(name:*daily* OR name:*news*) AND (name:*armenia*)`

Open its enrichment menu and pick DNSlytics. The domains appear in the Indicator's Knowledge tab.

**Playbook.** Use the trigger `Indicator created` filtered on `pattern_type = dnslytics`, then an enrichment step with DNSlytics, then Send for ingestion. Every new rule runs by itself. Re-running a rule picks up new hits and does not duplicate old ones.

**Provider breakdown.** A widget counting Domain-Names by label, filtered on labels starting with `provider:`, shows which hosting providers a campaign uses.

## Testing without spending credits

Only one call costs credits: `v2/dataset/domains`, 10 credits each. DNS, IP2ASN and AccountInfo are free. Test in this order, from free to paid:

1. **Unit tests, offline, 0 credits.** Every DNSlytics answer is a fixture. The IP2ASN fixtures are real answers for `armeniadaily.am`.

   ```bash
   pip install -r tests/test-requirements.txt
   pytest tests/
   ```

2. **Free live checks, 0 credits.** [`tools/live_check.py`](tools/live_check.py) reuses the connector's client and hosting code against the real services:

   ```bash
   python tools/live_check.py                     # DNS + IP2ASN for armeniadaily.am
   DNSLYTICS_API_KEY=... python tools/live_check.py   # + key check and credit balance
   ```

3. **One paid call, 10 credits, recorded once.** Runs the query once, reads the balance before and after (free) to show the real cost, and saves the answer:

   ```bash
   DNSLYTICS_API_KEY=... python tools/live_check.py --spend-one-call --record recording.json
   ```

   The recording can then be replayed for free, as often as needed:
   - **Kill-line sample.** `python tools/live_check.py --from-recording recording.json --sample 100 --csv sample.csv` writes the IPs, AS and provider of 100 active domains, with their DNSlytics web URL, for the comparison by hand.
   - **End to end on a real OpenCTI.** `python tools/mock_dnslytics_server.py --dataset recording.json` serves the recording as the DNSlytics API. Deploy the connector with `DNSLYTICS_API_BASE_URL=http://host.docker.internal:8000` and enrich Indicators as often as needed. DNS and IP2ASN stay real.

## Limits

- One call per enrichment, page 1 only: at most 1,000 domains. Beyond that, the work message shows the truncation (`created 1000 of 40000 matches`).
- The client allows at most 30 DNSlytics requests per minute. HTTP 429 and 503 are retried twice. HTTP 403 is never retried.
- IP2ASN is free but capped at 2,500 calls per day. The connector counts its calls and stops at the cap. Each unique IP costs one call.
- The API key is sent as a query parameter, as DNSlytics requires. It is never logged.
