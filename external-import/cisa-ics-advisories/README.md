# OpenCTI CISA ICS Advisories Connector

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
- [Usage](#usage)
- [Behavior](#behavior)
- [Debugging](#debugging)

## Introduction

[CISA Industrial Control Systems Advisories (ICSA/ICSMA)](https://www.cisa.gov/news-events/ics-advisories) are the
U.S. government's free, authoritative feed of vulnerabilities affecting operational technology, industrial control
systems, and SCADA products — published as structured
[CSAF](https://oasis-open.github.io/csaf-documentation/) documents in the
[cisagov/CSAF](https://github.com/cisagov/CSAF) repository.

There is no commercial cost to this data, but no existing connector imports it: OpenCTI's OT/ICS coverage today is
limited to the commercial `dragos` connector and the general-purpose `cisa-known-exploited-vulnerabilities`
connector (which is not ICS-specific). This connector fills that gap.

It polls the ICS Advisories RSS feed, resolves each advisory's linked CSAF JSON document, and imports it as a STIX
`Report` referencing per-CVE `Vulnerability` objects, the affected vendor/product `Identity` and `Software` objects,
and the relationships between them.

## Installation

### Requirements

- pycti `==7.260811.0`

## Configuration variables

Configuration is handled through `config.yml` (Docker/production) or `.env` (local development). See
`config.yml.sample` / `.env.sample`.

### OpenCTI environment variables

| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                     |
|---------------|---------------|------------------------------|-----------|--------------------------------------------------|
| OpenCTI URL   | `url`         | `OPENCTI_URL`                 | Yes       | The URL of the OpenCTI platform.                  |
| OpenCTI Token | `token`       | `OPENCTI_TOKEN`               | Yes       | The default admin token set in the OpenCTI docker-compose. |

### Connector extra parameters

| Parameter                        | config.yml               | Docker environment variable        | Default                                                       | Mandatory | Description                                                                 |
|-----------------------------------|---------------------------|--------------------------------------|----------------------------------------------------------------|-----------|------------------------------------------------------------------------------|
| Feed URL                          | `feed_url`                 | `CISA_ICS_FEED_URL`                    | `https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml` | No        | The CISA ICS Advisories RSS feed.                                             |
| CSAF raw base URL                 | `csaf_org_raw_base`        | `CISA_ICS_CSAF_ORG_RAW_BASE`           | `https://raw.githubusercontent.com/cisagov/CSAF/develop/`      | No        | Base URL used to resolve each advisory's raw CSAF JSON document.             |
| Max advisories per run            | `max_advisories_per_run`   | `CISA_ICS_MAX_ADVISORIES_PER_RUN`      | `100`                                                           | No        | Safety ceiling on advisories processed per run.                              |
| TLP                                | `tlp`                       | `CISA_ICS_TLP`                          | `TLP:CLEAR`                                                     | No        | TLP marking applied to imported objects.                                     |

## Deployment

### Docker

```shell
docker compose up -d
```

### Manual/VM

```shell
pip3 install -r src/requirements.txt
cd src && python3 main.py
```

## Usage

Once running, the connector polls the ICS Advisories feed on the schedule set by `connector.duration_period`
(default every 4 hours — CISA publishes new advisories on a regular cadence). No manual interaction is required
after configuration.

## Behavior

For each new advisory (tracked by ID in connector state so re-runs are idempotent):

1. Fetch the advisory's CSAF JSON via the link embedded in the RSS `<description>`.
2. Walk `product_tree` to build a `product_id -> {vendor, product}` map.
3. For each `vulnerabilities[]` entry with a CVE: create a `Vulnerability`, and for each affected `product_id` in
   `product_status.known_affected`, create (or reuse, de-duplicated within the advisory) the vendor `Identity` and
   product `Software`, and a `has` relationship from Software to Vulnerability.
4. Create a `Report` for the advisory referencing every object produced from it.

Advisories with no CVE-bearing vulnerabilities are skipped (nothing meaningful to import).

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for verbose output. The connector logs a summary (advisories imported, total
tracked) at the end of each run via `helper.log_info`.

## Additional information

- CISA maintains no fixed publication schedule; the safety ceiling (`max_advisories_per_run`) protects the first run
  after a backlog builds (e.g. connector downtime).
- The connector deliberately relies on Suricata/OpenCTI-agnostic, spec-shaped CSAF fields (`product_tree`,
  `vulnerabilities[].cve`, `.notes`, `.product_status`) rather than free-text parsing, so it should be resilient to
  cosmetic changes in advisory wording.
