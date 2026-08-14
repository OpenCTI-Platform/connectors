# OpenCTI XposedOrNot Connector

<!--
General overview of the connector:
* What it does: enrich Email-Addr observables with data-breach exposure from XposedOrNot
* Works without any API key (free community API); optional key raises rate limits
-->

Table of Contents

- [OpenCTI XposedOrNot Connector](#opencti-xposedornot-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Legal and privacy notice](#legal-and-privacy-notice)
  - [Debugging](#debugging)

## Introduction

[XposedOrNot](https://xposedornot.com) is an open, free data-breach search service tracking 760+ known breaches. Given an email address it returns the breaches the address appears in, with per-breach detail: breach date, records exposed, exposed data classes, affected domain, industry and password-storage risk, plus an overall risk score.

This internal-enrichment connector enriches `Email-Addr` observables with that exposure data. **No API key or registration is required** — the free community API is used by default. An optional commercial key ([console.xposedornot.com](https://console.xposedornot.com)) switches the connector to the Plus API with higher rate limits.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- No XposedOrNot account or API key needed (optional key for higher volume)

## Configuration variables

Full configuration reference: [`__metadata__/CONNECTOR_CONFIG_DOC.md`](__metadata__/CONNECTOR_CONFIG_DOC.md).

Key parameters:

| Parameter | Docker env var | Mandatory | Default | Description |
|-----------|----------------|-----------|---------|-------------|
| OpenCTI URL | `OPENCTI_URL` | Yes | | The OpenCTI platform URL. |
| OpenCTI Token | `OPENCTI_TOKEN` | Yes | | Token of the connector user. |
| Connector Auto | `CONNECTOR_AUTO` | No | `false` | Automatic enrichment. The keyless API allows 2 req/s and 25/hour per IP — keep manual, or configure an API key before enabling on busy platforms. |
| API key | `XPOSEDORNOT_API_KEY` | No | *(empty)* | Optional key; switches to the Plus API with higher limits. Fully functional without it. |
| Base URL | `XPOSEDORNOT_API_BASE_URL` | No | `https://api.xposedornot.com` | Free community API base URL. |
| Max TLP | `XPOSEDORNOT_MAX_TLP` | No | `TLP:AMBER` | Maximum TLP of an observable the connector may enrich (the email address is sent to the API). |
| TLP level | `XPOSEDORNOT_TLP_LEVEL` | No | `amber` | TLP marking applied to the produced objects. |

## Deployment

### Docker Deployment

Use the provided `docker-compose.yml` (or add the service to your OpenCTI stack):

```shell
docker compose up -d
```

### Manual Deployment

```shell
# From the connector root directory (internal-enrichment/xposedornot):
pip3 install -r src/requirements.txt
cp config.yml.sample config.yml   # then edit config.yml
python3 -m src
```

## Usage

On an `Email-Addr` observable, click the enrichment button and select the XposedOrNot connector (or set `CONNECTOR_AUTO=true` — mind the rate limits above). The connector is playbook-compatible.

## Behavior

For a breached email address, the connector enriches in place — no extra entities are created, keeping the graph clean:

- the observable's **score** is set from the XposedOrNot risk score (0–100, free API);
- **labels** `data-breach` — and `plaintext-password-exposure` when at least one breach stored passwords in plaintext — are added to the observable;
- an **external reference** to xposedornot.com is attached;
- a markdown **Note** is attached with the full breach table: breach name, date, records exposed, affected domain, exposed data classes, password-storage risk and verification status, plus first/latest exposure years and totals.

A clean email (not found in any breach) completes with an explicit "no known breach exposure" message and modifies nothing. Rate limiting (HTTP 429) is retried with backoff honoring `Retry-After`; persistent rate limiting fails that single enrichment with a log message recommending the optional key — the connector itself keeps running.

## Legal and privacy notice

Only the observable's email address is sent, over TLS, to xposedornot.com — nothing else leaves the platform. Breach exposure tied to an email address is **personal information**: gate what may be enriched with `XPOSEDORNOT_MAX_TLP`, apply a restrictive `XPOSEDORNOT_TLP_LEVEL` to results, and use them only within lawful, authorised investigations (GDPR / legal basis / proper investigative framework). See the [XposedOrNot privacy policy](https://xposedornot.com/privacy).

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. All API errors are logged through the connector logger with masked context; the API key never appears in logs. Typical messages:

- `XposedOrNot rate limited (keyless: 2/s, 25/hour); backing off.` — expected under keyless bursts; configure a key for volume.
- `XposedOrNot: API key rejected or missing for the Plus API` — check `XPOSEDORNOT_API_KEY`.
