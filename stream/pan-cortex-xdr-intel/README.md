# OpenCTI Palo Alto Cortex XDR Intel Connector

## Table of Contents

- [OpenCTI Palo Alto Cortex XDR Intel Connector](#opencti-palo-alto-cortex-xdr-intel-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Behavior](#behavior)
    - [Supported actions](#supported-actions)
    - [Data flow](#data-flow)
    - [Supported observable types](#supported-observable-types)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Getting the Cortex XDR API base URL](#getting-the-cortex-xdr-api-base-url)
    - [Getting the Cortex XDR API credentials](#getting-the-cortex-xdr-api-credentials)
  - [Configuration variables](#configuration-variables)
  - [Operational guidance](#operational-guidance)
    - [Log interpretation](#log-interpretation)
    - [Idempotency](#idempotency)
    - [Unsupported observable handling](#unsupported-observable-handling)
  - [Troubleshooting](#troubleshooting)


## Introduction

Palo Alto Cortex XDR is an extended detection and response (XDR) platform that integrates endpoint,
network, and cloud data to detect, investigate, and respond to threats across the enterprise.

This connector listens to an OpenCTI live stream and synchronizes indicators as Indicators of
Compromise (IOCs) in Palo Alto Cortex XDR.

## Behavior

### Supported actions

Only STIX **Indicator** entities are processed; any other entity type (e.g. Malware, Identity)
received on the stream is skipped with a `warning` log.

The connector reacts to the following live stream events on Indicator entities:

| OpenCTI event | Cortex XDR action |
| ------------- | ------------------ |
| `create` / `update` | Upsert: insert the indicator's IOC(s), or update them if they already exist |
| `delete` | Delete the indicator's IOC(s) |

Any other event type (e.g. a custom event) is skipped with a `warning` log.

`delete` events require `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` to be enabled (`true` by default,
see [Configuration variables](#configuration-variables)); when disabled, OpenCTI never emits
delete events on the stream and this connector never removes IOCs from Cortex XDR.

### Data flow

1. OpenCTI's live stream emits an event for an Indicator create/update/delete.
2. The indicator's `observable_values` extension attribute is normalized into the connector's
   internal representation, keeping only observables of a [supported type](#supported-observable-types).
3. Each supported observable is mapped to a Cortex XDR IOC (`type` + `indicator` value).
4. On upsert, the indicator's `score`, `valid_until` and `description` are additionally mapped to
   the IOC's `severity`, `expiration_date` and `comment`, and `reputation` is hardcoded to `BAD`
   (see [Idempotency](#idempotency) for how updates to an already-existing IOC are handled).
5. The resulting IOC(s) are sent to Cortex XDR in a single batched API call
   (`insert_iocs` for upsert, `delete_iocs` for delete).

An indicator whose observables map to **no** supported Cortex XDR IOC at all is skipped (see
[Unsupported observable handling](#unsupported-observable-handling)).

### Supported observable types

| STIX observable | Cortex XDR IOC type |
| --------------- | -------------------- |
| `Domain-Name` | `DOMAIN_NAME` |
| `IPv4-Addr` / `IPv6-Addr` | `IP` |
| `StixFile` (hashes only, e.g. `MD5`, `SHA-1`, `SHA-256`) | `HASH` |

Any other observable type (e.g. `Hostname`, `Email-Addr`, `Url`) is out of scope for this
connector's MVP and is silently filtered out when building the indicator's observables. A
`StixFile` observable is a supported type, but only its hash(es) are mapped to a Cortex XDR IOC:
a `StixFile` with only a `name` and no hash passes the type filter but still yields no IOC (see
[Unsupported observable handling](#unsupported-observable-handling)).

## Installation

### Requirements

- OpenCTI Platform >= 7.260811.0
- A Palo Alto Cortex XDR tenant with API access enabled
- A Cortex XDR API Key (**Advanced** security level) and its associated Key ID

### Getting the Cortex XDR API base URL

The connector's `api_base_url` is built from your Cortex XDR tenant's FQDN:

1. In the Cortex XDR management console, go to **Settings** -> **Configurations** -> **API Keys**.
2. Note your tenant's FQDN, displayed at the top of the API Keys page (e.g. `xdr.eu.paloaltonetworks.com`).
3. Prefix it with `api-` and `https://` to build the base URL, i.e. `https://api-<fqdn>`.

See [Get Your FQDN](https://cortex-docs.paloaltonetworks.com/xdr-5-api/get-your-fqdn) for details.

### Getting the Cortex XDR API credentials

1. In the Cortex XDR management console, go to **Settings** -> **Configurations** -> **API Keys** -> **New Key**.
2. Select **Advanced** as the security level (**Standard** keys are not supported by this connector).
3. Copy the generated **API Key** (`api_key`) and its **Key ID** (`api_key_id`); the API Key is only shown once
   and cannot be retrieved again.
4. Use these values, together with the base URL above, to sign every request: the Key ID is sent as the
   `x-xdr-auth-id` header, and the Key is used to compute the `Authorization` header.

See [Make Your First API Call](https://cortex-docs.paloaltonetworks.com/xdr-5-api/make-your-first-api-call)
for further details on Cortex XDR API authentication.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding these variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Operational guidance

### Log interpretation

| Level | When | Example message |
| ----- | ---- | ---------------- |
| `warning` | An unsupported stream event or entity type is received (event skipped), or none of an indicator's observables are of a supported type (indicator skipped) | `Unsupported event type, skipping it` / `Unsupported entity type, skipping it` / `No supported observable(s) found in indicator, skipping it` |
| `debug` | Right before an upsert/delete API call is sent to Cortex XDR | `Upserting IOC(s) into Cortex XDR` / `Deleting IOC(s) from Cortex XDR` |
| `info` | An indicator was successfully parsed, upserted, or deleted | `Parsed observable(s) from stream event` / `Successfully upserted IOC(s) into Cortex XDR` / `Successfully deleted IOC(s) from Cortex XDR` |
| `error` (indicator-scoped, stream continues) | The indicator has supported-type observable(s) but none of them could still be mapped to a Cortex XDR IOC (e.g. a `StixFile` without any hash), or the Cortex XDR API rejects one specific event (e.g. an invalid IOC value) | `No Cortex XDR IOC could be extracted from any observable, skipping indicator` / `Error while hitting Cortex XDR API. Skipping event and continuing with the next one.` |
| `error` (fatal, connector exits) | A stream payload could not be parsed/validated, or the Cortex XDR API returned an authentication, authorization, not-found, rate-limit, or server error (401/403/404/429/5xx) | `Failed to parse stream event's data payload as JSON` / `Failed to parse indicator and/or observables from stream event` / `Error while hitting Cortex XDR API` |

A fatal error stops the connector process on purpose, to avoid exhausting or silently
mis-processing the live stream while a systemic issue (e.g. a revoked API key, or an
unexpected breaking change in the stream payload) remains unresolved; the connector must be
restarted manually once the root cause is fixed.

### Idempotency

- **Upsert**: before inserting an IOC, the connector looks up any existing Cortex XDR IOC with
  the same indicator value. If found, its `rule_id` is included in the following insert call so
  Cortex XDR *updates* the existing IOC in place instead of failing with a 400 "IOC indicator
  exists" error. Replaying the same `create`/`update` event is therefore safe.
- **Delete**: Cortex XDR's delete API is inherently idempotent — deleting an IOC that no longer
  exists (e.g. already deleted) does not raise. Replaying the same `delete` event is safe.

### Unsupported observable handling

Observables of an unsupported type (see [Supported observable types](#supported-observable-types))
are filtered out silently, without any log, when the indicator is parsed. If this filtering
leaves the indicator with **no** observable at all, the connector logs a `warning` and skips that
specific indicator, without stopping the stream — this is expected behavior, not a runtime error.

A supported-type observable can still fail to yield a Cortex XDR IOC (e.g. a `StixFile` with only
a `name` and no hash). If **all** of an indicator's supported-type observables end up in this
situation, the connector logs an `error` (instead of a `warning`) and skips the indicator, since
this points to an unexpected data shape rather than the normal type-filtering behavior.

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| Connector exits right after startup or after processing one event; logs show a 401/403 Cortex XDR error | Invalid, revoked, or **Standard** (non-Advanced) API key | Generate an **Advanced** API key/Key ID pair (see [Getting the Cortex XDR API credentials](#getting-the-cortex-xdr-api-credentials)) and update `PAN_CORTEX_XDR_INTEL_API_KEY`/`PAN_CORTEX_XDR_INTEL_API_KEY_ID` |
| Same as above but with a 429 error | Cortex XDR API rate limit exceeded (not currently configurable from the connector side) | Restart the connector; if the issue persists, contact Filigran support |
| Logs repeatedly show `No supported observable(s) found in indicator, skipping it` | The indicator's observables are all of an unsupported type (e.g. `Hostname`, `Email-Addr`, `Url`) | Expected behavior for unspported observable types; no action needed unless those indicators are expected to be pushed to Cortex XDR |
| Logs repeatedly show `No Cortex XDR IOC could be extracted from any observable, skipping indicator` | The indicator only has `StixFile` observable(s) without any hash (e.g. only a `name`) | Expected behavior since only hashes are mapped for `StixFile`; no action needed unless those indicators are expected to be pushed to Cortex XDR |
| `delete` events never reach Cortex XDR | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` is set to `false` | Set `CONNECTOR_LIVE_STREAM_LISTEN_DELETE=true` (the default) |
| Connector exits with `Failed to parse stream event's data payload as JSON` or `Failed to parse indicator and/or observables from stream event` | Unexpected OpenCTI/`pycti` stream payload shape (e.g. a breaking upstream change) | This should not happen; please report the issue with the connector's logs |
