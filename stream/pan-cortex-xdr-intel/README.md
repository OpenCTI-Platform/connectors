# OpenCTI Palo Alto Cortex XDR Intel Connector

| Status | Date | Comment |
|--------|------|---------|
| Filigran Verified | 2026-09-17 | -       |

## Table of Contents

- [OpenCTI Palo Alto Cortex XDR Intel Connector](#opencti-palo-alto-cortex-xdr-intel-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Behavior](#behavior)
    - [Supported actions](#supported-actions)
    - [Data flow](#data-flow)
      - [Score to severity mapping](#score-to-severity-mapping)
    - [Supported observable types](#supported-observable-types)
    - [Dissemination assurance (deployment write-back)](#dissemination-assurance-deployment-write-back)
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

#### Score to severity mapping

On upsert, the OpenCTI indicator's `score` (0-100) is mapped to the Cortex XDR IOC `severity`
as follows:

| OpenCTI score | Cortex XDR severity |
| ------------- | -------------------- |
| `80` - `100` | `SEV_040_HIGH` |
| `60` - `79` | `SEV_030_MEDIUM` |
| `40` - `59` | `SEV_020_LOW` |
| `20` - `39` | `SEV_010_INFO` |
| `0` - `19` | *(no severity sent; Cortex XDR applies its own default)* |

When the indicator has no `score` at all, no `severity` is sent either and Cortex XDR applies its
own default.

### Supported observable types

| STIX observable | Cortex XDR IOC type |
| --------------- | -------------------- |
| `Domain-Name` | `DOMAIN_NAME` |
| `IPv4-Addr` | `IP` |
| `StixFile` (hashes only, e.g. `MD5`, `SHA-1`, `SHA-256`) | `HASH` |
| `Email-Addr` | `EMAIL_ADDRESS` |
| `Url` | `URL` |

Any other observable type (e.g. `Hostname`, `IPv6-Addr`) is out of scope for this
connector's MVP and is silently filtered out when building the indicator's observables.
`IPv6-Addr` is intentionally excluded because Cortex XDR's `IP` IOC type only accepts IPv4
values and rejects IPv6 ones. A
`StixFile` observable is a supported type, but only its hash(es) are mapped to a Cortex XDR IOC:
a `StixFile` with only a `name` and no hash passes the type filter but still yields no IOC (see
[Unsupported observable handling](#unsupported-observable-handling)).

### Dissemination assurance (deployment write-back)

The connector reports to OpenCTI whether each indicator is actually live in Cortex XDR. The status is stored on the
`deployed-on` relationship between the indicator and the `Palo Alto Cortex XDR` Security Platform entity (created if it
does not exist), and detection hits are counted with a sighting of the indicator on that entity.

| When                                        | Reported to OpenCTI                                                                                       |
|---------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Indicator upserted in Cortex XDR            | `deployed`, with the Cortex XDR `rule_id` of its first IOC as external id                                 |
| Indicator rejected by Cortex XDR            | `failed`, with the API error, the HTTP status and the Cortex XDR response                                 |
| Indicator without any supported observable  | Nothing: the indicator is never pushed                                                                    |
| Delete event processed                      | `removed` (also when the IOC was already absent from Cortex XDR); a failed deletion is not reported      |
| Reconciliation, indicator present           | `active`                                                                                                  |
| Reconciliation, indicator absent            | `removed` (deleted or expired in Cortex XDR)                                                              |
| Reconciliation, `pending` (analyst retry)   | The indicator is upserted again and reported `deployed` or `failed`                                       |
| Reconciliation, withdrawal or expiry        | Revoked, expired or withdrawn indicators still present are deleted from Cortex XDR and reported `removed` |
| Hits                                        | IOC alerts (`alert_source` `XDR IOC`) whose events carry the value of a deployed indicator                |

- **Reconciliation**: every `DEPLOYMENT_RECONCILIATION_INTERVAL` minutes, the IOCs of the tenant are read back with the
  `indicators/get` API (100 per call, `search_from` / `search_to`); IOCs whose `expiration_date` is in the past are not
  live. Cortex XDR does not store the OpenCTI id, so deployments are matched by `rule_id`, then by value. A read-back
  error, or a page repeated by the API, skips the run: indicators are never reported `removed` from a partial listing.
- **Hits**: during each reconciliation, the IOC alerts created since the previous run are read with their events
  (`alerts/get_alerts_multi_events`, oldest creation time first, at most 10,000 per run: a capped read is complete until
  the creation time of the newest alert read and the next run resumes there, so no alert is lost). An alert counts one hit for every deployed indicator whose
  value is one of its IP addresses, host names, DNS queries, email addresses or file hashes (domain indicators match the
  host of a URL value); hits already reported are never counted twice.
- **IOC validation requests**: OpenAEV runs the benign validation tests requested in OpenCTI and writes their results;
  the requests only target indicators this connector reports `deployed` or `active`. The two analyst requests carried by
  a deployment are handled by the reconciliation: a retry (`pending`) upserts the indicator again, a withdrawal deletes
  it from Cortex XDR.
- **Permissions**: the API key role needs **Threat Management -> Detections -> Rules** (**View/Edit**, already required)
  and **Investigation -> Incidents and Alerts** (**View**) to report hits; without the latter, set
  `HITS_REPORTING_ENABLED=false`.
- **Graceful degradation**: on OpenCTI platforms without the deployment write-back API the feature is a no-op (logged
  once). Write-back errors are logged as warnings and never block the dissemination.

| Environment variable                 | Default                | Description                                                           |
|--------------------------------------|------------------------|-----------------------------------------------------------------------|
| `DEPLOYMENT_REPORTING_ENABLED`       | `true`                 | Report the deployment status of the pushed indicators.                |
| `DEPLOYMENT_RECONCILIATION_INTERVAL` | `60`                   | Minutes between two reconciliations, `0` disables the reconciliation. |
| `HITS_REPORTING_ENABLED`             | `true`                 | Report the IOC alert hits of the deployed indicators.                 |
| `SECURITY_PLATFORM_NAME`             | `Palo Alto Cortex XDR` | Name of the Security Platform entity in OpenCTI.                      |
| `SECURITY_PLATFORM_TYPE`             | `XDR`                  | Type of the Security Platform entity (`security_platform_type_ov`).   |
| `SECURITY_PLATFORM_ID`               |                        | Id of an existing Security Platform entity, used instead of the name. |

## Installation

### Requirements

- OpenCTI Platform >= 7.260811.0
- A Palo Alto Cortex XDR tenant with API access enabled
- A Cortex XDR API Key (**Advanced** security level) and its associated Key ID
- A role granting **Threat Management -> Detections -> Rules** with the **View/Edit** permission, plus
  **Investigation -> Incidents and Alerts** with the **View** permission to report hits (see
  [Dissemination assurance](#dissemination-assurance-deployment-write-back)); everything else can stay disabled

### Getting the Cortex XDR API base URL

The connector's `api_base_url` is built from your Cortex XDR tenant's FQDN:

1. In the Cortex XDR management console, go to **Settings** -> **Configurations** -> **API Keys**.
2. Note your tenant's FQDN, displayed at the top of the API Keys page (e.g. `xdr.eu.paloaltonetworks.com`).
3. Prefix it with `api-` and `https://` to build the base URL, i.e. `https://api-<fqdn>`.

See [Get Your FQDN](https://cortex-docs.paloaltonetworks.com/xdr-5-api/get-your-fqdn) for details.

### Getting the Cortex XDR API credentials

1. In the Cortex XDR management console, go to **Settings** -> **Configurations** -> **API Keys** -> **New Key**.
2. Select **Advanced** as the security level (**Standard** keys are not supported by this connector).
3. Assign the key a role that grants **Threat Management -> Detections -> Rules** with the **View/Edit**
   permission: it covers reading, inserting/updating and deleting IOCs. Hit reporting also needs
   **Investigation -> Incidents and Alerts** with the **View** permission (or set `HITS_REPORTING_ENABLED=false`).
   All other permissions can stay disabled (least privilege).
4. Copy the generated **API Key** (`api_key`) and its **Key ID** (`api_key_id`); the API Key is only shown once
   and cannot be retrieved again.
5. Use these values, together with the base URL above, to sign every request: the Key ID is sent as the
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
| Connector exits right after startup or after processing one event; logs show a 401/403 Cortex XDR error | Invalid, revoked, or **Standard** (non-Advanced) API key, or a key whose role lacks **Threat Management -> Detections -> Rules** (**View/Edit**) | Generate an **Advanced** API key/Key ID pair with a role granting **Threat Management -> Detections -> Rules** (**View/Edit**) (see [Getting the Cortex XDR API credentials](#getting-the-cortex-xdr-api-credentials)) and update `PAN_CORTEX_XDR_INTEL_API_KEY`/`PAN_CORTEX_XDR_INTEL_API_KEY_ID` |
| Same as above but with a 429 error | Cortex XDR API rate limit exceeded (not currently configurable from the connector side) | Restart the connector; if the issue persists, contact Filigran support |
| Logs repeatedly show `No supported observable(s) found in indicator, skipping it` | The indicator's observables are all of an unsupported type (e.g. `Hostname`) | Expected behavior for unspported observable types; no action needed unless those indicators are expected to be pushed to Cortex XDR |
| Logs repeatedly show `No Cortex XDR IOC could be extracted from any observable, skipping indicator` | The indicator only has `StixFile` observable(s) without any hash (e.g. only a `name`) | Expected behavior since only hashes are mapped for `StixFile`; no action needed unless those indicators are expected to be pushed to Cortex XDR |
| `delete` events never reach Cortex XDR | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` is set to `false` | Set `CONNECTOR_LIVE_STREAM_LISTEN_DELETE=true` (the default) |
| Logs show `[DEPLOYMENT] Cannot read the detections from the vendor` | The API key role lacks **Investigation -> Incidents and Alerts** (**View**) | Grant the permission, or set `HITS_REPORTING_ENABLED=false` |
| Logs show `[DEPLOYMENT] Cannot read the indicators back from the vendor, reconciliation skipped.` | The IOC read-back failed (permission, rate limit, server error); no status was changed | Check the error in the log; the next reconciliation retries |
| Connector exits with `Failed to parse stream event's data payload as JSON` or `Failed to parse indicator and/or observables from stream event` | Unexpected OpenCTI/`pycti` stream payload shape (e.g. a breaking upstream change) | This should not happen; please report the issue with the connector's logs |
