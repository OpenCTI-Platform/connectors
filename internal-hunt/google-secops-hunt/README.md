# OpenCTI Google SecOps Hunt Connector

The Google SecOps hunt connector executes the hunts of OpenCTI on Google Security Operations (SecOps, formerly
Chronicle) as UDM searches or YARA-L 2.0 rule tests. It is a connector of type `INTERNAL_HUNT` registered for the
`google-secops` hunt platform.

## Before you start

| | |
|---|---|
| Credential | The JSON key of a Google Cloud service account. |
| Console | Google Cloud console: **APIs & Services > Library**, **IAM & Admin > Service accounts**, **IAM & Admin > IAM**; SecOps: **SIEM Settings > Profile**. |
| Network | `chronicle.googleapis.com` (or its regional endpoint) and `oauth2.googleapis.com` reachable from the connector. |

Step by step:

1. In the Google Cloud project of the SecOps instance, **APIs & Services > Library**: enable the **Chronicle API**.
2. In **IAM & Admin > Service accounts > Create service account**, create `opencti-hunt`.
3. In **IAM & Admin > IAM > Grant access**, give the service account the role **Chronicle API Editor** (`roles/chronicle.editor`), as for the other Google SecOps connectors; a custom role holding the UDM search and rule test permissions works as well.
4. In the service account, **Keys > Add key > Create new key > JSON**, and copy its `private_key`, `private_key_id`, `client_email`, `client_id` and `client_x509_cert_url` values into the configuration.
5. In SecOps, **SIEM Settings > Profile**: copy the project ID, the region (`us`, `europe`, `asia-southeast1`...) and the customer ID (instance UUID).

Least-privilege permissions:

| Permission | Why |
|---|---|
| Role `roles/chronicle.editor` (Chronicle API Editor) on the project | Run the UDM searches and test the YARA-L rules of the hunts: a test runs the rule over the window without saving it, enabling it or creating alerts. |
| Chronicle API enabled on the project | Every call of the connector goes through it. |

The connector only reads: it never saves, enables nor alerts on a rule.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
GOOGLE_SECOPS_HUNT_PROJECT_ID=my-project
GOOGLE_SECOPS_HUNT_PROJECT_REGION=us
GOOGLE_SECOPS_HUNT_PROJECT_INSTANCE=ChangeMe-instance-UUID
GOOGLE_SECOPS_HUNT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nChangeMe\n-----END PRIVATE KEY-----\n"
GOOGLE_SECOPS_HUNT_PRIVATE_KEY_ID=ChangeMe
GOOGLE_SECOPS_HUNT_CLIENT_EMAIL=opencti-hunt@my-project.iam.gserviceaccount.com
GOOGLE_SECOPS_HUNT_CLIENT_ID=ChangeMe
```

Once the connector runs, open it in OpenCTI (**Data > Ingestion > Connectors**) and click **Test connection** on its **Hunted platform** card. It requests a token and runs one UDM search. A missing permission is named in plain words, with what to grant; a hunt run refused by the platform reports the same sentence.

Table of Contents

- [OpenCTI Google SecOps Hunt Connector](#opencti-google-secops-hunt-connector)
  - [Before you start](#before-you-start)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Google Cloud permissions](#google-cloud-permissions)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Query languages](#query-languages)
  - [Behavior](#behavior)
  - [Limits](#limits)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

A hunt is a falsifiable hypothesis plus the logic to test it: a canonical Sigma rule and, optionally, a native query
per platform. For every hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. takes the native UDM search or YARA-L rule of the hunt for Google SecOps, or translates its Sigma rule with
   [pySigma](https://github.com/SigmaHQ/pySigma) and the
   [SecOps backend](https://github.com/AttackIQ/pySigma-backend-secops);
2. runs it through the Chronicle API over the run time window, within the run timeout and result limit;
3. sends the resulting knowledge to OpenCTI: a sighting of every technique and indicator of the hunt on the Google
   SecOps Security Platform identity, and observed-data referencing the IOC observables found in the results;
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave SecOps: OpenCTI only receives counts and evidence values that are SHA-256 hashed and truncated.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261002.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- A Google SecOps instance bound to a Google Cloud project with the Chronicle API (`chronicle.googleapis.com`)
  enabled, reachable from the connector.

### Google Cloud permissions

The account, the least-privilege permissions, the console steps and a configuration example are in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Google SecOps Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `google-secops` | No | Hunt platform slug, keep `google-secops`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `Google SecOps` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per instance. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `SIEM` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Project ID | `google_secops_hunt.project_id` | `GOOGLE_SECOPS_HUNT_PROJECT_ID` | | Yes | Google Cloud project ID of the SecOps instance. |
| Region | `google_secops_hunt.project_region` | `GOOGLE_SECOPS_HUNT_PROJECT_REGION` | | Yes | Region of the SecOps instance, e.g. `us` or `europe`. |
| Customer ID | `google_secops_hunt.project_instance` | `GOOGLE_SECOPS_HUNT_PROJECT_INSTANCE` | | Yes | Customer ID (instance UUID) of SecOps. |
| Private key | `google_secops_hunt.private_key` | `GOOGLE_SECOPS_HUNT_PRIVATE_KEY` | | Yes | Service account private key (PEM); literal `\n` sequences are turned into newlines. |
| Private key ID | `google_secops_hunt.private_key_id` | `GOOGLE_SECOPS_HUNT_PRIVATE_KEY_ID` | | Yes | Service account private key ID. |
| Client email | `google_secops_hunt.client_email` | `GOOGLE_SECOPS_HUNT_CLIENT_EMAIL` | | Yes | Service account client email. |
| Client ID | `google_secops_hunt.client_id` | `GOOGLE_SECOPS_HUNT_CLIENT_ID` | | Yes | Service account client ID. |
| Client certificate URL | `google_secops_hunt.client_cert_url` | `GOOGLE_SECOPS_HUNT_CLIENT_CERT_URL` | | No | Service account `client_x509_cert_url`. |
| API URL | `google_secops_hunt.base_url` | `GOOGLE_SECOPS_HUNT_BASE_URL` | `https://chronicle.googleapis.com` | No | Chronicle API URL; the region is prefixed to the host at runtime. |
| Auth URI | `google_secops_hunt.auth_uri` | `GOOGLE_SECOPS_HUNT_AUTH_URI` | `https://accounts.google.com/o/oauth2/auth` | No | OAuth2 auth URI of the service account. |
| Token URI | `google_secops_hunt.token_uri` | `GOOGLE_SECOPS_HUNT_TOKEN_URI` | `https://oauth2.googleapis.com/token` | No | OAuth2 token URI of the service account. |
| Auth provider certificates | `google_secops_hunt.auth_provider_cert` | `GOOGLE_SECOPS_HUNT_AUTH_PROVIDER_CERT` | `https://www.googleapis.com/oauth2/v1/certs` | No | OAuth2 auth provider certificates URL. |
| Query language | `google_secops_hunt.query_language` | `GOOGLE_SECOPS_HUNT_QUERY_LANGUAGE` | `udm` | No | Language Sigma rules are translated into: `udm` or `yara-l`. |
| Sigma pipeline | `google_secops_hunt.sigma_pipeline` | `GOOGLE_SECOPS_HUNT_SIGMA_PIPELINE` | `secops_udm` | No | pySigma pipeline(s), chained with `+`: `secops_udm` or `none`. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-google-secops-hunt:latest
```

Replace the `ChangeMe` values of `docker-compose.yml` with your configuration, then start the container:

```shell
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on `config.yml.sample`, replace the `ChangeMe` values, install the dependencies
(preferably in a virtual environment) and start the connector from the `src` directory:

```shell
pip3 install -r requirements.txt
python3 main.py
```

## Usage

At startup the connector registers the `google-secops` hunt platform in OpenCTI with the `udm` and `yara-l` languages
and the Security Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from OpenCTI
(manually, on schedule, when the threat landscape changes or from playbooks), and their runs appear in the hunt detail
page. A preview run only translates the hunt logic: the translated query is shown in OpenCTI and SecOps is never
queried.

## Query languages

The connector executes `udm` and `yara-l`.

- **Sigma rules** are translated into `GOOGLE_SECOPS_HUNT_QUERY_LANGUAGE` with the `secops_udm` pipeline, which maps
  the Sigma log sources and fields to UDM (`CommandLine` becomes `target.process.command_line`...).
  In `udm`, the result is a UDM search, and Sigma documents with several rules are joined with `OR`. In `yara-l`, the
  result is a complete YARA-L 2.0 rule, and each Sigma rule must be its own hunt.
- **Native queries** written for the `google-secops` platform are executed verbatim in their language:
  - `udm`: a UDM search (`principal.hostname = "ws1" AND target.ip = "203.0.113.7"`), as typed in the SecOps search
    bar;
  - `yara-l`: a complete YARA-L 2.0 rule (`rule name { meta: ... events: ... condition: ... }`), single-event or
    multi-event with a `match` section.

## Behavior

1. The run window is passed to SecOps as the time range of the search or rule test (no time condition is added to
   the query text).
2. A UDM search returns at most `max_results` events; when SecOps holds more (`moreDataAvailable`), the result is
   marked truncated.
3. A YARA-L rule is tested over the window (`legacyRunTestRule`, the same as the rule editor test): every detection
   counts as one hit and contributes the UDM events it references. At most `max_results` detections are returned;
   when SecOps reports too many detections, the result is marked truncated. Compilation and runtime errors of the
   rule fail the run with the SecOps message.
4. Events matching a benign pattern of the hunt are suppressed.
5. With hits, the connector sends one sighting per technique and indicator of the hunt (`where_sighted_refs` = the
   Google SecOps Security Platform, `count` = hits, `first_seen` / `last_seen` = first and last event) and one
   observed-data per public IP address, domain, URL, file hash or email address found, with the number of result events
   holding it, restricted to the observable types the hunt expects. Objects inherit the
   markings and author of the hunt and have deterministic identifiers; those of the sightings and observed-data derive
   from the hunt run too, so a retry of a run updates its own objects and two runs never share one.
6. The run is reported with the hit count, the distinct hosts, users and network peers, the query executed and an
   evidence sample. UDM bookkeeping fields (`metadata.id`, `metadata.product_log_id`, ingestion and collection times,
   log types...) are never sampled; host names, user names and command lines only appear hashed and truncated in the
   evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Limits

| Limit | Value |
|---|---|
| Results read per run | `limits.max_results` of the run (set by OpenCTI), at most 10,000 UDM events or YARA-L detections (the Chronicle API maximum). |
| Run timeout | `limits.timeout_seconds` of the run: the token request (at most 30 seconds) and the search or rule test are bounded by the time left. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |
| Chronicle API quotas | UDM searches and rule tests count against the quotas of the SecOps instance; set `CONNECTOR_MAX_CONCURRENT_RUNS` to stay within them. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed events, objects
sent) or failure. Failed runs are reported to OpenCTI with the SecOps error message (for example the compilation
error of an invalid YARA-L rule, a `PERMISSION_DENIED` of a missing role, or a failed Google authentication).

## Additional information

- UDM search is the default because it returns the matching events directly; choose `yara-l` to hunt with
  multi-event correlation (`match` over a time window) or to reuse detection rules.
- One connector instance executes against one SecOps instance. Deploy one instance (with its own Security Platform
  name) per SecOps instance to hunt.
