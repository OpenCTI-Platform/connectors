# OpenCTI Internal Enrichment Connector: AlienVault OTX

> **Status: under development (epic [#8537](https://github.com/OpenCTI-Platform/connectors/issues/8537)).**
> The connector looks the observable up in AlienVault OTX and adds an external reference to its OTX
> page, but it does **not create the summary note or the country sightings yet**: they are added by
> the next sub-issues of the epic. The configuration described here is the one of the final
> connector.

Table of Contents

- [OpenCTI Internal Enrichment Connector: AlienVault OTX](#opencti-internal-enrichment-connector-alienvault-otx)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)

## Introduction

[AlienVault OTX](https://otx.alienvault.com) (Open Threat Exchange) is an open threat intelligence
community. This connector enriches observables already present in OpenCTI with what OTX knows about
them, through the OTX DirectConnect API.

It is distinct from the [AlienVault external import connector](../../external-import/alienvault/README.md),
which imports the pulses you subscribed to. This connector works on demand, on one entity at a time.

For an IPv4 address, a domain name or a URL, it adds:

- an external reference to the OTX indicator page;
- _(not implemented yet)_ a summary note (reputation, number of pulses and related pulses);
- _(not implemented yet)_ sightings from the countries reported by OTX.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.261117.0
- An AlienVault OTX account and its API key
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors/tree/master/connectors-sdk) library matching your OpenCTI version

## Configuration variables

Configuration parameters are provided either in `config.yml` or as environment variables
(see `config.yml.sample` and `docker-compose.yml`). Environment variables are the section name, then the
field name, in upper case (for example `ALIENVAULT_OTX_API_KEY`).

### OpenCTI environment variables

| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                  |
|---------------|---------------|-----------------------------|-----------|----------------------------------------------|
| OpenCTI URL   | `opencti.url` | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.             |
| OpenCTI Token | `opencti.token` | `OPENCTI_TOKEN`           | Yes       | The default admin token of the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml            | Docker environment variable | Default                                | Mandatory | Description                                                                                                                                                       |
|-----------------|-----------------------|-----------------------------|----------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID    | `connector.id`        | `CONNECTOR_ID`              | `0781c790-5d76-4539-b3b5-d8e6e74bc9a2` | No        | A unique `UUIDv4` identifying this connector instance. Set your own when you run several instances.                                                              |
| Connector Name  | `connector.name`      | `CONNECTOR_NAME`            | `AlienVault OTX`                       | No        | The name of the connector in OpenCTI.                                                                                                                             |
| Connector Scope | `connector.scope`     | `CONNECTOR_SCOPE`           | `IPv4-Addr`                            | No        | Comma-separated entity types to enrich, among `IPv4-Addr`, `Domain-Name` and `Url`. A type the connector does not handle is rejected at startup.                  |
| Log Level       | `connector.log_level` | `CONNECTOR_LOG_LEVEL`       | `error`                                | No        | Log verbosity: `debug`, `info`, `warn`, `warning` or `error`.                                                                                                     |
| Auto            | `connector.auto`      | `CONNECTOR_AUTO`            | `false`                                | No        | Enrich entities automatically when they are created or updated. Keep it off unless you accept that every matching entity is sent to OTX.                          |
| Max TLP         | `connector.max_tlp`   | `CONNECTOR_MAX_TLP`         | `TLP:AMBER`                            | No        | The highest TLP of the entities the connector may enrich: `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT` or `TLP:RED`.                    |

### Connector extra parameters environment variables

| Parameter    | config.yml                  | Docker environment variable  | Default                      | Mandatory | Description                                      |
|--------------|-----------------------------|------------------------------|------------------------------|-----------|--------------------------------------------------|
| API key      | `alienvault_otx.api_key`    | `ALIENVAULT_OTX_API_KEY`     |                              | Yes       | The API key of your AlienVault OTX account.      |
| API base URL | `alienvault_otx.api_base_url` | `ALIENVAULT_OTX_API_BASE_URL` | `https://otx.alienvault.com` | No        | The base URL of the OTX API.                     |

_The `opencti` and `connector` options are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`.

Example:

```shell
docker build . -t opencti/connector-alienvault-otx:latest
```

Replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment (especially the "**ChangeMe**" values), then start the container:

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
your environment.

Install the required Python dependencies (preferably in a virtual environment):

```shell
pip3 install -r src/requirements.txt
```

Then, start the connector from the `src` directory:

```shell
python3 main.py
```

## Usage

The connector enriches an entity when it is triggered:

- manually, from the entity in OpenCTI (the enrichment button);
- automatically, if `CONNECTOR_AUTO` is `true`;
- by a playbook, through the enrichment step.

## Behavior

Whatever the trigger, the connector processes each entity in this order:

1. **Scope**: an entity whose type is not in `CONNECTOR_SCOPE` is skipped.
2. **Max TLP**: an entity marked with a TLP above `CONNECTOR_MAX_TLP` is skipped, before any call to OTX.
   An entity without TLP marking is enriched.
3. **General lookup**: one call to the OTX `general` endpoint of the indicator
   (`/api/v1/indicators/<IPv4|domain|url>/<value>/general`).
   For a `Domain-Name` that the `domain` section does not know (0 pulse), a second call queries the
   `hostname` section, because OTX files subdomains (such as `www.example.com`) under it.
   No second call is made when the `domain` call is rejected (HTTP 400) or answers 404.
4. **Enrichment**: the observable is enriched when OTX knows it.

In a playbook, the connector always sends the bundle it received back, unchanged when it skips the
entity or finds nothing, so that the next step of the playbook runs. Outside playbooks, a skipped
entity sends nothing and its work is completed.

Entity types: `IPv4-Addr`, `Domain-Name` and `Url` are handled. Only `IPv4-Addr` is enabled by default:
add the others to `CONNECTOR_SCOPE` to enable them.

### Known indicators

OTX answers a `general` lookup for any valid indicator, so an answer does not mean OTX knows it.
An indicator is **known** when at least one OTX pulse contains it (`pulse_info.count` greater than 0).
An unknown indicator is not enriched: nothing is sent.

### What is added

For a known indicator, the connector sends:

- the observable itself, with the same value (so the same STIX id), and one external reference:
  source `AlienVault OTX`, pointing to
  `https://otx.alienvault.com/indicator/<ip|domain|hostname|url>/<value>`, where the value is URL-encoded
  (a URL such as `http://malicious.example/a?b=1` is encoded as `http%3A%2F%2Fmalicious.example%2Fa%3Fb%3D1`).
  A domain name known only through the `hostname` section links to `/indicator/hostname/<value>`.
  The observable carries no author and no marking: those of the entity are left untouched;
- the author `AlienVault`, an organization identity shared with the
  [AlienVault external import connector](../../external-import/alienvault/README.md) (same name, same
  STIX id);
- the `TLP:CLEAR` marking definition.

### Errors

- HTTP 404 (no such indicator): nothing is sent.
- HTTP 400 (OTX rejects the value, for example a private IP address, a CIDR range or an invalid
  domain): a warning is logged and nothing is sent.
- Any other failure (authentication error, HTTP 5xx or 429 after the retries, network error, invalid
  response): the work is put in error.
- Requests time out after 60 seconds. Timeouts and the HTTP statuses 408, 429, 500, 502, 503 and 504
  are retried up to 3 times with a backoff, and the `Retry-After` header is honoured. An unresponsive
  OTX can therefore keep an enrichment busy for several minutes before it fails.

## Debugging

The connector can be debugged by setting the appropriate log level (`CONNECTOR_LOG_LEVEL=debug`).
A debug message is logged for every entity that reaches the processor, before the OTX lookup. The
rejected indicators (HTTP 400) are logged as warnings, with the detail given by OTX.
