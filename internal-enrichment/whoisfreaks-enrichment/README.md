# OpenCTI WhoisFreaks Connector

| Status    | Date | Comment |
|-----------|------|---------|
| Community | -    | -       |

The WhoisFreaks connector enriches Domain-Name observables with live WHOIS data from [WhoisFreaks](https://whoisfreaks.com): registrar, registration dates, name servers, DNSSEC and domain status, and registrant and abuse contacts.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
- [Usage](#usage)
- [Behavior](#behavior)
- [Debugging](#debugging)
- [Additional information](#additional-information)

## Introduction

For each observable, the connector makes one request to the WhoisFreaks [Live WHOIS API](https://whoisfreaks.com/products/whois-api.html) and sends back:

- the observable with labels (`dnssec`, `unregistered`) and a link to its WhoisFreaks lookup
- its registrar as an Organization, its name servers as Domain-Name observables, its registrant organization, and its contact e-mail addresses, with relationships
- a note with the full WHOIS report, including the registrar, dates, domain status codes and every available contact

## Installation

### Requirements

- OpenCTI Platform >= 7.261002.0
- A WhoisFreaks API key ([sign up](https://whoisfreaks.com/signup.html)). The key is available in the [billing dashboard](https://whoisfreaks.com/dashboard.html).

## Configuration variables

Configuration comes from environment variables or from `config.yml` (see `config.yml.sample`).

### OpenCTI environment variables

| Parameter     | config.yml      | Docker environment variable | Mandatory | Description                                          |
|---------------|-----------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | `opencti.url`   | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `opencti.token` | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml            | Docker environment variable | Default        | Mandatory | Description                                                                 |
|-----------------|-----------------------|-----------------------------|----------------|-----------|-----------------------------------------------------------------------------|
| Connector ID    | `connector.id`        | `CONNECTOR_ID`              |                | Yes       | A unique `UUIDv4` identifier for this connector instance.                   |
| Connector Name  | `connector.name`      | `CONNECTOR_NAME`            | `WhoisFreaks`  | No        | Name of the connector.                                                      |
| Connector Scope | `connector.scope`     | `CONNECTOR_SCOPE`           | `Domain-Name`  | No        | The observable types the connector enriches.                                |
| Log Level       | `connector.log_level` | `CONNECTOR_LOG_LEVEL`       | `error`        | No        | `debug`, `info`, `warn` or `error`.                                         |
| Auto            | `connector.auto`      | `CONNECTOR_AUTO`            | `false`        | No        | Enrich new observables automatically. Every lookup spends API credits.      |
| Max TLP         | `connector.max_tlp`   | `CONNECTOR_MAX_TLP`         | `amber+strict` | No        | Highest TLP of the observables sent to WhoisFreaks: `clear`, `white`, `green`, `amber`, `amber+strict` or `red`. |

### Connector extra parameters environment variables

| Parameter            | config.yml                        | Docker environment variable         | Default                       | Mandatory | Description                                                        |
|----------------------|-----------------------------------|-------------------------------------|-------------------------------|-----------|--------------------------------------------------------------------|
| API key              | `whoisfreaks.api_key`             | `WHOISFREAKS_API_KEY`               |                               | Yes       | WhoisFreaks API key.                                              |
| API base URL         | `whoisfreaks.api_base_url`        | `WHOISFREAKS_API_BASE_URL`          | `https://api.whoisfreaks.com` | No        | WhoisFreaks API base URL.                                         |
| Timeout              | `whoisfreaks.timeout`             | `WHOISFREAKS_TIMEOUT`               | `30`                          | No        | HTTP request timeout in seconds.                                  |
| TLP level            | `whoisfreaks.tlp_level`           | `WHOISFREAKS_TLP_LEVEL`             | `clear`                       | No        | TLP marking of the objects the connector creates.                |
| Create labels        | `whoisfreaks.create_labels`       | `WHOISFREAKS_CREATE_LABELS`         | `true`                        | No        | Add labels to the observable.                                     |
| Create relationships | `whoisfreaks.create_relationships`| `WHOISFREAKS_CREATE_RELATIONSHIPS`  | `true`                        | No        | Link the observable to its registrar, name servers and contacts. |
| Create note          | `whoisfreaks.create_note`         | `WHOISFREAKS_CREATE_NOTE`           | `true`                        | No        | Attach a note with the full WHOIS report.                        |

## Deployment

### Docker Deployment

Build the image:

```shell
docker build . -t opencti/connector-whoisfreaks-enrichment:latest
```

Set the environment variables in `docker-compose.yml`, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create `config.yml` from `config.yml.sample`, then install the dependencies and start the connector:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Usage

In OpenCTI, open a Domain-Name observable, click the enrichment button and choose WhoisFreaks. With `CONNECTOR_AUTO=true`, new observables are enriched as they are created. The connector also works as a playbook step.

## Behavior

### Objects created

| WhoisFreaks data                    | OpenCTI                                                                    |
|-------------------------------------|----------------------------------------------------------------------------|
| Registrar                           | Organization; observable `related-to` it                                   |
| Registrant organization             | Organization; observable `related-to` it                                   |
| Name servers                        | Domain-Name observables; observable `related-to` each                      |
| Contact e-mails (registrant, admin, technical, billing, abuse) | Email-Addr observables; observable `related-to` each |
| DNSSEC and registration state       | Observable labels (`dnssec`, `unregistered`)                               |
| Everything, including dates and status codes | Note attached to the observable                                   |

All new objects carry the WhoisFreaks author and the configured TLP marking, and use the deterministic IDs of the connectors SDK, so enriching the same observable again updates the same entities. The observable keeps its own markings and author. Redacted contact placeholders (privacy, GDPR, "REDACTED FOR PRIVACY") are skipped rather than created as entities.

### Credits

Each enrichment is one live WHOIS lookup and costs one WhoisFreaks credit.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for detailed logs. API errors (invalid key, used-up quota) are reported in the connector's work in OpenCTI with the message returned by WhoisFreaks; the API key never appears in logs or messages.

## Additional information

- Observables with a TLP above `max_tlp` are never sent to WhoisFreaks.
- Support: support@whoisfreaks.com
