# OpenCTI IOC Extractor

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

## Description

The **IOC Extractor** enrichment connector extracts Observables from unstructured content within OpenCTI entities. It parses entity descriptions to identify and create STIX observables.

## Features

- **Playbook compatible**: The connector can be used within a playbook
- **Flexible content extraction**: Extracts observables from entity descriptions
- **Defanged IOC support**: Handles defanged indicators (e.g., `hxxps://`, `8[.]8[.]8[.]8`) thanks to the `ioc-finder` library
- **Configurable IOC types**: Enable or disable each type of observable extraction independently (hashes, IPv4, IPv6, domains, URLs)
- **Marking inheritance**: Created observables inherit the `object_marking_refs` from the source entity when present
- **Private IP filtering**: Configurable option to exclude private/reserved IP addresses (RFC 1918, loopback, etc.)

## Supported IOC Types

| Type    | STIX Object | Example                                    |
|---------|-------------|--------------------------------------------|
| MD5     | File (hash) | `d41d8cd98f00b204e9800998ecf8427e`         |
| SHA-1   | File (hash) | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA-256 | File (hash) | `e3b0c44298fc1c149afbf4c8996fb924...`      |
| IPv4    | IPv4-Addr   | `8.8.8.8`                                  |
| IPv6    | IPv6-Addr   | `2001:4860:4860::8888`                     |
| Domain  | Domain-Name | `example.com`                              |
| URL     | Url         | `https://malware.example.com/payload`      |


## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.12
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk)

## Configuration

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

```shell
docker compose up -d
```

### Manual Deployment

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Behavior

When triggered (manually, via auto-enrichment, or through a playbook):

1. The connector receives a STIX bundle containing the entity to enrich
2. It extracts text content from the entity's `description`
3. It parses the text for IOCs using the configured extraction types. The extraction is performed using the 'ioc-finder' library.
4. For each IOC found, it creates a STIX observable
5. For STIX domain entities, it creates `related-to` relationships between each observable and the source entity
6. For Container entities, it adds the observables to the container's `object_refs`
7. It returns the enriched bundle (or the original bundle unchanged if no IOCs are found)
