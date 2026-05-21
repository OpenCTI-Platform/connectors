# OpenCTI Splunk Search Internal Enrichment Connector

The Splunk Search connector enriches OpenCTI Indicators by running Splunk searches and converting matching telemetry into STIX observables, sightings, and source identities.

This is an `INTERNAL_ENRICHMENT` connector with `Indicator` scope. It does not poll OpenCTI on a schedule and it does not send data to Splunk HEC. OpenCTI triggers it when a user or playbook enriches an Indicator.

## How It Works

At startup, the connector checks OpenCTI for SPL search template Indicators:

- `pattern_type = "spl"`
- label `threat-hunting-splunk`

If no templates exist, it seeds the default bundle from `splunk_bundle.py`. These seeded Indicators are Splunk searches, not IOCs to enrich. They contain placeholders such as `<IP_LIST>`, `<DOMAIN_LIST>`, `<HOSTNAME_LIST>`, `<FILE_HASH_LIST>`, and `<INDICATOR_ID>`.

When an enrichment request arrives, the connector supports two paths:

- STIX Indicator path: for `pattern_type = "stix"`, the connector extracts observable values from the callback `stix_objects` or from the STIX pattern, finds matching SPL templates for the Indicator observable type, renders each template, runs each search in Splunk, and sends one STIX bundle back to OpenCTI.
- SPL Indicator path: for `pattern_type = "spl"`, the connector treats the Indicator pattern as the Splunk query, renders any placeholders if values are available, runs it directly, and sends one STIX bundle back to OpenCTI.

Unsupported `pattern_type` values are skipped with a warning.

## Search Parameters

Each SPL template can have an attached OpenCTI Note with `note_types = "Search Parameters"` and JSON content such as:

```json
{
  "earliest_time": "-90d@d",
  "latest_time": "now",
  "timeout": 120,
  "wait_seconds": 2,
  "max_results": 1000
}
```

Search parameter precedence is:

1. Per-Indicator Note parameters
2. Connector configuration defaults

For example, if the connector default is `SPLUNK_SEARCH_EARLIEST=-30d@d` but the Note has `"earliest_time": "-90d@d"`, the search runs with `-90d@d`.

## Requirements

- OpenCTI with a connector token that can read Indicators and Notes and import STIX bundles.
- Splunk management API access using a token.
- Python dependencies from `src/requirements.txt`, including `pycti`, `stix2`, and `splunk-sdk`.

## Configuration

Configuration can be provided through Docker environment variables or through `src/config.yml` using the paths shown below.

### OpenCTI

| Parameter | config.yml path | Environment variable | Default | Required | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | none | yes | OpenCTI platform URL. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | none | yes | Token used by the connector. |

### Connector

| Parameter | config.yml path | Environment variable | Default | Required | Description |
|---|---|---|---|---|---|
| Connector ID | `connector.id` | `CONNECTOR_ID` | none | yes | Unique connector UUID. |
| Connector type | `connector.type` | `CONNECTOR_TYPE` | none | yes | Must be `INTERNAL_ENRICHMENT`. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `SplunkSearch` | yes | Display name in OpenCTI. |
| Connector scope | `connector.scope` | `CONNECTOR_SCOPE` | `Indicator` | yes | Must include `Indicator`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `info` | no | Log verbosity. |
| Auto enrichment | `connector.auto` | `CONNECTOR_AUTO` | `false` | no | Whether OpenCTI should trigger enrichment automatically. |

### Splunk

| Parameter | config.yml path | Environment variable | Default | Required | Description |
|---|---|---|---|---|---|
| Splunk host | `splunk-search.host` | `SPLUNK_HOST` | none | yes | Splunk management API host, without scheme. |
| Splunk port | `splunk-search.port` | `SPLUNK_PORT` | `8089` | no | Splunk management API port. |
| Splunk token | `splunk-search.token` | `SPLUNK_TOKEN` | none | yes | Splunk authentication token. |
| Splunk app | `splunk-search.app` | `SPLUNK_APP` | `search` | no | Splunk app context for searches. |
| Scheme | `splunk-search.scheme` | `SPLUNK_SCHEME` | `https` | no | `https` or `http`. |
| Verify SSL | `splunk-search.verify_ssl` | `SPLUNK_VERIFY_SSL` | `true` | no | Set to `false` for self-signed certificates. |
| Default earliest time | `splunk-search.earliest_time` | `SPLUNK_SEARCH_EARLIEST` | `-30d@d` | no | Fallback earliest bound when the SPL Indicator Note does not provide one. |
| Default latest time | `splunk-search.latest_time` | `SPLUNK_SEARCH_LATEST` | `now` | no | Fallback latest bound when the SPL Indicator Note does not provide one. |
| Default timeout | `splunk-search.timeout` | `SPLUNK_SEARCH_TIMEOUT` | `60` | no | Fallback search timeout in seconds. |
| Poll interval | `splunk-search.wait_seconds` | `SPLUNK_WAIT_SECONDS` | `2` | no | Fallback polling interval while waiting for Splunk jobs. |
| Max results | `splunk-search.max_results` | `SPLUNK_MAX_RESULTS` | `1000` | no | Fallback maximum result rows to read. |
| Sighting TLP | `splunk-search.sighting_tlp` | `SPLUNK_SIGHTING_TLP` | `TLP:AMBER` | no | TLP marking applied to generated Sightings. |
| Observable TLP | `splunk-search.observable_tlp` | `SPLUNK_OBSERVABLE_TLP` | `TLP:AMBER` | no | TLP marking applied to generated observables/source identities. |

Supported TLP labels are `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, and `TLP:RED`.

## Docker Deployment

Build and start the connector with the provided Docker artifacts:

```shell
docker build . -t opencti-connector-splunk-search:dev
docker compose up -d
```

Set the required variables in your environment before starting Compose:

```shell
export OPENCTI_ADMIN_TOKEN=...
export CONNECTOR_SPLUNK_SEARCH_ID=...
export SPLUNK_TOKEN=...
```

Review `docker-compose.yml` for all available variables.

## Manual Deployment

Create `src/config.yml` from `src/config.yml.sample`, then install dependencies and run the connector:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Enrichment Output

For each Splunk result row, the connector uses `splunk_result_parser.py` to create STIX objects from recognized fields such as:

- IP addresses, domains, URLs, hostnames, user agents, users, software, files, and directories
- Source identities for Splunk hosts/sourcetypes where available
- Sightings with Splunk telemetry context and TLP markings

The connector sends a single STIX bundle per enrichment request. The bundle includes the Splunk author Identity plus all generated observables, sightings, and source identities.

## Troubleshooting

- No SPL templates found: confirm the startup seed ran, or create Indicators with `pattern_type = "spl"` and label `threat-hunting-splunk`.
- Search time range seems wrong: check the Search Parameters Note attached to the SPL Indicator. Note values override connector defaults.
- Splunk authentication fails: verify `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_SCHEME`, `SPLUNK_TOKEN`, and `SPLUNK_VERIFY_SSL`.
- Nothing happens automatically: `CONNECTOR_AUTO=false` means enrichment must be triggered manually or by a playbook.

For more detail, set `CONNECTOR_LOG_LEVEL=debug`.
