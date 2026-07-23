# OpenCTI Metras Feed Connector (EXTERNAL_IMPORT)

Imports telemetry from the [Metras](https://dashboard.metras.sa/) security platform
(`api.metras.sa`) into OpenCTI on a schedule: EDR alerts (with MITRE ATT&CK mapping),
file binaries, and endpoint inventory.

## What it imports

| Metras source | OpenCTI output |
|---|---|
| EDR alerts (`/v1/edr/alerts`) | **Incident** (name, severity, score, labels) |
| └ `mitre_ids` | **Attack-Pattern** (keyed by `external_id`, merges with MITRE ATT&CK) + `uses` relationship |
| └ `url` | **Url** observable + `related-to` (external destination — a real IOC) |
| └ `endpoint_name` (+ `agent_ip`) | **Identity** (`identity_class: system`) + `related-to` |
| Binaries (`/v1/edr/binary/list`) | **StixFile** (MD5 / SHA-1 / SHA-256, name, size, score) + `related-to` System |
| Endpoints (`/v1/endpoints`) | **Identity** (`identity_class: system`); interface/tunnel IPs in the description |

> **Internal assets are System identities, not IOCs** — your fleet endpoints (and their internal
> IPs: `agent_ip`, interface/tunnel IPs) are modelled as `Identity(identity_class="system")` with the
> IPs in the description, **not** as IPv4-Addr observables. Only genuinely external artifacts (alert
> `url`, file hashes) become observables. (Pattern per OpenCTI maintainer review, PR #6164.)
>
> **Observables only** — no STIX Indicators are auto-created from binaries (analysts promote manually).
> Process name/GUID from alerts is folded into the Incident description (STIX 2.1 `Process` has no `name`).

## Incremental behavior
- **EDR alerts** have no time filter on the API → the connector filters client-side on
  `last_occurrence_time` against stored state (`alerts_last_occurrence`).
- **Binaries** use the server-side `fromTime` window (state `binaries_last_seen`).
- **Endpoints** are re-listed each run (deduped by deterministic STIX IDs in OpenCTI).
- A category that errors does not advance its cursor (no data loss; safe retry next cycle).

## Requirements
- OpenCTI **7.260529.0** (pinned; `pycti==7.260529.0`).
- A Metras API key (`X-API-KEY`).

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | yes | — | OpenCTI base URL |
| `OPENCTI_TOKEN` | yes | — | OpenCTI API token |
| `CONNECTOR_ID` | yes | — | UUIDv4 for this connector |
| `CONNECTOR_NAME` | no | `Metras-Feed` | Connector name |
| `CONNECTOR_SCOPE` | no | `Metras` | Import scope |
| `CONNECTOR_LOG_LEVEL` | no | `info` | Log level |
| `CONNECTOR_DURATION_PERIOD` | yes | `PT1H` | ISO-8601 poll interval |
| `METRAS_API_BASE_URL` | no | `https://api.metras.sa/api` | Metras API base URL |
| `METRAS_API_KEY` | yes | — | Metras API key |
| `METRAS_VERIFY_SSL` | no | `true` | Verify TLS certificates |
| `METRAS_IMPORT_ALERTS` | no | `true` | Import EDR alerts |
| `METRAS_IMPORT_BINARIES` | no | `true` | Import binaries |
| `METRAS_IMPORT_ENDPOINTS` | no | `true` | Import endpoints |
| `METRAS_BINARY_MALICIOUS_ONLY` | no | `true` | Only import banned/unsigned binaries |
| `METRAS_PAGE_SIZE` | no | `50` | Records per page |
| `METRAS_TLP_LEVEL` | no | `amber` | TLP marking (`clear`/`white`/`green`/`amber`/`red`) |

## Installation
```bash
cp config.yml.sample src/config.yml   # or use env vars / docker-compose
docker compose up -d --build
```

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| `Metras API ping failed at startup` then exit | Bad `METRAS_API_KEY` or unreachable base URL |
| `Imported 0 incidents` after first run | Normal — alerts already imported; cursor advanced |
| `Cannot query field "s3"` | pycti/platform mismatch — keep `pycti==7.260529.0` |
| No Works in OpenCTI UI | Check `OPENCTI_TOKEN` permissions (Work API) |
