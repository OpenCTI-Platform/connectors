# Ransomware.live Connector

The Ransomware.live connector is an OpenCTI **external-import** connector that ingests publicly disclosed ransomware victims (and the operators behind them) from the community-maintained [ransomware.live](https://www.ransomware.live/) feed. On every scheduled tick it queries the upstream `recentvictims` endpoint (or the historical `victims/<year>/<month>` archive when `pull_history=true`), normalises every disclosure to STIX 2.1, and sends the resulting bundle into the configured OpenCTI worker.

The bundle the connector produces for each disclosed victim always includes the `Identity` (victim), the matched `Domain-Name` / `Location` observables when present, and a `Sector` linkage when the victim's industry is known. Configuration flags gate the optional SDOs: `create_intrusion_set` and `create_report` default to `true` to preserve the behaviour that existed before PR #5590 (the connector always emitted an `IntrusionSet` and a `Report` per disclosure); `create_threat_actor` and `create_campaign` default to `false` because they are new capabilities introduced by that PR.

| Status              | Date       | Comment |
| ------------------- | ---------- | ------- |
| Filigran Maintained | -          | -       |

## Installation

### Requirements

- OpenCTI Platform >= 7.260715.0 (matches the `pycti==7.260522.0` pin in `requirements.txt`)

### Configuration

Configuration parameters are provided via environment variables (or a `.env` file, ignored by git so it does not leak secrets — `.env.sample` carries a reference layout). Pydantic-settings parses every variable into a validated configuration model, so a malformed value (e.g. `CONNECTOR_MARKING_VALUE=TLP:UNKNOWN`) is rejected at startup with an actionable error rather than silently falling back.

#### Generic connector parameters

| Parameter           | `.env` variable   | Docker environment variable  | Default | Mandatory | Description                                                                                                  |
| ------------------- | ----------------- | ---------------------------- | ------- | --------- | ------------------------------------------------------------------------------------------------------------ |
| OpenCTI URL         | `url`             | `OPENCTI_URL`                |         | Yes       | URL of the OpenCTI platform (no trailing `/`). Example: `http://opencti:8080`.                               |
| OpenCTI Token       | `token`           | `OPENCTI_TOKEN`              |         | Yes       | API token for the connector user.                                                                            |
| Connector ID        | `id`              | `CONNECTOR_ID`               |         | Yes       | A valid `UUIDv4` unique to this connector instance. Generate one per deployment.                             |
| Connector Name      | `name`            | `CONNECTOR_NAME`             |         | Yes       | Display name in the OpenCTI UI.                                                                              |
| Connector Scope     | `scope`           | `CONNECTOR_SCOPE`            |         | Yes       | Comma-separated STIX entity types this connector is allowed to write.                                        |
| Connector Log Level | `log_level`       | `CONNECTOR_LOG_LEVEL`        | `error` | No        | One of `debug`, `info`, `warn`, `error`.                                                                     |
| Duration Period     | `duration_period` | `CONNECTOR_DURATION_PERIOD`  | `PT10M` | No        | ISO 8601 period between two scheduled runs (e.g. `PT12H`, `P1D`).                                            |

#### Ransomware.live-specific parameters

| Parameter             | `.env` variable        | Docker environment variable      | Default      | Mandatory | Description                                                                                                                                                  |
| --------------------- | ---------------------- | -------------------------------- | ------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Pull History          | `pull_history`         | `CONNECTOR_PULL_HISTORY`         | `false`      | No        | When `true`, the connector backfills from `history_start_year` on first run. Produces a large initial ingest — leave at `false` unless you need the archive. |
| History Start Year    | `history_start_year`   | `CONNECTOR_HISTORY_START_YEAR`   | `2023`       | No        | Year (or `YYYYMM`) to start the historical backfill from. The feed only goes back to 2020.                                                                   |
| Create Threat Actor   | `create_threat_actor`  | `CONNECTOR_CREATE_THREAT_ACTOR`  | `false`      | No        | When `true`, emit a `Threat Actor` SDO for the ransomware operator + a `targets` relationship to the victim.                                                 |
| Create Intrusion Set  | `create_intrusion_set` | `CONNECTOR_CREATE_INTRUSION_SET` | `true`       | No        | When `true`, emit an `Intrusion Set` SDO and link it to the victim, sector and location.                                                                     |
| Create Campaign       | `create_campaign`      | `CONNECTOR_CREATE_CAMPAIGN`      | `false`      | No        | When `true`, emit a `Campaign` SDO per disclosed victim and link it to the matching Intrusion Set / Sector / Location entities.                              |
| Create Report         | `create_report`        | `CONNECTOR_CREATE_REPORT`        | `true`       | No        | When `true`, emit a `Report` SDO whose `object_refs` carry every other SDO the bundle produced for the disclosure.                                           |
| Create Leak Site Domains | `create_leak_site_domains` | `CONNECTOR_CREATE_LEAK_SITE_DOMAINS` | `false` | No | When `true` (and `create_intrusion_set` is on), ingest ransomware group leak-site FQDNs as `Domain-Name` observables `related-to` the Intrusion Set, and add leak-site URLs as external references. Off by default to ease compliance with local rules on handling leaked-data links. |
| Create Leak Post Refs | `create_leak_post_refs` | `CONNECTOR_CREATE_LEAK_POST_REFS` | `false` | No | When `true`, include the direct leak-post URL (`post_url`) as an external reference on victim reports. Off by default for the same compliance reasons. |
| Marking Value         | `marking_value`        | `CONNECTOR_MARKING_VALUE`        | `TLP:CLEAR`  | No        | TLP marking attached to every emitted SDO. Allowed: `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`.                        |

> The `MARKING_VALUE` environment variable from an earlier draft has been renamed to `CONNECTOR_MARKING_VALUE` to match the pydantic-settings nested-env-var convention (`connector.marking_value` → `CONNECTOR_MARKING_VALUE`). The connector reads it via `self.config.connector.marking_value`, which is type-checked against the allowed `Literal` enum at startup.

> `TLP:CLEAR` is materialised as an OpenCTI-specific `MarkingDefinition` carrying the `x_opencti_definition='TLP:CLEAR'` extension so the modern label is rendered in the UI; `TLP:WHITE` remains available for deployments still using the legacy STIX 2.1 label.

### Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to surface every API call, every bundle creation and every state transition. Connector log messages are emitted via `self.helper.connector_logger.<level>(message, {"key": "value", …})` so they are JSON-serialisable in production log pipelines.

### Generated STIX objects

The connector emits the following objects per disclosure (every flag-gated entry is only present when the matching `CONNECTOR_CREATE_*` flag is `true`):

- `Identity` (author) — the connector's author (`Ransomware.Live`), set as `created_by_ref` on every other SDO.
- `MarkingDefinition` — the `TLP:*` marking configured via `CONNECTOR_MARKING_VALUE`.
- `Identity` (victim) — always emitted.
- `Domain-Name` — when the victim record carries a domain. Linked to the victim via a `belongs-to` relationship (`Domain-Name → Identity`).
- `Location` (country) — when the victim record carries a country. Linked to the victim via a `located-at` relationship (`Identity → Location`).
- `Identity` (sector) — when the victim's industry is known. Linked to the victim via a `part-of` relationship (`Identity (victim) → Identity (sector)`).
- `Threat Actor` — gated on `create_threat_actor`. Linked to the victim via a `targets` relationship (`Threat Actor → Identity`); when a sector/location is present the Threat Actor also `targets` those.
- `Intrusion Set` — gated on `create_intrusion_set`. Linked to the victim via a `targets` relationship (`Intrusion Set → Identity`), to the Threat Actor via an `attributed-to` relationship (`Intrusion Set → Threat Actor`), and to the sector/location via `targets` relationships when present.
- `Campaign` — gated on `create_campaign`. Linked to the victim via a `targets` relationship (`Campaign → Identity`), to the Intrusion Set via an `attributed-to` relationship (`Campaign → Intrusion Set`), and to the sector via a `targets` relationship when present.
- `Report` — gated on `create_report`. Its `object_refs` carry every SDO and SRO emitted for the disclosure above (victim, optional Threat Actor / Intrusion Set / Campaign, Sector, Location, Domain-Name, and every relationship between them).
