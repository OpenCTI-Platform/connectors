# Ransomware.live Connector

The Ransomware.live connector is an OpenCTI **external-import** connector that ingests publicly disclosed ransomware victims (and the operators behind them) from the community-maintained [ransomware.live](https://www.ransomware.live/) feed. On every scheduled tick it queries the upstream `recentvictims` endpoint (or the historical `victims/<year>/<month>` archive when `pull_history=true`), normalises every disclosure to STIX 2.1, and sends the resulting bundle into the configured OpenCTI worker.

The bundle the connector produces for each disclosed victim always includes the `Identity` (victim), the matched `Domain-Name` / `Location` observables when present, and a `Sector` linkage when the victim's industry is known. Configuration flags gate the optional SDOs: `create_intrusion_set` and `create_report` default to `true` to preserve the behaviour that existed before PR #5590 (the connector always emitted an `IntrusionSet` and a `Report` per disclosure); `create_threat_actor` and `create_campaign` default to `false` because they are new capabilities introduced by that PR.


## Installation

### Requirements

- OpenCTI Platform >= 7.260902.0 (matches the `pycti==7.260522.0` pin in `requirements.txt`)

### Configuration

Configuration parameters are provided via environment variables (or a `.env` file, ignored by git so it does not leak secrets — `.env.sample` carries a reference layout). Pydantic-settings parses every variable into a validated configuration model, so a malformed value (e.g. `RANSOMWARELIVE_MARKING_VALUE=TLP:UNKNOWN`) is rejected at startup with an actionable error rather than silently falling back.

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

### How to get a ransomware.live API-PRO key

1. Go to the official API page: [https://www.ransomware.live/api](https://www.ransomware.live/api).
2. Follow the API-PRO registration/request process described there.
3. Copy your API key and set it in `RANSOMWARELIVE_API_KEY`.
4. Set `RANSOMWARELIVE_API_BASE_URL=https://api-pro.ransomware.live`.

### Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to surface every API call, every bundle creation and every state transition. Connector log messages are emitted via `self.helper.connector_logger.<level>(message, {"key": "value", …})` so they are JSON-serialisable in production log pipelines.

### Generated STIX objects

The connector emits the following objects per disclosure (every flag-gated entry is only present when the matching `RANSOMWARELIVE_CREATE_*` flag is `true`):

- `Identity` (author) — the connector's author (`Ransomware.Live`), set as `created_by_ref` on every other SDO.
- `MarkingDefinition` — the `TLP:*` marking configured via `RANSOMWARELIVE_MARKING_VALUE`.
- `Identity` (victim) — always emitted.
- `Domain-Name` — when the victim record carries a domain. Linked to the victim via a `belongs-to` relationship (`Domain-Name → Identity`).
- `Location` (country) — when the victim record carries a country. Linked to the victim via a `located-at` relationship (`Identity → Location`).
- `Identity` (sector) — when the victim's industry is known. Linked to the victim via a `part-of` relationship (`Identity (victim) → Identity (sector)`).
- `Threat Actor` — gated on `create_threat_actor`. Linked to the victim via a `targets` relationship (`Threat Actor → Identity`); when a sector/location is present the Threat Actor also `targets` those.
- `Intrusion Set` — gated on `create_intrusion_set`. Linked to the victim via a `targets` relationship (`Intrusion Set → Identity`), to the Threat Actor via an `attributed-to` relationship (`Intrusion Set → Threat Actor`), and to the sector/location via `targets` relationships when present.
- `Campaign` — gated on `create_campaign`. Linked to the victim via a `targets` relationship (`Campaign → Identity`), to the Intrusion Set via an `attributed-to` relationship (`Campaign → Intrusion Set`), and to the sector via a `targets` relationship when present.
- `Report` — gated on `create_report`. Its `object_refs` carry every SDO and SRO emitted for the disclosure above (victim, optional Threat Actor / Intrusion Set / Campaign, Sector, Location, Domain-Name, and every relationship between them).
