# Plan: Hunter (Cyborg Security) OpenCTI Enrichment Connector

## Context

Hunter / Cyborg Security exposes hunt packages (sigma-rule based detections enriched with MITRE mappings, threat actors, campaigns, threat names, exploit/vuln links, analyst runbooks, validation harnesses) via `GET /es/query?indexes=cyborg_usecases`. The repo currently contains only `README.md` describing the endpoint and a captured `response.json` sample.

We want to ingest this hunt context into OpenCTI **on demand**, triggered by an analyst from within the OpenCTI UI on a specific entity ("show me Hunter coverage for this actor / technique / vuln"). This will give Southwest's SOC manual pivots from any actor, campaign, technique, vulnerability or malware page into the Hunter hunt corpus, materialised as native STIX objects.

Out of scope: bulk/scheduled imports, IOC ingestion (Hunter ships detections, not IOCs), validation-zip execution.

## Design summary

A single **OpenCTI Internal Enrichment connector** (Python 3.11 + Docker, official `pycti` template). Triggers on **Threat-Actor / Intrusion-Set, Campaign, Attack-Pattern, Vulnerability, Malware**. For each match returned by Hunter, the connector emits a STIX bundle containing:

- One **Report** (`report--<hunt_uuid>`, `report_types=["threat-hunting"]`) — the hunt package itself, mirroring the Verity report shape. Carries title, description, `published`, severity-derived score, labels and external references (Hunter URL + reference URLs). Its `object_refs` — the OpenCTI **Entities** tab — hold everything below.
- One **Indicator** (`indicator--<hunt_uuid>`) with `pattern_type=sigma`, `pattern=<sigma yaml>`, severity label + score, Hunter UI back-link. Referenced by the Report; kept lean since context lives on the Report.
- Attached **Note** objects (on the Report): analyst_runbook, mitigation, validation, plus one Note per `running_analyst_notes` entry.
- Auto-created related entities (Attack-Pattern, Intrusion-Set, Campaign, Malware, Vulnerability, Tool, Sector, Location) with STIX relationships — the Indicator `indicates` each, Intrusion-Set `uses` Attack-Pattern — all placed in the Report's `object_refs`.
- A UUID+`last_updated` cache to skip unchanged hunts on repeat enrichments.

> **Note (2026-07):** the hunt package was originally modelled as a top-level *Indicator*. Per stakeholder feedback it is now a *Report* (same shape as Verity reports), with all context surfaced under the Entities tab and the sigma rule kept as an Indicator tied to the Report. The sections below describe the original Indicator-centric build; the Report wrapper is layered on top of the same entity/relationship extraction.

## Layout

Matches the official OpenCTI `connectors` repo convention (`internal-enrichment/<vendor>-<product>/`):

```
cyborg-opencti/                             # repo root (unchanged files: README.md, response.json)
└── internal-enrichment/
    └── intel471-hunt/
        ├── src/
        │   ├── main.py                     # entrypoint: OpenCTIConnectorHelper().listen()
        │   ├── config.py                   # config.yml + env-var loader
        │   ├── hunter_client.py            # HTTP client for /es/query
        │   ├── stix_builder.py             # hunt-json → STIX 2.1 bundle
        │   ├── entity_mapper.py            # OpenCTI entity → Hunter query params
        │   ├── severity.py                 # High/Medium/Low → score 90/60/30
        │   └── cache.py                    # JSON-file cache keyed by hunt UUID + last_updated
        ├── tests/
        │   ├── fixtures/response.json      # copy of the repo-root response.json
        │   ├── test_stix_builder.py
        │   ├── test_entity_mapper.py
        │   └── test_hunter_client.py       # responses mocked via responses/requests-mock
        ├── config.yml.sample
        ├── Dockerfile
        ├── docker-compose.yml              # compose snippet for plug-into existing OpenCTI stack
        ├── entrypoint.sh
        ├── requirements.txt                # pycti, pyyaml, requests, stix2, python-dateutil
        ├── README.md                       # install + config + usage
        └── PLAN.md                         # copy of this plan file, kept alongside the code
```

The repo-root `response.json` remains the canonical capture; `tests/fixtures/response.json` is the test copy (copied at scaffold time, not symlinked, so the test suite is self-contained).

## Behaviour

### Entity → Hunter query mapping (`entity_mapper.py`)

| OpenCTI entity         | Hunter API param          | Source field on entity        |
| ---------------------- | ------------------------- | ----------------------------- |
| Intrusion-Set / Threat-Actor | `actors`            | `name`                        |
| Campaign               | `campaigns`               | `name`                        |
| Attack-Pattern         | `mitre_technique_ids`     | `x_mitre_id` / `external_id` (e.g. `T1059.007`) |
| Vulnerability          | `exploit_or_vulns`        | `name` (CVE id)               |
| Malware                | `threat_names`            | `name`                        |
| Tool                   | `tools`                   | `name`                        |
| Sector                 | `target_industries`       | `name`                        |
| Country / Location(country) | `target_countries` ∪ `source_countries` (2 API calls, unioned) | `name`                        |
| Region / Location(region)   | `target_regions` ∪ `source_regions` (2 API calls, unioned)     | `name`                        |

Aliases are also tried where the entity has them. The connector logs the resolved query for traceability.

### Hunt → STIX (`stix_builder.py`)

For every result in `data.results`:

1. **Indicator**
   - `id`: deterministic from `hunt.UUID` (`indicator--<uuid>`).
   - `name`: `hunt.title`.
   - `description`: `hunt.description` (full prose — runbook etc. moves to Notes).
   - `pattern_type`: `"sigma"`.
   - `pattern`: `hunt.sigma` (raw YAML, as STIX allows multi-line strings).
   - `valid_from`: `hunt.completed_date` or `hunt.created_date`.
   - `x_opencti_score`: severity-mapped (High=90, Med=60, Low=30).
   - `labels`: `tags.threat_categories`, `tags.kill_chains`, `tags.attack_surfaces`, `tags.target_oses`, plus `severity:<level>`.
   - `external_references`:
     - `{"source_name": "Cyborg Hunter", "url": f"{hunter_ui_base}/hunts/{uuid}", "external_id": uuid}` — only if `hunter_ui_base` is configured.
     - One entry per URL in `references.general/analysis/deep_dives/blog_links/malware_samples`, grouped by source.

2. **Notes** (each `created_by_ref` = connector identity, `object_refs` = [indicator id])
   - `analyst_runbook` → one Note `abstract="Analyst runbook"`.
   - `response_actions.mitigation_recommendations` → one Note `abstract="Mitigation recommendations"`.
   - `validation` → one Note `abstract="Validation"` (validation_encoded_zip not included — link to Hunter UI instead).
   - One Note per entry of `running_analyst_notes` (use `analyst_note_date` for `created`, `current_analyst_note` for `content`, `analyst_note_type` for `abstract`).

3. **Related entities** — auto-created with `name`-based deterministic IDs so multiple hunts deduplicate. Created with `confidence=hunt_confidence`.
   - `mapping.mitre.mitre_attack_payload[].T<id>` → **Attack-Pattern** (`x_mitre_id=T<id>`, `name=technique_name`, `kill_chain_phases=tactics`).
   - `tags.actors` → **Intrusion-Set**.
   - `tags.threat_names` → **Malware** *iff* `tags.threat_categories` contains `"Malware"`, else **label only** on Indicator.
   - `tags.campaigns` → **Campaign**.
   - `tags.exploit_or_vulns` / `mapping.exploit_or_vulns` → **Vulnerability**.

4. **Relationships** (all `created_by_ref` = connector identity)
   - `indicator --indicates--> Intrusion-Set | Campaign | Malware | Vulnerability`.
   - `indicator --indicates--> Attack-Pattern` (uses `indicates` per OpenCTI convention for sigma→technique linkage).
   - Optional: `Intrusion-Set --uses--> Attack-Pattern` when both are present in the same hunt (gives the graph richer edges).

### Severity → score (`severity.py`)
```
High   → 90
Medium → 60
Low    → 30
unknown→ 50  (logged warning)
```

### Cache (`cache.py`)
- JSON file at `${CACHE_PATH:-/opt/connector/cache.json}`, keyed by `hunt.UUID` → `last_updated` ISO string.
- On enrichment: skip hunts whose `(uuid, last_updated)` already in cache; update entries after successful `send_stix2_bundle`.
- TTL configurable (`HUNTER_CACHE_TTL_HOURS`, default 24h) — entries older than TTL are re-fetched even if unchanged, to recover from bad pushes.
- Safe for single-process; if running multiple replicas, swap for Redis later (out of scope).

### Connector lifecycle (`main.py`)
Standard pycti pattern:
```python
helper = OpenCTIConnectorHelper(config)
helper.listen(message_callback=self._process_message)
```
`_process_message`:
1. Parse `data` → entity_id, entity_type, OpenCTI representation.
2. `entity_mapper.build_query(entity)` → `{param: [values]}`.
3. `hunter_client.query(**params)` → list of hunts.
4. For each hunt not in cache: `stix_builder.build(hunt)` → bundle of STIX objects.
5. `helper.send_stix2_bundle(bundle.serialize(), update=True)`.
6. Update cache, return human-readable summary string.

### Config (`config.yml.sample` + env overrides)
```yaml
opencti:
  url: http://opencti:8080
  token: ChangeMe
connector:
  id: <generated-uuid>
  type: INTERNAL_ENRICHMENT
  name: Cyborg Hunter
  scope: Intrusion-Set,Threat-Actor,Campaign,Attack-Pattern,Vulnerability,Malware
  auto: false                         # require manual trigger; flip true to auto-enrich on entity create
  confidence_level: 75
  log_level: info
hunter:
  api_base_url: https://api.hunter.cyborgsecurity.io
  api_key: ChangeMe                   # sent as `Authorization: API-Key <key>`
  ui_base_url: https://hunter.cyborgsecurity.io        # optional, for external_references; blank disables
  indexes: cyborg_usecases
  request_timeout_seconds: 30
  max_results_per_query: 100
  cache_path: /opt/connector/cache.json
  cache_ttl_hours: 24
```
Every key overridable by env var (`HUNTER_API_KEY`, `CONNECTOR_SCOPE`, …) using pycti's `get_config_variable`.

## Critical files to author

All paths relative to `internal-enrichment/intel471-hunt/`:

- `src/main.py` — wires `OpenCTIConnectorHelper` + listen loop.
- `src/hunter_client.py` — `requests.Session` with `Authorization: API-Key …` header, retry on 429/5xx, JSON parsing.
- `src/entity_mapper.py` — single function `build_query(entity: dict) -> dict | None`; returns None for unsupported types so the connector early-exits cleanly.
- `src/stix_builder.py` — pure function `build_bundle(hunt: dict, author: Identity) -> stix2.Bundle`. Easy to unit-test against the fixture.
- `src/cache.py` — file-locked JSON cache; small, no extra deps.
- `tests/test_stix_builder.py` — fixture-driven: load `tests/fixtures/response.json`, assert that for each result we produce ≥1 Indicator, expected Notes, the correct related entities and relationship types, MITRE Attack-Patterns with correct `x_mitre_id`.
- `PLAN.md` — verbatim copy of this plan, committed alongside the code so future readers find the design rationale next to the implementation.

## Reuse / patterns to follow

This will be the first connector in this repo so there's nothing to reuse internally. The implementation should mirror the official OpenCTI enrichment connector template (`opencti/connectors` repo, e.g. `internal-enrichment/abuseipdb` or `recordedfuture-notes`) — same `OpenCTIConnectorHelper().listen()` shape, same `config.yml` + Docker layout, same `stix2` Python library for bundle creation. That gives Southwest's ops team a familiar deploy story.

## Verification

End-to-end smoke (manual, after implementation), all from `internal-enrichment/intel471-hunt/`:

1. **Unit tests**: `pytest`. `test_stix_builder.py` exercises every result in the fixture; should pass without network.
2. **Local dry run**: `python -m src.stix_builder --fixture tests/fixtures/response.json --out /tmp/bundle.json` (small CLI in `stix_builder.py` `__main__` for offline inspection) — assert the bundle validates with `stix2.parse(bundle, allow_custom=False)`.
3. **Live API**: `python -m src.hunter_client --actors TeamPCP` → prints hunt UUIDs and titles (mirrors the README curl example).
4. **OpenCTI integration**:
   - Stand the connector up via `docker-compose up` against a dev OpenCTI.
   - In the OpenCTI UI, open the Intrusion-Set `TeamPCP` → Enrichment → trigger `Cyborg Hunter`.
   - Confirm: 1+ new Report(s) appear (`report_types=threat-hunting`); on each Report's **Entities** tab: the sigma Indicator, MITRE Attack-Patterns, actors/campaigns/etc., and `TeamPCP` itself; attached Notes on the Report; relationship `indicator --indicates--> TeamPCP`.
   - Re-trigger: cache hit logged, no duplicate objects created.
   - Repeat for an Attack-Pattern (`T1059.007`), a Vulnerability (a CVE present in any hunt's `exploit_or_vulns`), and a Campaign (`Shai-Hulud 2.0`).

## Known limitations to document in `internal-enrichment/intel471-hunt/README.md`

- `validation_encoded_zip` is not extracted (security review needed before unzipping arbitrary attacker-adjacent payloads inside a connector).
- Single-process cache; multi-replica deployments need Redis backing.
- Connector creates entities on first encounter; renames in Hunter won't propagate (the connector keys on name-derived STIX IDs).
