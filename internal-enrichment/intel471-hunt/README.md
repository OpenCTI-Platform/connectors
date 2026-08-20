# OpenCTI — Intel 471 Hunter Internal Enrichment Connector

On-demand enrichment of OpenCTI entities (Threat-Actor / Intrusion-Set,
Campaign, Attack-Pattern, Vulnerability, Malware) with detection coverage from
the [Intel 471 Hunter](https://hunter.cyborgsecurity.io/) hunt package corpus
(formerly Cyborg Security Hunter, `/es/query` endpoint).

When an analyst triggers enrichment on a supported entity, the connector
queries Hunter with the right filter (e.g. `actors=TeamPCP`,
`mitre_technique_ids=T1059.007`), then materialises each returned hunt as a
STIX 2.1 **Report** (mirroring the Verity report shape). The Report's
`object_refs` — the OpenCTI **Entities** tab — carry the sigma detection as an
**Indicator** plus all the auto-created context (Threat-Actor / Campaign /
Malware / Vulnerability / Attack-Pattern / Tool / Sector / Location) and the
relationships that connect them. Analyst runbook, mitigation, validation and
running-update Notes attach to the Report.

---

## Quick start

### Docker (matches the upstream OpenCTI connector layout)

```bash
cp config.yml.sample config.yml         # or rely on env vars / compose
# fill in OPENCTI_URL, OPENCTI_TOKEN, CONNECTOR_ID (uuidgen), HUNTER_API_KEY
docker compose up -d --build
```

Then in OpenCTI: open a supported entity → **Enrichment** → trigger
**Intel 471 Hunter**.

### Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## Running without OpenCTI

All scenarios run from the connector directory after `pip install -e ".[dev]"`.

### 1. Unit tests (no network, no API key)

```bash
pytest
```

Fixture-driven against `tests/fixtures/response.json`. Exercises
`entity_mapper`, `hunter_client` (mocked HTTP), `cache`, `severity`, and
`stix_builder` against a real captured Hunter response.

### 2. Full pipeline dry run (live network, full STIX bundle, no OpenCTI)

This is the closest thing to a real enrichment — same code path the connector
takes in production, just without OpenCTI on the other end.

```bash
export HUNTER_API_KEY=...

python -m src.dry_run \
  --entity-type Threat-Actor-Group \
  --entity-name TeamPCP \
  --out /tmp/teampcp-bundle.json
```

What it does:

1. Constructs a fake OpenCTI entity (`{entity_type, name, standard_id}`) using
   a deterministic synthesised STIX id.
2. Runs it through `entity_mapper.build_query` to derive the Hunter filter.
3. Calls the live Hunter API.
4. Builds a STIX bundle exactly as the real connector would, including the
   trigger-entity linking — so you can verify each `Indicator` points at
   your synthesised STIX id and no duplicate entity is created for the
   triggering name.

Output to stderr shows the entity, derived query, hunt count, and bundle
size; the bundle JSON goes to `--out` (or stdout if omitted).

More examples:

```bash
# MITRE technique trigger
python -m src.dry_run --entity-type Attack-Pattern --entity-name JavaScript \
                     --mitre-id T1059.007

# Campaign
python -m src.dry_run --entity-type Campaign --entity-name "Shai-Hulud 2.0"

# Vulnerability
python -m src.dry_run --entity-type Vulnerability --entity-name CVE-2024-0001
```

Supported `--entity-type` values: `Threat-Actor`, `Threat-Actor-Group`,
`Threat-Actor-Individual`, `Intrusion-Set`, `Campaign`, `Attack-Pattern`,
`Vulnerability`, `Malware`, `Tool`, `Sector`, `Country`, `Region`.

---

## Configuration

Every key is configurable via `config.yml` or env-var override. Env-var names
follow pycti convention (uppercased, dot-separated → underscore).

| `config.yml` key                  | Env var                              | Default                                   |
| --------------------------------- | ------------------------------------ | ----------------------------------------- |
| `opencti.url`                     | `OPENCTI_URL`                        | —                                         |
| `opencti.token`                   | `OPENCTI_TOKEN`                      | —                                         |
| `connector.id`                    | `CONNECTOR_ID`                       | —                                         |
| `connector.scope`                 | `CONNECTOR_SCOPE`                    | `Report,Indicator,Note,Intrusion-Set,Threat-Actor,Threat-Actor-Group,Threat-Actor-Individual,Campaign,Attack-Pattern,Vulnerability,Malware,Tool,Sector,Country,Region` |
| `connector.auto`                  | `CONNECTOR_AUTO`                     | `false`                                   |
| `connector.confidence_level`      | `CONNECTOR_CONFIDENCE_LEVEL`         | `75`                                      |
| `hunter.api_base_url`             | `HUNTER_API_BASE_URL`                | `https://api.hunter.cyborgsecurity.io`    |
| `hunter.api_key`                  | `HUNTER_API_KEY`                     | —                                         |
| `hunter.ui_base_url`              | `HUNTER_UI_BASE_URL`                 | `https://hunter.cyborgsecurity.io`        |
| `hunter.indexes`                  | `HUNTER_INDEXES`                     | `cyborg_usecases`                         |
| `hunter.request_timeout_seconds`  | `HUNTER_REQUEST_TIMEOUT_SECONDS`     | `30`                                      |
| `hunter.max_results_per_query`    | `HUNTER_MAX_RESULTS_PER_QUERY`       | `100`                                     |
| `hunter.cache_path`               | `HUNTER_CACHE_PATH`                  | `/opt/connector/cache/cache.json`         |
| `hunter.cache_ttl_hours`          | `HUNTER_CACHE_TTL_HOURS`             | `24`                                      |

> **Scope is also an import filter.** For internal-enrichment connectors OpenCTI
> applies `CONNECTOR_SCOPE` as a type-filter on the *returned* bundle, silently
> discarding any object whose type isn't listed (no error, no log — just a
> ticked work expectation). So the scope must include every type the connector
> **emits** — `Report`, `Indicator`, `Note` — not only the types it's triggered
> on. Symptom if you get this wrong: entities/relationships appear but the
> **Report never shows up** (relationship endpoints get back-created, containers
> don't).

---

## What the connector emits

For each Hunter hunt returned by the query:

- **1 Report** (`report--<hunt_uuid>`, `report_types=["threat-hunting"]`) — the
  hunt package itself. Carries the title, description, `published` date,
  `x_opencti_score` (90/60/30 from Hunter severity), labels for
  threat-categories / kill-chains / target-OSes, and external references back
  to the Hunter UI plus every URL in `references.{general,analysis,deep_dives,blog_links,malware_samples}`.
  Its `object_refs` (the **Entities** tab) contain the Indicator, every entity
  below, and the relationships between them.
- **1 Indicator** (`indicator--<hunt_uuid>`) with `pattern_type=sigma`,
  `pattern=<sigma yaml>`, the severity label and score, and a Hunter UI
  back-link — kept lean, since the context lives on the Report.
- **Notes** attached to the Report: Analyst runbook, Mitigation
  recommendations, Validation, and one Note per `running_analyst_notes` entry
  (using its `analyst_note_date` / `analyst_note_type`).
- **Attack-Patterns** for every MITRE technique in `mapping.mitre.mitre_attack_payload`,
  with `kill_chain_phases` derived from the tactic list.
- **Intrusion-Sets** for `tags.actors`.
- **Campaigns** for `tags.campaigns`.
- **Malware** for `tags.threat_names`, only when `tags.threat_categories`
  contains `"Malware"` (otherwise the threat name lands as a label
  `threat:<name>`).
- **Vulnerabilities** for `tags.exploit_or_vulns` ∪ `mapping.exploit_or_vulns`.
- **Tools** for `tags.tools` ∪ `tags.tooling`.
- **Sectors** (Identity, identity_class=class) for `tags.target_industries`.
- **Countries** (Location, x_opencti_location_type=Country) for
  `tags.target_countries` ∪ `tags.source_countries`.
- **Regions** (Location, x_opencti_location_type=Region) for
  `tags.target_regions` ∪ `tags.source_regions`.
- **Relationships**: `Indicator --indicates--> {Intrusion-Set, Campaign,
  Malware, Vulnerability, Attack-Pattern, Tool, Sector, Country, Region}`,
  plus `Intrusion-Set --uses--> Attack-Pattern` when both are present. When the
  enrichment was triggered on an entity, the Indicator also `indicates` that
  entity and the entity is added to the Report's Entities tab.

The connector identity (`Intel 471 — Hunter`, organization) is set as
`created_by_ref` on every object. Re-enriching an updated hunt reuses the same
`report--`/`indicator--` ids (both keyed on the hunt UUID), so OpenCTI updates
in place rather than creating duplicates.

---

## Entity → Hunter query mapping

| OpenCTI entity                              | Hunter param           |
| ------------------------------------------- | ---------------------- |
| Intrusion-Set / Threat-Actor (any flavour)  | `actors`               |
| Campaign                                    | `campaigns`            |
| Attack-Pattern                              | `mitre_technique_ids` (preferred) → `mitre_technique_names` |
| Vulnerability                               | `exploit_or_vulns`     |
| Malware                                     | `threat_names`         |
| Tool                                        | `tools`                |
| Sector                                      | `target_industries`    |
| Country / Location (sub-type Country)       | `target_countries` ∪ `source_countries`  |
| Region / Location (sub-type Region)         | `target_regions` ∪ `source_regions`      |

Aliases on the entity are included when present.

Location triggers fan out to **two separate API calls** (target_\* and
source_\*) and the connector unions the results by hunt UUID. Hunter's content
authors populate the source-attribution side far more consistently than the
target side, so a single `target_countries=X` call usually returns 0 even for
common nation-state actors. The API ANDs across query params within a single
call, which is why this can't be expressed as one request.

Full Hunter `/es/query` parameter spec:
[`https://api.hunter.cyborgsecurity.io/docs`](https://api.hunter.cyborgsecurity.io/docs).

---

## Cache

The connector caches `(hunt_uuid, last_updated)` to disk
(`HUNTER_CACHE_PATH`). On repeated enrichments of the same entity, hunts that
haven't been updated upstream are skipped. The cache entry also has a TTL
(`HUNTER_CACHE_TTL_HOURS`, default 24h) so a stuck/failed push self-recovers
on the next trigger.

For multi-replica deployments this should be replaced with Redis (out of scope
for v1).

---

## Known limitations

- **`validation_encoded_zip`** (base64 zip with Atomic Red Team payloads) is
  intentionally not extracted — link out to the Hunter UI for validation
  artifacts.
- **Cache** is local-file / single-process; multi-replica deployments need a
  shared store.
- **Renames** in Hunter (changed hunt title / actor name) won't propagate
  cleanly because the related entities use name-derived deterministic STIX
  IDs.

---

## Testing

```bash
pytest                            # everything (offline, fixture-driven)
pytest tests/test_stix_builder.py # builder tests against the captured fixture
```

The fixture `tests/fixtures/response.json` is a real Hunter capture (9 hunts
including the Shai-Hulud 2.0 supply-chain hunts) — it exercises every code
path: MITRE techniques, actors, campaigns, malware classification, running
analyst notes.
