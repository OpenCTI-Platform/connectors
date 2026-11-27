# Missing features compared with the existing CrowdStrike connector

What the existing connector (`external-import/crowdstrike`, indicator scope)
does that this proof of concept does not, or does differently. Compiled on
2026-11-20 from `crowdstrike_feeds_connector/indicator/importer.py`,
`indicator/builder.py`, `related_actors/builder.py` and
`crowdstrike_feeds_services/utils/labels.py`, against the POC chain
`CreateCrowdStrikeIndicator` -> `CrowdStrikeAddMalware` ->
`CrowdStrikeAddAttackPatterns` -> `MakeStixBundle` ->
`CrowdStrikeAddIdentity` -> `CrowdStrikeAddTlpMarking`.

To be dealt with later: each item says what the existing connector does and
where the POC stands.

## Objects the POC does not create

### Intrusion sets for actors

- **Existing connector**: one `IntrusionSet` per actor resolved through the
  CrowdStrike actors API, with aliases (`known_as`, plus a compact form such as
  `SALTYSPIDER`), description, `first_seen` / `last_seen` from the activity
  dates, primary and secondary motivations, goals from `objectives`, and an
  external reference to the actor's CrowdStrike URL. The indicator `indicates`
  each intrusion set. Enabled by the `actor` scope.
- **POC**: actors are already resolved at extraction (`actor_objects_list`,
  with the same fields), but only kept as `x_crowdstrike_actor_objects_list` on
  the indicator. No `IntrusionSet`, no relationship.
- **Note**: the closest gap to fill, a new transformer working on data the
  extraction already provides.

### Observables

- **Existing connector**: one observable per indicator (domain name, URL, IPv4
  / IPv6, file hashes, email address, email subject, file name, IP block,
  mutex, user agent, cryptocurrency wallet), with the labels, the score, the
  author and the marking, and a `based-on` relationship from the indicator to
  it. Controlled by `create_observables` and `create_indicators`.
- **POC**: no observable, no `based-on` relationship.

### Vulnerabilities

- **Existing connector**: one `Vulnerability` per entry of the indicator's
  `vulnerabilities`, and an `indicates` relationship from the indicator to each.
- **POC**: only kept as `x_crowdstrike_vulnerabilities`.

### Targeted sectors

- **Existing connector**: one sector `Identity` per entry of the indicator's
  `targets`, added to the bundle. No relationship links them:
  `_create_targets_relationships` exists but `build()` never calls it.
- **POC**: only kept as `x_crowdstrike_targets`.

## Indicator types not supported

- **Existing connector**: 16 types: `domain`, `url`, `ip_address`,
  `hash_md5`, `hash_sha1`, `hash_sha256`, `email_address`, `email_subject`,
  `file_name`, `file_path`, `ip_address_block`, `mutex_name`, `user_agent`,
  `bitcoin_address`, `coin_address`. Other types are skipped with a warning.
- **POC**: 6 types: `domain`, `url`, `ip_address`, `hash_md5`, `hash_sha1`,
  `hash_sha256`. Any other type makes `CreateCrowdStrikeIndicator` raise
  `ItemConversionError`; the connector logs and skips the item, so these
  indicators are lost.
- **Missing**: `email_address`, `email_subject`, `file_name`, `file_path`,
  `ip_address_block`, `mutex_name`, `user_agent`, `bitcoin_address`,
  `coin_address`.

## Indicator properties not set

| Property | Existing connector | POC |
|---|---|---|
| `x_opencti_score` | From configurable label lists: `indicator_low_score_labels`, `indicator_medium_score_labels`, `indicator_high_score_labels`, with their scores, and `default_x_opencti_score` otherwise | Absent |
| `indicator_types` | `threat_types` (or the `ThreatType/...` labels), `domain_types` and `ip_address_types`, merged, de-duplicated case-insensitively | Absent; the fields are kept as `x_crowdstrike_*` |
| `x_opencti_main_observable_type` | Set from the observable type | Absent |

## Filters and settings not available

| Setting | Existing connector | POC |
|---|---|---|
| Maximum age by type | Skips indicators whose `published_date` is older than a threshold per type (`ip`, `domain`, `url`, `hash`, `default`) | None |
| Unwanted labels (`indicator_unwanted_labels`) | Skips an indicator carrying one of these labels, case-insensitively | None |
| `exclude_types` | Excluded in the FQL filter of the API query | None |
| `create_observables` / `create_indicators` | Choose what to create | None (indicator only) |
| Scopes (`actor`) | Turn the intrusion sets on or off | None (actors always looked up, never turned into objects) |

`max_records_per_run` has an equivalent: `max_element_count` in the
extraction contract.

## Same feature, different result

- **Malware names**: the existing connector takes the families from the
  `Malware/...` labels (it overwrites the API's `malware_families` with them)
  and splits CamelCase: `Malware/ExampleFamily1` gives `Example Family1`. The
  POC uses the API's `malware_families` unchanged (`ExampleFamily1`). For a
  family with inner capitals, OpenCTI sees two different Malware entities, so
  the POC could create duplicates next to existing data.
- **Labels**: the existing connector removes the labels it turned into objects
  or fields (`Mitre ATT&CK/...`, `Malware/...`, `Actor/...`, `Threat Type/...`)
  and normalizes the others. The POC keeps every label unchanged.
- **Confidence**: the existing connector sets the connector-wide confidence
  level on every object. It also maps `malicious_confidence` to 90 / 50 / 10,
  but the builder never reads that value. The POC maps `malicious_confidence`
  to 85 / 50 / 15 (STIX 2.1 scale) on the indicator, and leaves it absent for
  `unverified`.
- **Attack patterns**: the existing connector resolves label technique names to
  a MITRE id through a lookup and builds minimal `AttackPattern` objects with
  CrowdStrike as author. The POC copies MITRE's object (id, name, `mitre-attack`
  reference) from a local ATT&CK dataset and uses the label's tactic to choose
  between techniques of the same name. Both add `indicates` relationships.

## In the existing connector, not features to port

- `ReportFetcher` is created and its cache cleared on each run, but
  `_get_reports_by_code` is never called in the indicator path.
- `actor_names_from_labels` (actors named by `Actor/...` labels) is computed
  and never used.
- The `malicious_confidence` -> `confidence` mapping (see above) is computed
  and never used.

## What the POC does that the existing connector does not

- `revoked` set from the indicator's `deleted`.
- An external reference with `source_name` `CrowdStrike` and the CrowdStrike
  indicator id.
- Every raw field kept (`x_crowdstrike_*`), so the source record can be rebuilt
  from the STIX indicator.
- Deterministic output: the same input always gives the same bundle.

## Real data

In the indicators readable from `raw-dumps/` (10 indicators, all hash types),
none had `actors`, `targets` or `vulnerabilities` set. That sample is too small
to tell how often the missing objects matter.
