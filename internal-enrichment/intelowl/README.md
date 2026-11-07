# OpenCTI IntelOwl Connector (Internal Enrichment)

Enriches observables with [IntelOwl](https://github.com/intelowlproject/IntelOwl), the open-source
platform that runs many threat intelligence analyzers (Tor exit node lists, abuse trackers,
DNS and reputation services, malware databases and more) on an observable in one request.

For each observable, the connector runs an IntelOwl **playbook**, waits for the job to finish,
and writes the results back to OpenCTI.

## Supported observables

| OpenCTI type | Sent to IntelOwl as |
|---|---|
| `IPv4-Addr`, `IPv6-Addr` | `ip` |
| `Domain-Name`, `Hostname` | `domain` |
| `Url` | `url` |
| `StixFile` | `hash` (SHA-256, else SHA-1, else MD5). Files without a hash are skipped. |

## What is created

- A **Note** on the observable with IntelOwl's aggregated verdict (`malicious`, `trusted` or no
  verdict), its reliability (0 to 10), tags, malware family, kill chain phase, the playbook used
  and the status of every analyzer. The note links to the job in IntelOwl. Its ID only depends on
  the results, so re-running an unchanged analysis updates the same note instead of adding one.
- The observable's **score** (`INTELOWL_UPDATE_SCORE`): reliability x 10 for a `malicious`
  verdict, 0 for `trusted`, unchanged when there is no verdict.
- **Labels** (`INTELOWL_CREATE_LABELS`): IntelOwl's tags (for example `tor_exit_node`, `scanner`,
  `phishing`) and the malware family.
- A **Malware** entity and a `related-to` relationship from the observable when IntelOwl names a
  malware family.

The created objects carry the observable's TLP and are authored by an `IntelOwl` organization.

## TLP handling

The connector uses the most restrictive TLP on the observable, from both the OpenCTI entity
and the STIX observable's marking references. It refuses observables whose TLP is above
`CONNECTOR_MAX_TLP`. Otherwise it sends that TLP to IntelOwl (`TLP:CLEAR`/`TLP:WHITE` as
`CLEAR`, `TLP:GREEN` as `GREEN`, `TLP:AMBER` as `AMBER`, `TLP:AMBER+STRICT` and `TLP:RED` as
`RED`, unmarked as `CLEAR`); IntelOwl has no AMBER+STRICT, so it is not relaxed to AMBER.
IntelOwl uses it to skip analyzers that are not allowed to share the observable with third
parties. Created objects carry the same TLP.

## Requirements

- OpenCTI Platform >= 6.8.12
- An IntelOwl instance (self-hosted, see the
  [IntelOwl installation guide](https://intelowlproject.github.io/docs/IntelOwl/installation/))
  and an API key for it (IntelOwl web UI, "API Access")

The default playbook, `FREE_TO_USE_ANALYZERS`, ships with IntelOwl and only uses analyzers
that need no third-party API key. Any other playbook configured in your IntelOwl can be used.

## Configuration

Configuration comes from `config.yml` in the connector directory or from environment variables
(which take precedence). See `config.yml.sample` and `docker-compose.yml`.

### OpenCTI

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | yes | | OpenCTI platform URL |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | yes | | Token of the connector's OpenCTI user |

### Connector

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| Connector ID | `connector.id` | `CONNECTOR_ID` | yes | | UUIDv4 unique to this instance |
| Name | `connector.name` | `CONNECTOR_NAME` | no | `IntelOwl` | Name shown in OpenCTI |
| Scope | `connector.scope` | `CONNECTOR_SCOPE` | no | `IPv4-Addr,IPv6-Addr,Domain-Name,Hostname,Url,StixFile` | Observable types to enrich |
| Auto | `connector.auto` | `CONNECTOR_AUTO` | no | `false` | Enrich new observables automatically. Each enrichment runs a full playbook, so keep it off unless your IntelOwl can absorb the load |
| Max TLP | `connector.max_tlp` | `CONNECTOR_MAX_TLP` | no | `TLP:AMBER` | Highest TLP sent to IntelOwl |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | no | `error` | `debug`, `info`, `warn` or `error` |

### IntelOwl

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| URL | `intelowl.url` | `INTELOWL_URL` | yes | | Base URL of the IntelOwl instance |
| API key | `intelowl.api_key` | `INTELOWL_API_KEY` | yes | | IntelOwl API key |
| Playbook | `intelowl.playbook` | `INTELOWL_PLAYBOOK` | no | `FREE_TO_USE_ANALYZERS` | Playbook run on each observable |
| Verify SSL | `intelowl.verify_ssl` | `INTELOWL_VERIFY_SSL` | no | `true` | Verify IntelOwl's TLS certificate |
| Poll interval | `intelowl.poll_interval` | `INTELOWL_POLL_INTERVAL` | no | `5` | Seconds between job status checks |
| Job timeout | `intelowl.job_timeout` | `INTELOWL_JOB_TIMEOUT` | no | `300` | Seconds to wait for a job before failing the enrichment |
| Update score | `intelowl.update_score` | `INTELOWL_UPDATE_SCORE` | no | `true` | Set the observable score from the verdict |
| Create labels | `intelowl.create_labels` | `INTELOWL_CREATE_LABELS` | no | `true` | Add tags and malware family as labels |

## Deployment

### Docker

```shell
docker build -t opencti/connector-intelowl:latest .
docker compose up -d
```

### Manual

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Behavior

1. Checks the observable is in scope and its TLP is at most `CONNECTOR_MAX_TLP`.
2. Starts the playbook with `POST /api/playbook/analyze_multiple_observables`, tagging the job
   `opencti` in IntelOwl.
3. Polls `GET /api/jobs/{id}` until the job is `reported_without_fails`,
   `reported_with_fails`, `killed` or `failed`, or `INTELOWL_JOB_TIMEOUT` passes.
4. Sends the original bundle plus the note, malware and relationship, with the observable's
   score and labels updated.

A failed or killed job, an IntelOwl error or a timeout fails the enrichment. When the request
comes from an OpenCTI playbook, the connector logs the problem and sends the playbook's bundle
back unchanged instead, so the playbook continues.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. The IntelOwl job ID is logged when a job starts, and every note
links to its job in the IntelOwl UI.

## Tests

```shell
bash run_test.sh ./internal-enrichment/intelowl/tests/test-requirements.txt
```
