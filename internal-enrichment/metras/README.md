# OpenCTI Metras Enrichment Connector (INTERNAL_ENRICHMENT)

Answers *"have I seen this in my fleet?"* by querying the [Metras](https://dashboard.metras.sa/)
platform when you enrich an observable in OpenCTI. Adds a context **Note** (and
**System identity** links to matched fleet endpoints) summarising local EDR/endpoint presence.

## Supported observables (`CONNECTOR_SCOPE`)

| Observable | Metras lookups | Output |
|---|---|---|
| **IPv4-Addr** | `/v1/edr/alerts?agent_ip=`, `/v1/endpoints?interface_ip=` | Note (alert + endpoint hits) + `related-to` **System identity** per matched endpoint |
| **StixFile** | `/v1/edr/binary/list?query=sha256:` / `?query=sha1:`, `/v1/edr/binary/details?md5=` | Note (publisher, signer, signature/runnability status, first/last seen) + System identity |

> Matched fleet endpoints are emitted as `Identity(identity_class="system")` (internal assets,
> not IOCs), consistent with the Feed connector and OpenCTI maintainer guidance (PR #6164).

> **Why only IPv4 + StixFile?** Metras exposes no value-lookup for domains or URLs, and
> `/v4/threats/detail` requires incident identifiers (title+direction+type), not an observable
> value. Domain/URL enrichment is therefore not offered.
>
> Fleet presence is conveyed via **Notes + relationships**, not STIX Sightings (the `stix2`
> library forbids a Sighting referencing an observable).

## Behavior & safety
- **Custom TLP check** (not `helper.check_max_tlp`) — skips observables above `METRAS_MAX_TLP`.
- **Refangs** values before querying Metras.
- **Partial results**: each lookup is wrapped; if at least one succeeds, results are sent.
  If *all* lookups fail, a `ValueError` is raised so the failure is visible in the OpenCTI UI.
- Playbook-compatible (`playbook_compatible=True`, `entity_in_scope()` guard).

## Requirements
- OpenCTI **7.260529.0** (`pycti==7.260529.0`). A Metras API key.

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` / `OPENCTI_TOKEN` / `CONNECTOR_ID` | yes | — | Standard connector settings |
| `CONNECTOR_NAME` | no | `Metras-Enrichment` | Connector name |
| `CONNECTOR_SCOPE` | no | `IPv4-Addr,StixFile` | Observable types to enrich |
| `CONNECTOR_AUTO` | no | `false` | Auto-enrich on observable creation |
| `CONNECTOR_LOG_LEVEL` | no | `info` | Log level |
| `METRAS_API_BASE_URL` | no | `https://api.metras.sa/api` | Metras API base URL |
| `METRAS_API_KEY` | yes | — | Metras API key |
| `METRAS_VERIFY_SSL` | no | `true` | Verify TLS certificates |
| `METRAS_MAX_TLP` | no | `amber+strict` | Max TLP to enrich (`clear`/`white`/`green`/`amber`/`amber+strict`/`red`) |

## Usage
Right-click an IPv4 or file-hash observable → **Enrich** → *Metras-Enrichment*, or set
`CONNECTOR_AUTO=true` to enrich automatically. Triggering via API uses
`stixCoreObjectEdit.askEnrichment(connectorId)` on OpenCTI 7.260529.0+.

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| "No Metras fleet data found" | The observable isn't present in your Metras fleet (expected for unknown IOCs) |
| Enrichment fails with auth error | Bad `METRAS_API_KEY` |
| File observable not enriched | Ensure `StixFile` is in `CONNECTOR_SCOPE` |
