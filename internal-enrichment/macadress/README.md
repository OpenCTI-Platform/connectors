# OpenCTI macadress.com Enrichment Connector (INTERNAL_ENRICHMENT)

Enriches a `Mac-Addr` observable with data from the [macadress.com](https://macadress.com/)
API: the IEEE-registered vendor, an inferred device category, virtualization and
special-use classification, and MAC-randomization confidence. The observable is
updated in place and, when the vendor lookup is reliable, linked to a vendor
Organization identity.

## Supported observable (`CONNECTOR_SCOPE`)

| Observable | API call | Output |
|---|---|---|
| **Mac-Addr** | `GET /v1/mac/{mac}` | Observable description, score and labels; `macadress.com` author identity; a vendor **Organization identity** + `related-to` relationship; a summary **Note** |

## What it writes

On the enriched observable (via `OpenCTIStix2.put_attribute_in_extension`):

- `x_opencti_description` - markdown summary (vendor, registered block, device, virtualization, special use, randomization)
- `score` - `MACADRESS_DEFAULT_SCORE` (default `30`)
- `labels` - always `macadress`; plus device category, `locally-administered` / `universally-administered`, `mac-randomized`, `virtualization:<platform>`, `special-use:<type>` when applicable
- `external_references` - `https://macadress.com/lookup/<mac>` and the vendor page when available

Appended STIX objects:

- **Identity** `macadress.com` (organization) - author / `created_by_ref`
- **Identity** for the registering vendor (organization, `x_opencti_organization_type: vendor`) plus `mac-addr --related-to--> identity`. Skipped when the API marks the vendor lookup unreliable (for example a locally administered or randomized MAC), or when `MACADRESS_CREATE_VENDOR_IDENTITY=false`.
- **Note** with the full analysis (`MACADRESS_CREATE_NOTE=true`, default). Its id is stable per MAC, so re-enrichment updates the note instead of duplicating it.

## Behavior and safety

- **Max TLP check** (`OpenCTIConnectorHelper.check_max_tlp`) - observables above `MACADRESS_MAX_TLP` are skipped.
- A `400` from the API (not a MAC address) and an invalid result return the original bundle unchanged.
- `401` / `403` / `429` / `5xx` are raised so the failure is visible in the OpenCTI UI.
- Playbook compatible (`playbook_compatible=True`).

## Requirements

- OpenCTI `>= 7.260722.0`.
- A macadress.com API key (Bearer token, free tier available at https://macadress.com/).

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` / `OPENCTI_TOKEN` / `CONNECTOR_ID` | yes | - | Standard connector settings |
| `CONNECTOR_NAME` | no | `macadress.com` | Connector name |
| `CONNECTOR_SCOPE` | no | `mac-addr` | Observable types to enrich |
| `CONNECTOR_AUTO` | no | `false` | Auto-enrich on observable creation |
| `CONNECTOR_LOG_LEVEL` | no | `info` | Log level |
| `MACADRESS_API_BASE_URL` | no | `https://api.macadress.com` | API base URL |
| `MACADRESS_API_KEY` | yes | - | macadress.com API key |
| `MACADRESS_MAX_TLP` | no | `TLP:AMBER` | Max TLP to enrich |
| `MACADRESS_DEFAULT_SCORE` | no | `30` | Score written on the observable |
| `MACADRESS_CREATE_NOTE` | no | `true` | Attach the analysis summary as a Note |
| `MACADRESS_CREATE_VENDOR_IDENTITY` | no | `true` | Create and link the vendor Organization identity |

## Usage

Right-click a MAC address observable in OpenCTI, choose **Enrich** and select
*macadress.com*, or set `CONNECTOR_AUTO=true` to enrich automatically.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "could not parse the MAC address" | The observable value is not a MAC address |
| Enrichment fails with an auth error | Bad `MACADRESS_API_KEY` |
| No vendor identity created | Locally administered / randomized MAC, or `MACADRESS_CREATE_VENDOR_IDENTITY=false` |
| HTTP 429 | Free-tier monthly quota or rate limit reached |
