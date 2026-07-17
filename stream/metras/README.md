# OpenCTI Metras Stream Connector (STREAM)

Forwards OpenCTI **Indicator** create/update/delete events to
[Metras](https://dashboard.metras.sa/) **custom blocklists**.

## Important scope limitation
Metras has **no create-IOC and no create-rule API** — `/v1/yara/rule` and `/v1/sigma/rule`
are read-only. The only indicator-writable surface is `/v1/custom-blocklist`, which accepts
**file paths only**. Therefore this connector forwards **only indicators that carry a file
name or path** (STIX `[file:name = '...']`, optionally with `directory:path`). Indicators for
IPs, domains, or hashes are **skipped** and logged (`not pushable to Metras blocklist`).

## Event mapping

| OpenCTI event | Metras action |
|---|---|
| `create` (file indicator) | `POST /v1/custom-blocklist` with `file_paths` |
| `update` | resolve by name → `PATCH /v1/custom-blocklist/{id}` |
| `delete` | resolve by name → `DELETE /v1/custom-blocklist/{id}` |

The blocklist **name** is derived from the indicator's *name* (`opencti-<slug>`), not its
volatile STIX ID, so updates/deletes resolve to the same entry across re-imports.

## Behavior
- Listens via `helper.listen_stream()`; the main thread stays alive.
- **Never raises** on a push failure — logs and continues (won't drop the stream).
- Parses `msg.data` as a JSON string (`json.loads(msg.data)["data"]`).

## Requirements
- OpenCTI **7.260529.0** (`pycti==7.260529.0`).
- A Metras API key.
- A **live stream collection** in OpenCTI (Data → Data sharing → Live streams), **activated**,
  whose UUID goes in `CONNECTOR_LIVE_STREAM_ID`.

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` / `OPENCTI_TOKEN` / `CONNECTOR_ID` | yes | — | Standard connector settings |
| `CONNECTOR_NAME` | no | `Metras-Stream` | Connector name |
| `CONNECTOR_SCOPE` | no | `Metras` | Scope |
| `CONNECTOR_LIVE_STREAM_ID` | yes | — | UUID of an **activated** live stream collection |
| `CONNECTOR_LOG_LEVEL` | no | `info` | Log level |
| `METRAS_API_BASE_URL` | no | `https://api.metras.sa/api` | Metras API base URL |
| `METRAS_API_KEY` | yes | — | Metras API key |
| `METRAS_VERIFY_SSL` | no | `true` | Verify TLS certificates |
| `METRAS_BLOCKLIST_ACTION` | no | `ALERT` | `ALERT` or `BLOCK` |
| `METRAS_BLOCKLIST_PLATFORM` | no | `windows` | `windows` / `linux` / `darwin` |
| `METRAS_BLOCKLIST_SEVERITY` | no | `Medium` | `Informational`…`Critical` |

## Usage
```bash
cp config.yml.sample src/config.yml   # or use env vars / docker-compose
docker compose up -d --build
```
Before starting, create a **live stream collection** in OpenCTI
(Data → Data sharing → Live streams), **activate** it, and set its UUID as
`CONNECTOR_LIVE_STREAM_ID`. On startup the logs confirm the Metras API connection
(`[CONNECTOR] Metras API connection verified`) and that the stream listener has
started; the connector then forwards Indicator create/update/delete events to Metras
custom blocklists.

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| HTTP 410 "live stream is stopped" | The stream collection isn't activated — set `stream_live=true` |
| Connector exits right after startup | `CONNECTOR_LIVE_STREAM_ID` missing/invalid |
| Indicator not pushed | It has no file name/path — only file indicators are forwardable |
