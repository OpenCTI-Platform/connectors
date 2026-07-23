# RansomLook connector

The RansomLook connector is an OpenCTI `EXTERNAL_IMPORT` connector that imports newly published ransomware intelligence from the public RansomLook API. It creates deterministic STIX 2.1 claim graphs so overlapping collection windows update existing knowledge instead of creating duplicates.

| Status | Date | Comment |
| --- | --- | --- |
| Community | - | - |

## Use cases

- Monitor ransomware-group activity and newly claimed victims.
- Correlate ransomware incidents with organizations already present in OpenCTI.
- Maintain separately scoped victim-claim and ransomware actor-profile graphs.
- Preserve bounded claim captures and actor intelligence with explicit policy controls.

## Imported data

For each valid claim, the connector creates:

- an `Intrusion Set` for the ransomware group;
- an organization `Identity` for the claimed victim;
- an `Incident` for the ransomware claim;
- `targets` and `attributed-to` relationships between those entities;
- a `Report` containing the complete claim graph;
- optional direct victim website context and claim evidence;
- a separately traversable actor profile for infrastructure, named actors, notes, wallets, torrents, leaks, and explicit analysis intelligence enabled by policy.

Actor-profile history is not copied into every claim Report. Post screenshots and captured HTML source are retained as validated evidence Artifacts and Report files. Each accepted screenshot is available as `ransomnote.png` and as an embedded PNG file. HTML is preserved as a passive downloadable attachment. These evidence files do not populate Report main content and are never rendered, executed, or followed.

Named records returned by RansomLook's actor API are modeled as Threat Actor Individuals, never merged with ransomware-operation Intrusion Sets by name. The connector enumerates actors once per cycle, imports only actors with an explicit upstream relation to a group encountered in the claims window, and retains only explicit aliases, roles, contacts, wanted sources, profiles, peers, forums/markets, and group relations. Peer actors and forum/market Infrastructure remain in the actor-profile graph and are not copied into victim claim Reports. If the optional actor API is unavailable, claims continue normally and the incomplete profile enrichment remains eligible for retry.

Torrent and leak enrichment is evidence-scoped. A valid BitTorrent v1 infohash becomes a stable magnet URL observable; bounded `.torrent` metainfo can be retained as a passive Artifact, and explicit webseeds become contextual URL/domain observables. Only an explicit upstream post identifier places this evidence in that claim; an explicit group relation places it in the actor profile. Victim-name, domain, or other fuzzy corpus similarity does not create a direct claim assertion. Peer IP telemetry is disabled by default and, when enabled, remains context rather than an Indicator.

Technical-analysis support is capability-gated. The connector imports only explicit Malware mappings, syntactically valid ATT&CK technique IDs, and observables explicitly asserted malicious by the upstream API. Indicator creation also requires an explicit detection basis and the opt-in `RANSOMLOOK_CREATE_INDICATORS` policy. Analysis documents are retained only as passive PDF, HTML, or plain-text Artifacts under the common evidence budgets. Group analyses remain in the actor profile unless a stable upstream post ID explicitly links them to a claim.

## Requirements

- OpenCTI Platform 7.260710.0 or later, matching the pinned `pycti` release.
- A dedicated OpenCTI connector user named `RansomLook`, its token, and a unique connector UUID. OpenCTI derives its platform **Creators** field from the user owning the ingest token.
- HTTPS egress to `www.ransomlook.io` unless a different API base URL is configured.
- Docker, or Python 3.12 for a local installation.

RansomLook's public read endpoints do not require an API key. An optional key can be configured for deployments using an authenticated or self-hosted endpoint.

The connector sets the STIX `created_by_ref` / OpenCTI **Author** to the RansomLook Identity. OpenCTI sets **Creators** and native-file uploader metadata from the user whose `OPENCTI_TOKEN` performs ingestion. Use a dedicated user named `RansomLook` when the Creators label must also display RansomLook.

## Installation

### Docker Compose

1. Copy `docker-compose.yml` and set `OPENCTI_URL`, `OPENCTI_TOKEN`, and `CONNECTOR_ID`.
2. Review the optional settings, especially sensitive infrastructure, evidence budgets, and the initial history window.
3. Start the connector:

```bash
docker compose up -d connector-ransomlook
```

The image runs as an unprivileged user and includes a process health check. The supplied Compose service caps memory at 4 GiB. Custom deployments should provision at least the configured serialized-evidence budget plus response, graph, Python, and queue-serialization overhead.

### Local Python

From this connector directory:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r src/requirements.txt
cp config.yml.sample config.yml
python src/main.py
```

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`.

## Configuration

Settings can be supplied as environment variables or through `config.yml`. Environment variables take the names shown below.

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `OPENCTI_URL` | | Yes | OpenCTI platform URL. |
| `OPENCTI_TOKEN` | | Yes | API token for the dedicated OpenCTI user named `RansomLook`; this determines the platform Creators field and native-file uploader. |
| `CONNECTOR_ID` | Generated by SDK if omitted | Recommended | Unique connector UUID; set it explicitly for stable deployments. |
| `CONNECTOR_NAME` | `RansomLook` | No | Connector display name. |
| `CONNECTOR_SCOPE` | See sample | No | Imported STIX entity types. |
| `CONNECTOR_LOG_LEVEL` | `error` | No | One of `debug`, `info`, `warn`, `warning`, or `error`. |
| `CONNECTOR_DURATION_PERIOD` | `PT1H` | No | ISO 8601 interval between collection runs. |
| `RANSOMLOOK_API_BASE_URL` | `https://www.ransomlook.io/api` | No | RansomLook API root URL. |
| `RANSOMLOOK_API_KEY` | | No | Optional value sent in the `Authorization` header. |
| `RANSOMLOOK_LABELS` | `ransomware,ransomlook` | No | Comma-separated OpenCTI labels. |
| `RANSOMLOOK_MARKING_DEFINITION` | `TLP:CLEAR` | No | TLP marking applied to imported intelligence. |
| `RANSOMLOOK_INITIAL_HISTORY_DAYS` | `7` | No | First-run lookback in days (1–3650). |
| `RANSOMLOOK_MAX_RESPONSE_SIZE_MB` | `32` | No | Maximum accepted size of one upstream response in MiB (1–256). |
| `RANSOMLOOK_MAX_RECORDS_PER_ENDPOINT` | `1000` | No | Cap for one endpoint/aggregate collection and for nested torrent context values retained per group (1–10000). |
| `RANSOMLOOK_MAX_PAGES_PER_ENDPOINT` | `10` | No | Page cap for a paginated endpoint per run (1–100). |
| `RANSOMLOOK_MAX_REQUESTS_PER_RUN` | `2000` | No | Maximum physical upstream HTTP attempts, including retries, in one run (10–100000). |
| `RANSOMLOOK_MAX_RUN_DURATION_SECONDS` | `2700` | No | Shared monotonic deadline for all upstream requests in one run (60–86400 seconds). |
| `RANSOMLOOK_WORK_RECONCILIATION_TIMEOUT_SECONDS` | `900` | No | Maximum time to wait for OpenCTI worker completion for one logical delivery (10–7200 seconds). |
| `RANSOMLOOK_MAX_OBJECTS_PER_BUNDLE` | `500` | No | Maximum STIX objects in one dependency-complete input bundle (32–5000). Shared dependencies may be repeated across bundles; all remain under one work item. |
| `RANSOMLOOK_MAX_OBJECTS_PER_RUN` | `20000` | No | Maximum STIX objects accumulated during one connector run before undelivered claims are retained for retry (100–200000). |
| `RANSOMLOOK_MAX_BUNDLE_SIZE_MB` | `64` | No | Maximum serialized size of one dependency-complete input bundle before queue transport (1–256 MiB). Keep this at or below the deployment's queue-message limit. Startup rejects a value too small for the configured maximum claim-evidence payload. |
| `RANSOMLOOK_REPLAY_WINDOW_DAYS` | `1` | No | Days replayed before the claims cursor (0–6). The upper bound guarantees forward progress within the seven-day collection window. |
| `RANSOMLOOK_MAX_ARTIFACT_SIZE_MB` | `5` | No | Maximum decoded size of one evidence Artifact (1–32 MiB). This is independent of the HTTP response limit. |
| `RANSOMLOOK_MAX_ARTIFACTS_PER_CLAIM` | `2` | No | Maximum evidence Artifacts decoded for one claim (1–20). |
| `RANSOMLOOK_MAX_ARTIFACTS_PER_LOCATION` | `2` | No | Maximum evidence Artifacts decoded for one actor location (1–20). |
| `RANSOMLOOK_MAX_ARTIFACTS_PER_RUN` | `300` | No | Maximum evidence Artifact count per run (1–10000). |
| `RANSOMLOOK_MAX_ARTIFACT_BYTES_PER_RUN_MB` | `200` | No | Total decoded evidence budget per run (1–4096 MiB). |
| `RANSOMLOOK_MAX_EVIDENCE_SERIALIZED_BYTES_PER_RUN_MB` | `800` | No | Aggregate base64 bytes retained across Artifacts and Report files per run (1–16384 MiB). Every owner occurrence is charged; claim screenshots reserve three representations and claim HTML reserves two. |
| `RANSOMLOOK_MAX_PENDING_CLAIMS` | `5000` | No | Maximum incomplete claim/deferred-window records retained for bounded retry. |
| `RANSOMLOOK_MAX_CLAIM_RETRIES` | `5` | No | Retry limit for incomplete claim details, budget-deferred evidence, and unpageable post windows. |
| `RANSOMLOOK_MAX_PENDING_GROUPS` | `1000` | No | Maximum actor-profile groups retained for retry. |
| `RANSOMLOOK_MAX_ENRICHMENT_RETRIES` | `5` | No | Retry limit for transient actor-profile enrichment failures. |
| `RANSOMLOOK_RETRY_MAX_AGE_DAYS` | `30` | No | Maximum age of retryable claim/profile work before it becomes a non-retrying audit record. |
| `RANSOMLOOK_ENRICH_ACTOR_PROFILES` | `true` | No | Enrich groups encountered in the current claims window. |
| `RANSOMLOOK_IMPORT_INFRASTRUCTURE` | `true` | No | Import typed group infrastructure into actor profiles. |
| `RANSOMLOOK_IMPORT_SENSITIVE_INFRASTRUCTURE` | `false` | No | Import private, chat, admin, and file-server endpoint values. Opt in only when storage/access policy permits. |
| `RANSOMLOOK_IMPORT_POST_EVIDENCE` | `true` | No | Import bounded screenshot and HTML-source claim evidence. |
| `RANSOMLOOK_IMPORT_LOCATION_EVIDENCE` | `false` | No | Import bounded actor-location captures. These may contain multiple victims and sensitive material. |
| `RANSOMLOOK_IMPORT_NOTES` | `true` | No | Import ransom notes for groups encountered in new claims into the actor profile. A group-level note is not copied into a victim Report unless RansomLook explicitly links it to that claim. |
| `RANSOMLOOK_IMPORT_WALLETS` | `true` | No | Import group-associated cryptocurrency wallets as context, not Indicators. |
| `RANSOMLOOK_IMPORT_TORRENTS` | `true` | No | Import bounded torrent and magnet intelligence. |
| `RANSOMLOOK_IMPORT_TORRENT_PEERS` | `false` | No | Import peer telemetry as context. Peers never become Indicators automatically. |
| `RANSOMLOOK_IMPORT_LEAKS` | `true` | No | Import only deterministically related leak evidence. |
| `RANSOMLOOK_IMPORT_ANALYSES` | `true` | No | Import explicit analyses, malware, and TTP mappings when supported upstream. |
| `RANSOMLOOK_IMPORT_VICTIM_WEBSITES` | `true` | No | Import victim websites as non-malicious claim context. |
| `RANSOMLOOK_CREATE_INDICATORS` | `false` | No | Permit Indicator creation only for an explicit upstream malicious/detection assertion. |

### One-shot runs

For an intentional one-shot run, set `CONNECTOR_RUN_AND_TERMINATE=true` and `CONNECTOR_RESTART_POLICY=no`. The SDK scheduler owns one-shot flushing and termination; leaving the default restart policy enabled would restart the successfully terminated container.

## Runtime behavior

- The first run starts `RANSOMLOOK_INITIAL_HISTORY_DAYS` in the past and processes at most seven days per cycle, so large backfills cannot create unbounded bundles.
- After the first successful claims checkpoint, changing `RANSOMLOOK_INITIAL_HISTORY_DAYS` alone does not start another backfill. To intentionally re-run an older interval, stop the connector, clear this connector's saved state, set the larger lookback, and restart it.
- Later runs replay one day before the saved cursor. Stable IDs make this safe and allow late upstream publications to be collected.
- The connector does not emit Report main content. Screenshot and HTML evidence remain available through Report files and Artifacts only.
- Claims are requested in at-most-seven-day chunks and deduplicated across chunk boundaries. An oversized multi-day response is recursively subdivided within a request cap. An unpageable single day is persisted as bounded deferred work, so later ranges continue instead of pinning the normal cursor.
- Dedicated-post detail, run-budget evidence rejection, and transient claim-scoped context failures create bounded per-claim retry records. These records carry only the minimum route/context required to retry outside the overlap window. Retry count/age limits turn terminal work into a blocked audit record rather than silently dropping it or polling forever.
- Actor-profile retry records are admitted only while actor enrichment is enabled. Disabling the feature performs no pending profile calls and clears the obsolete backlog after the claims checkpoint succeeds.
- Group metadata enrichment is best-effort. If an all-history group response exceeds the configured limit, the connector fetches only each current claim's dedicated post and continues importing the core graph.
- Invalid or incomplete individual posts are logged and skipped.
- RansomLook API calls retry rate limits and transient server failures with exponential backoff. Every physical retry consumes the run request budget, and timeouts, streamed reads, and backoff are constrained by the shared run deadline.
- Responses larger than `RANSOMLOOK_MAX_RESPONSE_SIZE_MB` are rejected before conversion.
- Claim and enrichment object lists are deduplicated and every top-level STIX reference is validated against the complete logical graph. Sink objects such as Reports are grouped with their transitive dependencies; shared author, marking, group, or observable dependencies are repeated across groups when needed. Each dependency-complete input contains at most `RANSOMLOOK_MAX_OBJECTS_PER_BUNDLE` objects and is valid independently. Each is published atomically with `no_split=true`, so no per-chunk cleanup can strip a cross-bundle reference and concurrent workers cannot race a Report ahead of a Relationship in the same closure. Inputs are also packed under `RANSOMLOOK_MAX_BUNDLE_SIZE_MB`. During claim assembly, oversized optional direct leak/analysis context is omitted first; if necessary, oversized Report evidence is omitted next and recorded as an optional skip. The Incident, victim, group, and core relationships still deliver. A core or non-claim closure above either cap fails before queue submission with its state left retryable. All inputs remain under one work item.
- Each run emits a content-free metrics summary covering posts fetched, accepted, and skipped; objects and bundles delivered; optional skips; and accepted/rejected Artifact counts and decoded-byte budget consumption.
- Logical deliveries use multipart OpenCTI work. After queue submission, the connector closes the work and polls it with a hard timeout; success requires terminal `complete` status, no worker errors, and complete expectation tracking. Failed, incomplete, or timed-out work is closed with `in_error=true`, and the cursor is not advanced.
- A persisted content-fingerprint revision ledger advances `modified` whenever a source-owned mutable SDO changes and is committed only after reconciled delivery. Identical replay retains the prior version.
- Object confidence is governed by OpenCTI user and group confidence policies.

## Security and data handling

- Only HTTP and HTTPS website values with valid hostnames become observables or external references.
- Embedded screenshots and captured HTML source are retained only after bounded, strict validation as passive Artifacts. Accepted post captures are also attached to their Report with deterministic names, correct MIME/marking, and `no_trigger_import=true`; location captures are not copied into claim Files. The validated claim PNG is attached twice from the same accepted bytes: once as the normal downloadable Report File `ransomnote.png` and once, under a distinct content-addressed filename, as an OpenCTI embedded file. Each retained base64 representation consumes the serialized-evidence budget, while the source bytes consume the decoded budget once for that owner. The connector does not generate Report `x_opencti_content`; screenshot Markdown is therefore absent from Description & main content. HTML is never embedded or placed in Report main content, and is never rendered, executed, or followed.
- The API key is stored as a secret configuration value, is never emitted by connector logs, and can only be used with an HTTPS API URL.
- Operational logs do not include response payloads, base64 evidence, API secrets, or full private URLs. Sensitive identities and endpoint paths used in failure diagnostics are represented by short SHA-256 identifiers and exception classes.
- The container runs as the non-root `opencti` user with a read-only filesystem, all Linux capabilities dropped, and privilege escalation disabled by the supplied Compose configuration.
- Private/chat/admin/file-server values and location captures can contain sensitive operational or victim material. Both are disabled by default and require explicit opt-in.
- Post captures are enabled by default but are constrained independently by per-response, per-Artifact, per-claim, per-run-count, total decoded-byte, and aggregate emitted-base64 limits. Identical evidence used by different owners is charged for every retained occurrence.
- Disabling evidence never disables the core claim objects. HTML is stored as passive evidence and is never rendered or used for secondary requests.

## Troubleshooting

### Connector cannot register with OpenCTI

Verify `OPENCTI_URL`, `OPENCTI_TOKEN`, and network reachability. The connector user must have permission to register and submit bundles.

### RansomLook requests fail or time out

Confirm HTTPS access to the configured API host. Set `CONNECTOR_LOG_LEVEL=debug` to inspect request failures. HTTP 429 and transient 5xx responses are retried automatically.

### No objects are imported

Check that recent posts exist within the initial or replay window. Verify the connector scope permits every configured entity type and inspect the connector state in OpenCTI.

### Infrastructure or victim website context is not wanted

Set `RANSOMLOOK_IMPORT_INFRASTRUCTURE=false` and/or `RANSOMLOOK_IMPORT_VICTIM_WEBSITES=false`. Claim entities, reports, and relationships continue to be imported.

### Container is unhealthy

Inspect `docker logs connector-ransomlook`. The health check expects the scheduled `python3 main.py` process to remain active; configuration validation or OpenCTI connectivity failures cause that process to exit.

## Data source and attribution

- Website: <https://www.ransomlook.io/>
- API documentation: <https://www.ransomlook.io/doc/>
- Upstream source: <https://github.com/RansomLook/RansomLook>

RansomLook states that its API data is available under CC BY 4.0. Imported objects include RansomLook external references for attribution.
