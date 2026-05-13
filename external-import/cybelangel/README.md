# CybelAngel connector

External-import connector that ingests _claimed attacks_ from the
[CybelAngel platform](https://platform.cybelangel.com/) and maps them into
STIX 2.1 objects: intrusion sets, campaigns, victim organizations, sectors,
locations and the relationships between them.

## Requirements

- OpenCTI Platform >= 6.7.0
- Python >= 3.12 (matches the container base image)
- A CybelAngel API client (`client_id` / `client_secret`). The OAuth2 access
  token returned by `/oauth/token` is valid for 1 hour and the platform
  allows up to 2,000 tokens per month, so the connector reuses the same
  token within a run and only re-authenticates on a `401` response.
  See the [official CybelAngel authentication docs](https://developers.cybelangel.com/docs/cybelangel-platform-api/b6b6c2d4906e9-authentication)
  for details.

## Configuration variables

The connector reads its configuration from `config.yml` (manual deployment)
or from environment variables (Docker deployment).

### OpenCTI connectivity

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | URL of the OpenCTI platform.                         |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token configured in OpenCTI.       |

### Generic connector parameters

| Parameter          | config.yml          | Docker environment variable | Default       | Mandatory | Description                                                                |
|--------------------|---------------------|-----------------------------|---------------|-----------|----------------------------------------------------------------------------|
| Connector ID       | `id`                | `CONNECTOR_ID`              |               | Yes       | A unique `UUIDv4` identifier for this connector instance.                  |
| Connector Type     | `type`              | `CONNECTOR_TYPE`            | `EXTERNAL_IMPORT` | No    | Must be `EXTERNAL_IMPORT`.                                                 |
| Connector Name     | `name`              | `CONNECTOR_NAME`            | `CybelAngel`  | No        | Name of the connector as displayed in the OpenCTI UI.                      |
| Connector Scope    | `scope`             | `CONNECTOR_SCOPE`           | `all`         | No        | Scope of the connector.                                                    |
| Log Level          | `log_level`         | `CONNECTOR_LOG_LEVEL`       | `info`        | No        | One of `debug`, `info`, `warn`, `error`.                                   |
| Duration Period    | `duration_period`   | `CONNECTOR_DURATION_PERIOD` | `PT6H`        | No        | ISO 8601 duration between two runs (e.g. `PT6H` for 6 hours, `P1D` daily). |

### CybelAngel specific parameters

| Parameter        | config.yml       | Docker environment variable | Default                                       | Mandatory | Description                                                                                                                              |
|------------------|------------------|-----------------------------|-----------------------------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------|
| Client ID        | `client_id`      | `CYBELANGEL_CLIENT_ID`      |                                               | Yes       | OAuth2 client ID provided by CybelAngel.                                                                                                 |
| Client Secret    | `client_secret`  | `CYBELANGEL_CLIENT_SECRET`  |                                               | Yes       | OAuth2 client secret provided by CybelAngel.                                                                                             |
| API URL          | `api_url`        | `CYBELANGEL_API_URL`        | `https://platform.cybelangel.com`             | No        | Base URL of the CybelAngel platform API.                                                                                                 |
| Auth URL         | `auth_url`       | `CYBELANGEL_AUTH_URL`       | `https://auth.cybelangel.com/oauth/token`     | No        | OAuth2 token endpoint.                                                                                                                   |
| Marking          | `marking`        | `CYBELANGEL_MARKING`        | `TLP:AMBER+STRICT`                            | No        | TLP marking attached to every imported entity. Supported: `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`. |
| Fetch Period     | `fetch_period`   | `CYBELANGEL_FETCH_PERIOD`   | `7`                                           | No        | Number of days to look back on the **first** run. Use `all` to fetch every available claimed attack.                                     |

## Behavior

- Authenticates with the CybelAngel API using OAuth2 client credentials.
- On every run, queries `GET {api_url}/api/v1/threat-intelligence/claimed-attacks`
  for the period delimited by `start_date` / `end_date` (the previous
  successful `last_run` UTC timestamp on subsequent runs, falling back to
  `fetch_period` days on the first run).
- Each claimed attack is converted into a STIX 2.1 bundle containing:
  - One `Intrusion Set` per threat actor.
  - One `Location` per victim country and one `Identity` (class `class`)
    per victim industry.
  - One `Identity` (class `organization`) per victim organization.
  - One `Campaign` per `(threat actor, victim)` pair (or a single generic
    campaign when no victim is available).
  - The corresponding `targets` / `attributed-to` relationships between
    every campaign / intrusion set and the victim / location / sector
    entities.
- The bundle is sent to OpenCTI through the standard ingestion queue via
  `send_stix2_bundle`. The connector advances `last_run` only when the
  whole run completes successfully, so a transient failure does not cause
  data to be skipped on the next run.
- Scheduling is delegated to `OpenCTIConnectorHelper.schedule_iso`, which
  honours the configured `CONNECTOR_DURATION_PERIOD` and applies
  auto-backpressure when the OpenCTI queue is busy.

## Deployment

### Docker

```shell
docker build . -t opencti/connector-cybelangel:latest
docker compose up -d
```

### Manual

Create `config.yml` from `config.yml.sample`, install dependencies and
start the connector:

```shell
pip3 install -r src/requirements.txt
python3 src/cybelangel.py
```

## Sources

- [CybelAngel platform API documentation](https://developers.cybelangel.com/docs/cybelangel-platform-api)
