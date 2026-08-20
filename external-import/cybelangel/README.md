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

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

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

The connector loads its configuration from `src/config.yml` (same directory
as `cybelangel.py`). Create that file from the provided sample, install
dependencies and start the connector:

```shell
cp src/config.yml.sample src/config.yml
# edit src/config.yml and fill in opencti.token, cybelangel.client_id,
# cybelangel.client_secret, ...
pip3 install -r src/requirements.txt
python3 src/main.py
```

## Sources

- [CybelAngel platform API documentation](https://developers.cybelangel.com/docs/cybelangel-platform-api)
