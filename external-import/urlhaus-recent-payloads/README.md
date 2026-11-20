# OpenCTI URLhaus Recent Payloads Connector

Imports the most recent malware payloads of [URLhaus](https://urlhaus.abuse.ch) as
Artifacts, labelled with their file type and malware family signature.

## Authentication

The connector reads URLhaus either from the abuse.ch community API or from the
[Spamhaus commercial API](https://abusech-docs.spamhaus.com/api-reference). At least
one mode is required, otherwise the connector stops at startup.

| Mode | Settings | Host |
| --- | --- | --- |
| Community | `URLHAUS_RECENT_PAYLOADS_AUTH_KEY` | `urlhaus-api.abuse.ch`, `Auth-Key` header |
| Commercial | `URLHAUS_RECENT_PAYLOADS_SPAMHAUS_USERNAME` and `URLHAUS_RECENT_PAYLOADS_SPAMHAUS_PASSWORD` | `api.spamhaus.com`, JWT |

- `URLHAUS_RECENT_PAYLOADS_API_KEY` is the former name of `..._AUTH_KEY`. It still
  works, with a deprecation warning.
- **Both modes set**: the commercial mode is used. If the Spamhaus API cannot be used
  (network error, 5xx, rejected credentials), the run falls back to the community
  Auth-Key and logs a warning.
- **Only commercial credentials set** and they fail: the run fails and the log asks to
  check the Spamhaus credentials.

### Commercial mode

- The connector logs in once (`POST https://api.spamhaus.com/v1/login`, realm
  `abusech`), reuses the JWT until it is close to its expiry and logs in again once
  when the API answers 401.
- Payloads come from `GET /urlhaus/v1/payloads`, requested `since` the connector
  checkpoint (`import_start_date` on the first run) and following every page.
- Samples are downloaded with the JWT from `/urlhaus/v1/files/samples/<sha256>`. They
  come as an AES-encrypted zip (password `infected`): the connector opens it and
  checks the sha256 before the upload. A sample that cannot be opened is skipped with a
  warning.
- Every request carries the `User-Agent` `OpenCTI-urlhaus-recent-payloads/<version>`.
- The password, the JWT and the login response are never logged.

## Configuration

See [`__metadata__/CONNECTOR_CONFIG_DOC.md`](__metadata__/CONNECTOR_CONFIG_DOC.md) for
every setting, [`src/config.yml.sample`](src/config.yml.sample) and
[`docker-compose.yml`](docker-compose.yml) for examples.

The checkpoint (`last_first_seen`) only moves forward and keeps the same format in
both modes, so switching mode keeps the import going.
