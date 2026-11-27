# HOW TO use the Spamhaus client

`connectors_sdk.shared.spamhaus` holds what the abuse.ch connectors (ThreatFox, URLhaus
and MalwareBazaar) share to read the Spamhaus commercial API (`https://api.spamhaus.com`):
the login with a username and a password, the JWT, the cursor pagination and the
authentication settings.

It has no dependency other than the ones of `connectors-sdk` (`pydantic`, `requests`).
A connector that already depends on `connectors-sdk` has nothing more to install.

## Authentication modes

| Mode | Configuration | Host |
|------|---------------|------|
| Community | `auth_key` (abuse.ch Auth-Key, `Auth-Key` header) | community hosts (`threatfox-api.abuse.ch`, ...) |
| Commercial | `spamhaus_username` and `spamhaus_password` | `api.spamhaus.com`, with a JWT |

- At least one mode must be configured, otherwise the settings validation fails and
  names both options.
- When both are configured, the commercial mode wins (`use_commercial`). If it fails,
  the connector falls back to the community Auth-Key by catching `ProviderApiError`
  around the Spamhaus call.
- The community mode is not implemented here: the connector keeps calling its community
  host as before.

## Public API

```python
from connectors_sdk.shared.spamhaus import (
    AbuseChAuthConfigMixin,
    SpamhausClient,
    build_user_agent,
)
```

- `AbuseChAuthConfigMixin`: settings fields `auth_key`, `spamhaus_username` and
  `spamhaus_password` (`SecretStr`, a blank value counts as unset), the validation of the
  two modes, and the properties `community_configured`, `commercial_configured` and
  `use_commercial`. Add it to the connector's settings section and set
  `auth_env_prefix` (for example `"THREATFOX"`) so that the validation message names the
  environment variables. A connector may override `community_configured` when another
  setting also gives access to the community API.
- `SpamhausClient(username=..., password=..., connector_name=..., connector_version=...)`:
  - `login()`: `POST /v1/login` with the realm `abusech`.
  - `get_json(path, params=None)`: GET a JSON resource with the JWT.
  - `get_bytes(path, params=None)`: GET a binary resource (sample files).
  - `paginate(path, params=None, page_size=100)`: yields the `items` of every page,
    following `meta.next_cursor` with `after`.
- `build_user_agent(connector_name, version)`: `OpenCTI-<connector>/<version>`, sent on
  every request (Spamhaus rejects the default Python User-Agent with a 403).

The client logs in once, reuses the JWT until 300 seconds before its expiry (the
`expires` field of the login response), and logs in again exactly once when the API
answers 401, then retries. It never logs in for each request.

`urllib3` never retries a POST, so the client replays the login itself, once, after a
5xx answer or a network failure (a refused login is not replayed). With
`max_retries=0` nothing is replayed.

## Errors

The client raises the standard `connectors-sdk` provider errors, so OpenCTI gets the
matching `api.*` code. A connector that holds a community Auth-Key catches
`ProviderApiError` around the Spamhaus call to fall back:

| Error (code) | Raised when |
|--------------|-------------|
| `ProviderApiAuthenticationError` (`api.authentication`) | login refused (400, 401, 403), 401 after a re-login |
| `ProviderApiAuthorizationError` (`api.authorization`) | 403 on a request |
| `ProviderApiRateLimitError` (`api.rate_limit`) | HTTP 429, on a request or on the login |
| `ProviderApiServerError` (`api.server`) | HTTP 5xx, on a request or on the login |
| `ProviderApiTimeoutError` (`api.timeout`) | a request or the login times out |
| `ProviderApiConnectionError` (`api.connection`) | the API cannot be reached (network, DNS, TLS) |
| `ProviderApiInvalidResponseError` (`api.invalid_response`) | any other 4xx (400, 404, 422...) on `get_json` or `paginate`, a 200 whose body is not valid JSON, a page with an unexpected shape, a cursor that does not advance, an unexpected login response |

A 4xx on `get_bytes` (for example a 404 on a sample) only concerns that file: it
propagates as the `connectors-sdk` `ApiClientError` subclasses and does not mean the
commercial mode is unusable.

The password, the JWT and the login response never appear in a log or in an error
message.
