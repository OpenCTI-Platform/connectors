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
  the connector falls back to the community Auth-Key by catching
  `SpamhausCommercialError`.
- The community mode is not implemented here: the connector keeps calling its community
  host as before.

## Public API

```python
from connectors_sdk.shared.spamhaus import (
    AbuseChAuthConfigMixin,
    SpamhausAuthenticationError,
    SpamhausClient,
    SpamhausCommercialError,
    SpamhausInvalidResponseError,
    SpamhausUnavailableError,
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

## Errors

Every error that means "the commercial mode cannot be used" is a
`SpamhausCommercialError`, so a connector can catch one class to fall back:

| Error | Raised when |
|-------|-------------|
| `SpamhausAuthenticationError` | login refused (400, 401, 403), 401 after a re-login, 403 on a request |
| `SpamhausUnavailableError` | network error, timeout, HTTP 429 or 5xx, unexpected login response |
| `SpamhausInvalidResponseError` | a page with an unexpected shape, or a cursor that does not advance |

Other client errors (for example a 404 on a sample) are not commercial errors and
propagate as the `connectors-sdk` `ApiClientError` subclasses.

The password, the JWT and the login response never appear in a log or in an error
message.
