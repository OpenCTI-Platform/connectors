# TDR: Provider-specific code shared by several connectors (`connectors_sdk.shared`)

<br>

## Overview

`connectors_sdk.shared` holds the code that several connectors share because they read the same provider: the login, the client and the authentication settings.
It has one subpackage per provider. The first one is `connectors_sdk.shared.spamhaus`, for ThreatFox, URLhaus and MalwareBazaar.

```python
from connectors_sdk.shared.spamhaus import SpamhausClient
```

<br>

## Motivation

The abuse.ch connectors (ThreatFox, URLhaus, MalwareBazaar) are moving to the Spamhaus commercial API, with the same login, JWT handling, cursor pagination and settings.
Copying that code into each connector means three copies of an authentication flow to fix and to keep in sync.

The SDK did not have a place for it: everything in it so far is generic (models, settings, state, errors, base clients).
Without a rule, the next shared provider client would have to guess where to go and what is allowed in it.

<br>

## Proposed Solution

Provider-specific code shared by several connectors goes into `connectors_sdk/shared/<provider>/`.

**What goes in**
- The authentication flow, the HTTP client and the settings fields of one provider.
- Only what at least two connectors use. Code used by one connector stays in that connector.

**What stays in the connectors**
- The mapping of the provider's data to STIX, and anything specific to one connector.

**Rules for a shared provider package**
- One subpackage per provider, with an `__init__.py` that exports the public API, a how-to under `connectors-sdk/docs/` and its tests under `tests/test_shared/test_<provider>/`.
- No new runtime dependency: only what `connectors-sdk` already requires.
- Build on the SDK: `BaseClientApi` for the HTTP calls, `SecretStr` for secrets, and the standard `ProviderApi*` errors.
  A package does not define its own error classes only to signal "this mode failed". A connector that can fall back catches `ProviderApiError` around the call, and OpenCTI gets the right `api.*` code.
- A secret never appears in a log, an error message or a validation error.
- Same quality bar as the rest of the SDK: strict `mypy`, `ruff`, and 100% test coverage.

<br>

## Advantages

- One fix for all the connectors of a provider, and one place to test the authentication flow.
- Connectors already depend on `connectors-sdk`: no second package to pin, and no second versioning path.
- A change to a shared client is tested with the SDK, not through the tests of every connector.

<br>

## Disadvantages

- The SDK ships provider-specific code, which is not its main role as a development kit. The rules above are there to keep it small: only shared code, no new dependency.
- A change in a shared client is released with the SDK, so a connector gets it by raising its SDK version.

<br>

## Alternatives Considered

- **A separate package under `shared/` of the repository** (first version of the Spamhaus client).
  It is the first runtime package in `shared/`, which only held CI tooling until then. Connectors would pin it from git, next to the SDK pin, and any change under `shared/` runs the tests of all the connectors.
- **A copy in each connector.** No new place to maintain, but three copies of the same authentication flow.

<br>

## References

- `connectors-sdk/connectors_sdk/shared/spamhaus/`
- `connectors-sdk/docs/HOW-TO-Use-the-Spamhaus-client.md`
- [Error handling in connectors](../docs/HOW-TO-Handle-errors-in-connectors.md)
- Pull request [#8529](https://github.com/OpenCTI-Platform/connectors/pull/8529)
