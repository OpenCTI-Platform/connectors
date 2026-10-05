# AGENTS.md — Intel 471 v2 connector

Guidance for AI agents (and humans) working in this directory. Keep changes
minimal and match the surrounding style.

## Golden rule: changelog + version

Every **user-facing change** (new/changed behaviour, new config option, bug fix)
and every **dependency upgrade** (`src/requirements.txt`) must, in the same commit:

1. Add an entry to [`changelog.md`](changelog.md) under a **new version section**
   at the top of the file.
2. Update [`src/__version__`](src/__version__) to the **same** version.

By default, increment the **patch** bit (e.g. `2.2.1` → `2.2.2`). Bump a higher
bit only when the change clearly warrants it.

**Exempt** (no changelog entry, no version bump): pure refactors, test-only
changes, and internal/dev docs (including this file).

`changelog.md` format — newest version first, two-space `+ ` bullets:

```
# v2.2.2

  + Short description of the change
  + Link upgraded SDKs, e.g. Upgrade `verity471` to version [1.1.8](https://github.com/intel471/verity471-python/releases/tag/v1.1.8)
```

`src/__version__` is a single line, **no** `v` prefix (e.g. `2.2.2`). It is read
by `src/intel471/version.py` and appended to the API client User-Agent, so it
must always reflect the released version.

## What this connector does (and does not) do

This connector is **OpenCTI logistics only**. The heavy lifting — turning
Intel 471 API responses into STIX 2.1 — is done by the vendor SDKs:

- **`titan-client`** (`titan_client.titan_stix`) — the legacy Titan backend.
- **`verity471[stix]`** (`verity471.verity_stix`) — the newer Verity471 backend
  (a superset of Titan).

The connector calls `api_response.to_stix(...)` and ships the resulting bundle.
**Do not add STIX mapping logic here.** If a mapping is wrong or missing, the fix
belongs in the relevant SDK; here you typically only bump the SDK version (and
add a changelog entry per the golden rule). The connector's job is: scheduling,
paging/cursor management, OpenCTI state, and sending bundles.

## Code map (`src/intel471/`)

- `connector.py` — `Intel471Connector`: APScheduler `BackgroundScheduler` runs one
  job per enabled stream on its configured interval. Streams run in threads, so
  all OpenCTI **state** reads/writes are funnelled through `in_queue`/`out_queue`
  and serviced by `handle_helper_state()` to avoid race conditions
  (`HelperRequest` in `common.py`).
- `settings.py` — pydantic config (`ConnectorSettings`) built on `connectors-sdk`.
  Env vars are `INTEL471_*` / `CONNECTOR_*` / `OPENCTI_*`. A stream is enabled
  only if its `interval_<group_label>` is set (non-zero). The `initial_history_*`
  fields use the `EpochMillis` annotated type, which converts a value given in
  epoch seconds and rejects one that is neither unit — see "Initial history units".
- `backend.py` — `get_client(backend_name, ...)` returns a `ClientWrapper` that
  bundles the chosen SDK module, its `Configuration`, its STIX mapper settings
  class, its empty-bundle exception, and the tuple of stream classes. This is the
  single switch between `titan` and `verity471`. Proxy (incl. authenticated
  proxy) is wired here.
- `streams/core/base.py` — `Intel471Stream` (ABC). Holds the fetch loop:
  cursor + offset paging, calling the API method, calling `.to_stix(...)`, and
  `send_to_server()`. This is where almost all shared logistics lives.
- `streams/titan/` and `streams/verity471/` — thin per-stream subclasses. Most
  just declare class vars; some override `_get_api_kwargs` / `_get_cursor_value`
  / `_get_offsets`.

## Reports-API auth / authorization errors

The reports API returns four distinct auth/authorization responses. They are **not**
distinguishable by HTTP status alone (1a and 3 are both 401; the backend even remaps
1a's status internally), so `Intel471Stream.get_bundles()` (`streams/core/base.py`)
discriminates on the **response body**:

| # | HTTP | Body | Cause | Scope | Handling |
|---|------|------|-------|-------|----------|
| 1a | 401 | `<type> not in users access claims.` | Holds ≥1 report claim but not **this** type | one report type | **softened** |
| 1b | 403 | `User does not have any report related claims.` | Zero report claims | all report types | raised |
| 2  | 403 | `You cannot consume this service` *(Kong ACL)* | Reports API not added to the App | entire Reports API | raised |
| 3  | 401 | `Unauthorized` *(Kong gateway)* | Bad/missing credentials | everything | raised |

Only **case 1a** is softened: it is an expected, per-report-type entitlement gap, and
each report type runs as its own scheduler job, so the others are unaffected. It is
matched by the substring `ACCESS_CLAIMS_SIGNATURE = "access claims"` (which uniquely
identifies 1a) and reported via a one-time `WARNING` (then `DEBUG`) instead of a
recurring `ERROR` traceback, after which the stream's run ends cleanly.

Everything else — 1b, 2, 3, and any unrecognised auth error — is **re-raised** on
purpose: each means a whole stream/category cannot run, which is a real problem the
operator should see. The exception classes caught per backend
(`UnauthorizedException`, `ForbiddenException`) are supplied via
`ClientWrapper.auth_exceptions` in `backend.py`, alongside `empty_bundle_exception`.

## Initial history units

The APIs take `initial_history` in **epoch milliseconds**. A value handed over in
seconds reads as a date in early 1970, which silently turns "fetch from last month"
into "fetch the entire history", so the unit is normalised at both boundaries:

- **config** — `EpochMillis` (`settings.py`) runs `normalize_epoch_millis` on every
  `initial_history_*` field: milliseconds pass through, seconds are scaled up, `0`
  (no initial history) is left alone, and anything plausible as neither unit fails
  configuration validation so the connector never starts on an ambiguous date.
- **state** — `Intel471Stream._get_stored_initial_history()` (`streams/core/base.py`)
  backs the streams that pin the timestamp in OpenCTI state (Verity471 streams and
  the Titan indicators stream, so a later config change cannot desync it from the
  cursor). It repairs a value persisted in seconds by an earlier version, warns, and
  writes it back. It deliberately does **not** raise on an uninterpretable value:
  that would fail a scheduled run over state the connector cannot fix.

Both share `coerce_epoch_millis()` in `common.py`, which returns the value in
milliseconds or `None`. The seconds/milliseconds ranges it accepts
(2000-01-01 .. 2100-01-01) cannot overlap, so the unit is unambiguous.

## Adding or changing a stream

1. Subclass `TitanStream` or `Verity471Stream` in the matching `streams/<backend>/`
   package.
2. Set the class vars: `label` (unique internal id, used for cursor/queue names),
   `group_label` (drives config var names — multiple streams may share one, e.g.
   reports), `api_payload_objects_key`, `api_class_name`, `api_method_name`
   (the SDK class/method to call). Verity471 streams also set `size`.
3. Override `_get_api_kwargs` / `_get_cursor_value` / `_get_offsets` only if the
   defaults don't fit the endpoint.
4. Export it from the package `__init__.py` and register it in the matching
   `ClientWrapper.streams` tuple in `backend.py`.
5. If it introduces a new `group_label`, add the `interval_*` / `initial_history_*`
   fields in `settings.py` and mirror them in `config.yml.sample` and
   `docker-compose.yml`.

## Build, test, lint

- Tests: `pytest tests/` (run from this directory; `tests/conftest.py` puts `src/`
  on the path). Install with `pip install -r tests/test-requirements.txt`.
- Tests mock OpenCTI and the SDKs — they cover config validation and backend
  wiring, not live API calls.
- Formatting/linting is enforced repo-wide via pre-commit at the connectors repo
  root: **black**, **isort** (`--profile black --line-length 88`), and
  **flake8** (`--ignore=E,W`). Run `pre-commit run` before committing.

## Conventions

- Commits in this repo must be **GPG-signed** (enforced by a pre-commit hook).
- `__metadata__/` (manifest, config doc) is **generated by CI** — don't hand-edit
  it; it is rebuilt from `settings.py`.
- Keep `config.yml.sample`, `docker-compose.yml`, and `settings.py` in sync when
  changing configuration.
- Docker base image is `python:3.12-alpine`; entrypoint runs `src/main.py`.
