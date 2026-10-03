# TDR: Internal hunt connector base class

<br>

## Overview

This document describes `InternalHuntConnector`, the base class of the new connector type `INTERNAL_HUNT`, and
`BaseInternalHuntConnectorConfig`, its settings model. A hunt connector executes the hunts dispatched by OpenCTI
(one message per hunt run) against exactly one telemetry platform (a SIEM, an EDR, a data lake) or against internet
scanning APIs, sends the resulting knowledge and reports the run outcome.

The message format, the run report and the result bundle are defined by the OpenCTI hunt contract (OpenCTI-Platform/opencti#18671).

<br>

## Motivation

Every hunt connector repeats the same pipeline:

1. register the hunt platform of the connector (`register_hunt_platform`);
2. parse the hunt run message and pick the logic to execute: the native query override of the platform, or the
   canonical Sigma rule translated with pySigma;
3. honour the preview mode (translate only, never execute);
4. execute the query within the run limits (`timeout_seconds`, `max_results`);
5. suppress the benign events of the hunt;
6. map the results to STIX (sightings of the techniques and indicators on the Security Platform identity,
   one observed-data per observation count with IOC observables only), with deterministic ids scoped to the hunt
   run for sightings and observed-data, markings and author inherited from the hunt;
7. send the bundle within the run work;
8. report the run: hits, distinct entities, redacted evidence (SHA-256 hashes and truncated previews), translated
   query, cost and result ids, or the error of a failed run.

Only the platform translation backend and the query execution are platform specific. Without a base class, privacy
guarantees (no raw telemetry in the platform, internal IP addresses and domains never turned into observables) and
the contract would be re-implemented, and could drift, in each connector.

<br>

## Proposed Solution

### Settings

`BaseInternalHuntConnectorConfig` (`connectors_sdk.settings.base_settings`) hardcodes `type = "INTERNAL_HUNT"` and adds:

| Setting | Purpose |
| --- | --- |
| `scope` | Exactly one hunt platform slug (`splunk`, `microsoft-sentinel`, `elastic-security`, `crowdstrike-logscale`, `google-secops`, `opensearch`, `clickhouse`, `s3-ocsf`, `internet`). |
| `security_platform_name` / `security_platform_type` | Security Platform identity the hunts run against (required, except for `internet`). |
| `max_concurrent_runs` | Connector-side concurrency limit, sent at registration. |
| `observable_types` | Observable types the connector may create; IOC types by default, widened explicitly. |
| `max_observables` | Cap of observables per run. |

### Base class

```python
class SplunkHuntConnector(InternalHuntConnector):
    languages = ("spl",)

    def sigma_backend(self, pipeline: str | None) -> Backend:
        return SplunkBackend(build_pipeline(pipeline or "splunk_windows", PIPELINES))

    def execute(self, native_query, time_window, limits) -> HuntResult:
        return self.client.search(native_query.query, time_window, limits)
```

| Hook | Default |
| --- | --- |
| `sigma_backend(pipeline)` | Abstract: the pySigma backend and processing pipeline of the platform. |
| `execute(native_query, time_window, limits)` | Abstract: the query execution. |
| `translate(sigma_rule, pipeline)` | pySigma conversion with `sigma_backend`, detection field names kept for evidence ranking. |
| `combine_queries(queries)` | Single query, or joined with `query_join` when a Sigma document yields several. |
| `to_stix(request, result)` | Telemetry mapping (sightings + observed-data); outside-in connectors override it. |
| `on_timeout(native_query)` | No-op; cancels the platform job when overridden. |
| `post_init()` | No-op; creates the platform client when overridden. |

`execute` runs in a daemon thread joined with `limits.timeout_seconds`, so a hung platform call never blocks the
connector; results beyond `limits.max_results` are dropped and the total hit count is kept.

The run is reported as `completed` or `failed` by the SDK, then the error of a failed run is raised again so that
OpenCTI marks the work in error.

### Platform clients

`HuntApiClient` extends `BaseClientApi` for platform APIs: `hunt_request()` checks a `RunDeadline` built from
`limits.timeout_seconds`, bounds the request timeout with the time left, and turns HTTP and network failures into
`HuntExecutionError` / `HuntTimeoutError` whose message carries the (size-capped) platform error, so that the run
report says why the platform refused the query. `cleanup_request()` cancels or deletes platform jobs (search jobs,
async queries) without ever masking the run outcome.

### pycti compatibility

`INTERNAL_HUNT`, `listen_hunt`, `register_hunt_platform` and `report_hunt_run` ship in the pycti release that comes
with OpenCTI hunts. `start()` checks them before creating the helper and fails fast with a clear message
(`HuntUnsupportedPyctiError`) when the installed pycti is older. Tests never need them: the helper is mocked.

### pySigma as an optional extra

pySigma is declared as the `hunt` extra of the SDK (`connectors-sdk[hunt]`) and imported lazily by the translation
helpers. Hunt connectors list `pysigma` and their backend package in their own requirements, because the repository
CI and the image builds rewrite the `connectors-sdk @ git+...` requirement line and would drop an extra.

<br>

## Advantages

- **One contract implementation**: message parsing, preview, limits, evidence redaction, STIX mapping and reporting
  are written and tested once (100% coverage), so connectors only implement translation and execution.
- **Privacy by default**: raw telemetry never leaves the connector; only hashed and truncated evidence, counts and IOC
  observables reach OpenCTI.
- **Deterministic knowledge**: observables keep their standard ids; the ids of sightings and observed-data derive
  from the hunt run too, so a retry of a run upserts its own objects and two runs never share one.
- **Light SDK**: connectors that do not hunt do not install pySigma.

<br>

## Disadvantages

- **Thread-based timeout**: a Python thread cannot be killed. A timed out `execute` keeps running until its own HTTP
  timeouts expire; connectors bound their calls with `HuntApiClient.hunt_request()` and cancel platform jobs in
  `on_timeout`.
- **Benign suppression on returned events**: when results are truncated, suppressed events are subtracted from the
  platform total, which is an approximation of the benign-free hit count.

<br>

## Alternatives Considered

1. **Translation in the OpenCTI platform**: rejected, pySigma is a Python library and backends evolve with the
   platforms; translating where the query runs keeps the platform free of per-SIEM code and lets connectors pin
   their backend version.
2. **pySigma as a hard dependency of the SDK**: rejected, it adds pySigma and its dependencies to every connector.
3. **`connectors-sdk[hunt]` in connector requirements**: rejected, the CI and image builds rewrite the SDK
   requirement line and would drop the extra.

<br>

## References

- [pySigma](https://github.com/SigmaHQ/pySigma)
- OpenCTI hunts umbrella issue: https://github.com/OpenCTI-Platform/opencti/issues/18671
- Related TDR: [Typing and validation of configurations with Pydantic Settings](https://github.com/OpenCTI-Platform/connectors/blob/master/connectors-sdk/TDRs/2025-10-01-Typing_and_validation_of_configurations_with_Pydantic_Settings.md)
