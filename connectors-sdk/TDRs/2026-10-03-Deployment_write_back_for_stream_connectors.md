# TDR: Deployment write-back for stream connectors (dissemination assurance)

<br>

## Overview

This document describes the `connectors_sdk.connectors.stream.deployment` module. It lets stream connectors report to
OpenCTI whether each indicator they disseminate is actually live on the security platform they feed, reconcile that
state periodically with the indicators read back from the vendor, and report detection hits.

OpenCTI stores the lifecycle on a `deployed-on` relationship between the indicator and a `Security Platform` entity
(`pending`, `deployed`, `active`, `failed`, `removed`, `expired`) and counts hits with a sighting of the indicator on the
platform (umbrella issue OpenCTI-Platform/opencti#18680, connectors issue OpenCTI-Platform/connectors#7852).

<br>

## Motivation

OpenCTI disseminates indicators to tens of stream connectors but cannot tell whether an indicator was accepted by the
EDR or SIEM, is still present after the vendor retention purge, or ever matched anything. Every stream connector would
otherwise reimplement the same GraphQL calls, feature detection, batching, rate-limit handling and reconciliation logic,
with subtle differences. The write-back must also never break the dissemination itself and must keep working with older
OpenCTI platforms (no-op).

<br>

## Proposed Solution

### Components

| Component | Role |
| --- | --- |
| `DeploymentConfig`, `HitsConfig`, `SecurityPlatformConfig` | Settings namespaces giving `DEPLOYMENT_REPORTING_ENABLED`, `DEPLOYMENT_RECONCILIATION_INTERVAL`, `HITS_REPORTING_ENABLED`, `SECURITY_PLATFORM_NAME`, `SECURITY_PLATFORM_TYPE`, `SECURITY_PLATFORM_ID`. Connectors subclass `SecurityPlatformConfig` to set their default name and type. |
| `DeploymentAssuranceOptions` | Resolved options, built from SDK settings (`from_settings`) or, for connectors still loading their configuration by hand, from `config.yml` and the environment (`from_legacy_config`). |
| `DeploymentReporter` | Feature detection, security platform resolution, single, batch and hit reports, listing of the deployments of the platform, coalescing queue for the stream path. |
| `DeploymentReconciler` + `DeploymentVendorAdapter` | Reconciliation runner (periodic daemon thread) and the vendor operations a connector implements: list, remove, push, and optionally collect hits. |
| `DeploymentAssurance` | Facade wiring the reporter and the reconciliation for a connector. |

### Key design decisions

| Decision | Rationale |
| --- | --- |
| Composable facade, not a stream connector base class | Stream connectors share no base class today (SDK-based and legacy ones coexist). A composable object is adopted with a few lines by any of them. |
| Feature detection by introspecting the `Mutation` type once (cached) | Older platforms do not expose the mutations: the reporter logs once at info level and becomes a no-op. A failed detection is retried after a delay instead of disabling the feature forever. |
| pycti helpers first, GraphQL fallback | The SDK must not require a pycti release shipping `report_indicator_deployment` and friends: they are called when present (`hasattr`), otherwise the documented GraphQL documents are sent through `helper.api.query`. |
| No reporting method raises | Errors are warnings, rejections of individual reports are returned and logged at info level (for example the indicator of a stream delete event no longer exists). Dissemination never breaks because of the write-back. |
| `Too many requests` retried with exponential backoff | The OpenCTI write-back API is rate limited per user. |
| Stream reports are queued, coalesced per indicator and flushed in batches (every 5 s or 500 reports) | The stream callback is not slowed down by a GraphQL call per event, and the batch mutation (max 500 reports per call) is used. Batches are sent in order, the latest report of an indicator wins. |
| Queued reports wait (at most 10 000) while the feature detection or the platform resolution is retried | A transient OpenCTI outage at start-up does not lose the outcome of the first pushes; reports are dropped only when the platform is known not to support the write-back. |
| Reconciliation lists `pending`, `deployed`, `active`, `failed` and `expired` deployments | `expired` is listed in addition to the contract statuses so that indicators still present on the vendor after their expiry are withdrawn and their removal confirmed. |
| Vendor read-back errors abort the run; a read-back limit disables absence-based decisions | A partial vendor listing would otherwise report live indicators as `removed`. |
| Vendor indicators carrying an OpenCTI id but no deployment are reported `active` | Backfills the indicators pushed before the write-back existed. |
| Hits are counted only when newer than the `last_hit_at` of the deployment | Overlapping time windows (and restarts) never double count; the platform ignores replays as well. |

### Usage

```python
class MyEdrSecurityPlatformConfig(SecurityPlatformConfig):
    name: str = Field(default="My EDR", min_length=2, description="...")
    type: str | None = Field(default="EDR", description="...")


class ConnectorSettings(BaseConnectorSettings):
    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    hits: HitsConfig = Field(default_factory=HitsConfig)  # only when hits are retrievable
    security_platform: MyEdrSecurityPlatformConfig = Field(
        default_factory=MyEdrSecurityPlatformConfig
    )


assurance = DeploymentAssurance.from_settings(helper, settings, adapter=MyEdrAdapter(client))
assurance.start()
# in the stream callback, after each vendor call:
assurance.report_pushed(stix_indicator, external_id=vendor_id)
assurance.report_push_failed(stix_indicator, error)
assurance.report_removed(stix_indicator)
```

<br>

## Advantages

- One implementation of the write-back contract for every stream connector, unit tested with 100% coverage.
- Safe by construction: no exception, no blocking call in the stream path, graceful degradation on older platforms.
- Connectors only implement vendor operations (list, remove, push, hits); the reconciliation algorithm is shared.
- Works for SDK-based and legacy connectors.

<br>

## Disadvantages

- Background threads (flush timer, reconciliation) run inside the connector process; they are daemon threads and the
  queue is flushed at exit.
- Queued reports can be lost if the process is killed abruptly; the next reconciliation restores the state.
- Value matching (for vendors that do not keep the OpenCTI id) can match an indicator sharing the same observable value.

<br>

## Alternatives Considered

1. **A `StreamConnector` base class owning the listen loop**

    **Rejected for now**. It would require migrating every stream connector at once. The facade can later be owned by
    such a base class without changing connector code.

2. **Synchronous single reports in the stream callback**

    **Rejected**. One GraphQL call per event doubles the processing time of large streams and does not use the batch
    mutation.

3. **Reporting through STIX bundles (deployed-on relationships in bundles)**

    **Rejected**. Bundles go through the worker queue, cannot express "only refresh `last_sync_at`" without creating
    history noise, and offer no feedback on rejected reports.

<br>

## References

- OpenCTI umbrella issue: https://github.com/OpenCTI-Platform/opencti/issues/18680
- Connectors issue: https://github.com/OpenCTI-Platform/connectors/issues/7852
- Related TDR: [Typing and validation of configurations with Pydantic Settings](./2025-10-01-Typing_and_validation_of_configurations_with_Pydantic_Settings.md)
