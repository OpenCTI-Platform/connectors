# Connectors SDK

The `connectors-sdk` project is a toolkit designed to simplify the development of connectors for various integrations on the OpenCTI platform. It provides models, exceptions, and utilities to streamline the process of building robust connectors.

## Quick Start

This section demonstrates how to quickly get started with the `connectors-sdk`. More complex examples and usage patterns can be found later in the documentation.

### Installation

To get started with the `connectors-sdk`, install it directly from the GitHub repository.  
Replace `<branch_or_tag>` with the branch or tag you wish to use. If you omit it, the main branch will be used.

``` bash
python -m pip install "connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@<branch_or_tag>#subdirectory=connectors-sdk"
```

### Using Models

The SDK provides predefined models to represent data structures commonly used in connectors. These models help ensure consistency and reduce boilerplate code.  
You can use the models in your connector code as follows:

```python
from connectors_sdk.models import (
    IPV4Address,
    Organization,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)

# Create an IOC provider (Author)
author = OrganizationAuthor(name="Example Author")
# Create knowledge and activity objects and link them together
ip = IPV4Address(value="127.0.0.1", author=author, markings=[TLPMarking(level="amber+strict")])
org = Organization(name="Example Corp", author=author)
rel = Relationship(type="related-to", source=ip, target=org)
# Convert to OCTI extended STIX2 objects
for obj in [author, ip, org, rel]:
    stix_object = obj.to_stix2_object()
    print(stix_object)
```

### Using Exceptions

The SDK includes custom exceptions to handle errors gracefully. Use these exceptions to manage edge cases and improve the reliability of your connector.

See [docs/HOW-TO-Handle-errors-in-connectors.md](docs/HOW-TO-Handle-errors-in-connectors.md) for more details.

### Reporting deployment status from stream connectors

Stream connectors can report to OpenCTI whether each indicator they push is actually live on the security platform
(dissemination assurance). OpenCTI stores the lifecycle on a `deployed-on` relationship between the indicator and a
`Security Platform` entity (`deployed`, `active`, `failed`, `removed`...) and counts detection hits as a sighting.

1. Add the settings namespaces (they give the `DEPLOYMENT_*`, `HITS_*` and `SECURITY_PLATFORM_*` variables):

```python
from connectors_sdk import (
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
    DeploymentConfig,
    HitsConfig,
    SecurityPlatformConfig,
)
from pydantic import Field


class StreamConnectorConfig(BaseStreamConnectorConfig):
    name: str = Field(default="My EDR", description="The name of the connector.")


class MyEdrSecurityPlatformConfig(SecurityPlatformConfig):
    name: str = Field(default="My EDR", min_length=2, description="Name of the Security Platform entity.")
    type: str | None = Field(default="EDR", description="Type of the Security Platform entity.")


class ConnectorSettings(BaseConnectorSettings):
    connector: StreamConnectorConfig = Field(default_factory=StreamConnectorConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    hits: HitsConfig = Field(default_factory=HitsConfig)  # only when the vendor exposes detections
    security_platform: MyEdrSecurityPlatformConfig = Field(default_factory=MyEdrSecurityPlatformConfig)
```

| Variable | Default | Description |
| --- | --- | --- |
| `DEPLOYMENT_REPORTING_ENABLED` | `true` | Report the deployment status of every pushed indicator. |
| `DEPLOYMENT_RECONCILIATION_INTERVAL` | `60` | Minutes between two reconciliations with the vendor (`0` disables). |
| `HITS_REPORTING_ENABLED` | `true` | Report detection hits (connectors able to read detections only). |
| `SECURITY_PLATFORM_NAME` | per connector | Security Platform entity, created if missing (upsert by name). |
| `SECURITY_PLATFORM_TYPE` | per connector | `EDR`, `XDR`, `SIEM`, `SOAR`, `NDR`, `ISPM`... |
| `SECURITY_PLATFORM_ID` | | Bind an existing Security Platform entity instead of resolving it by name. |

2. Implement a `DeploymentVendorAdapter` when the vendor API can read the pushed indicators back (`list_vendor_indicators`,
   `remove_vendor_indicator`, `push_indicator`, `collect_hits` when detections are available, and `is_complete` when the
   vendor holds one item per observable, so that an indicator only partly on the vendor is pushed again instead of being
   confirmed `active`). A vendor keeping one item per observable value without the OpenCTI id overrides
   `expected_values` instead: every item holding one of those values is matched (and removed on withdrawal), and the
   indicator is pushed again while one of them is missing. Value matching, for the vendor items and the hits alike, then
   only uses those values (an empty set when the connector pushes none of the pattern values), so an item holding a
   pattern value the connector does not push is never withdrawn. An item another live deployment shares is never
   withdrawn. A `pending` deployment (analyst retry) is pushed again when the read-back finds it absent or only partly
   on the vendor; one the vendor holds in full is confirmed `active` without a new push, which would duplicate it on
   create-only vendor APIs.
   An adapter keeping a local snapshot of what it pushes (uploaded as a whole) overrides `forget_indicator`, called
   for a deployment withdrawn while the vendor no longer holds it, so that the next upload does not restore it.
   When the vendor API cannot read the indicators back, a `DeploymentPushAdapter` (`push_indicator`, optional
   `collect_hits`) still gets the periodic re-push of `pending` deployments and the hit reporting; presence, absence
   and withdrawal need the read-back.
   When the listing cannot guarantee completeness (offset pages of a collection without a documented
   order), set `confirms_absence = True` and implement `confirm_absent`: an indicator missing from the listing is then
   only reported `removed` once a direct vendor lookup confirms it (at most `max_absence_checks` lookups per run, 100 by
   default; the next ones wait for the next run).

3. Wire the facade and report after each vendor call (reports are queued and sent in batches, never raise):

```python
from connectors_sdk import DeploymentAssurance

assurance = DeploymentAssurance.from_settings(helper, settings, adapter=MyEdrAdapter(client))
assurance.start()  # feature detection, platform resolution, periodic reconciliation

assurance.report_pushed(stix_indicator, external_id=vendor_id)
assurance.report_push_failed(stix_indicator, error)
assurance.report_removed(stix_indicator)
```

OpenCTI shows the failure reason in the Deployments tabs: report one short sentence naming the platform and the cause,
never a vendor response. `deployment_failure_reason(platform, action, status_code)` writes it with the wording every
connector shares (`deployment_failure_reason("Google SecOps", "entity ingestion", 403)` gives
`"Google SecOps refused the entity ingestion: permission denied"`; for a success status whose response cannot be read,
`"... returned an unexpected response to the ..."`; without a status, `"... could not be reached for the ..."`); log the
vendor response with the indicator id instead. The re-push of the reconciliation reports the message
of the exception `push_indicator` raises, so adapters raise the same sentence.

On OpenCTI platforms without the write-back API, the module logs once and becomes a no-op. See the
[TDR](TDRs/2026-10-03-Deployment_write_back_for_stream_connectors.md) for the design and the reconciliation algorithm.

### Documentation

You can generate full Read the Docs-style documentation using Sphinx. This will provide comprehensive information about the SDK's features, usage, and API.  
See [How to generate documentation](docs/HOW-TO_Generate_sphinx_doc.md) for more details on how to set up and use Sphinx for this project.

## Using the Connectors SDK in Your Connector

### Dependency Management

To use the `connectors-sdk`, add it as a dependency in your project.

You can add it to your `requirements.txt` or `pyproject.toml` file:

```text
    connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@<octi_version>#subdirectory=connectors-sdk
```

#### Developing with the SDK Locally

To develop both the SDK and your connector at the same time, you can install the SDK in editable mode. This allows you to make changes to the SDK and see them reflected in your connector code without reinstalling.

Use a `pyproject.toml` file and install your connector using `pip install -e .`:

```toml
[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
# Poetry allows relative path dependencies.

[project]
name = "connector-using-sdk"
dynamic = ["version"]
description = "demo"
requires-python = ">=3.11, <3.13"

[tool.poetry]
version = "0.0.0"
packages = [{include = "connector_using_sdk"}]

[tool.poetry.dependencies]
connectors-sdk = {path = "../../connectors-sdk/", develop = true}
# NOTE: The 'develop' option is ignored by pip, but the relative path will work.
# For concurrent local development, you may use:
# pip install -e . && pip install -e ../../connectors-sdk/
# or use Poetry: pip install poetry && poetry install
```

### Unit Testing

When using the `connectors-sdk`, it is recommended to write unit tests for your code. Since the project is still under development, automated testing ensures stability and compatibility with future updates.

## How to Contribute

Contributions are welcome! To get started, refer to:

- [Contributing guidelines](docs/CONTRIBUTING.md)
- [TDRs](TDRs) to understand the technical decisions made in this project
- Documentation and HOW TO guides in the `docs` directory

These resources will help you understand the contribution process and coding standards.

### TO DO

- Implement all OpenCTI models.
- Implement factories to convert OpenCTI bundle payloads (e.g., OpenCTI-extended STIX2) to connectors-sdk models.
