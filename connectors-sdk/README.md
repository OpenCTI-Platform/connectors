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

### Reading provenance summaries

OpenCTI versions that ship provenance, corroboration and freshness ([OpenCTI-Platform/opencti#18676](https://github.com/OpenCTI-Platform/opencti/issues/18676))
record which sources asserted each Stix Core Object (SDO and SCO), Stix Core Relationship and sighting, and when.
They export a summary of these assertions in the `opencti-provenance` STIX property extension
(`extension-definition--283daa2f-7739-5345-a110-19d73676f670`, available as `STIX_EXT_OCTI_PROVENANCE`) when the provenance of an object is known.
The summary holds counts, dates and flags only: it never contains source names nor user emails.
Objects exported by OpenCTI versions without provenance support carry no such extension, and `from_stix` returns `None` for them.

`ProvenanceSummary.from_stix` reads it from a STIX object received from OpenCTI, either a plain dict (stream events, bundles) or a `stix2` library object:

```python
import json

from connectors_sdk.models import ProvenanceSummary, ProvenanceSummaryError
from connectors_sdk.models.enums import ProvenanceSourceKind


def process_message(self, msg) -> None:
    stix_object = json.loads(msg.data)["data"]
    try:
        summary = ProvenanceSummary.from_stix(stix_object)
    except ProvenanceSummaryError as err:
        self.helper.connector_logger.warning("Malformed provenance", meta={"error": str(err)})
        return
    if summary is None:
        return  # OpenCTI exported no provenance for this object
    if summary.single_sourced or summary.freshness_stale:
        return  # forward only corroborated and fresh knowledge
    connector_sources = summary.sources_by_kind.get(ProvenanceSourceKind.CONNECTOR, 0)
```

| Field                 | Type                                | Meaning                                                            |
|-----------------------|-------------------------------------|--------------------------------------------------------------------|
| `corroboration_count` | `int` (>= 0)                        | Number of distinct sources asserting the fact                      |
| `assertions_count`    | `int` (>= 0)                        | Sum of the assertion counts of all sources                         |
| `first_asserted`      | `datetime` or `None`                | When a source asserted the fact for the first time                 |
| `last_asserted`       | `datetime` or `None`                | When a source asserted the fact for the last time                  |
| `single_sourced`      | `bool`                              | Exactly one source asserts the fact                                |
| `has_conflicts`       | `bool`                              | Sources proposed conflicting values for some attributes            |
| `conflicting_fields`  | `tuple[str, ...]`                   | Names of the attributes with conflicting values                    |
| `freshness_stale`     | `bool`                              | A knowledge freshness rule flagged the fact as stale               |
| `sources_by_kind`     | read-only mapping `ProvenanceSourceKind` -> `int` | Distinct sources per kind: `connector`, `feed`, `author`, `user`, `inference`, `emulation` |

- `from_stix` returns `None` when the object carries no provenance extension. It raises `ProvenanceSummaryError` (a `ValueError`) when the extension is malformed, with the pydantic `ValidationError` as cause when the content fails validation.
- The summary is read-only: the model is frozen and its collections are immutable. It is not a write model: it has no `to_stix2_object` method and no write model accepts it. Connectors never send provenance: OpenCTI computes it from who writes the data.
- Forward compatibility: payload fields unknown to the SDK version are ignored, and unknown source kinds are kept in `sources_by_kind` (with a `UserWarning`).

### Using Exceptions

The SDK includes custom exceptions to handle errors gracefully. Use these exceptions to manage edge cases and improve the reliability of your connector.

See [docs/HOW-TO-Handle-errors-in-connectors.md](docs/HOW-TO-Handle-errors-in-connectors.md) for more details.

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
