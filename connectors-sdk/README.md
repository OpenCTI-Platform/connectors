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

From your connector directory, install its requirements, then replace the SDK they pulled with your local checkout:

```bash
uv venv && source .venv/bin/activate
uv pip install -r src/requirements.txt
uv pip install -e ../../connectors-sdk
```

`pip install` works the same way if you don't use uv.

#### Building the SDK

The SDK is built with the `uv_build` backend (see the [TDR](TDRs/2026-11-24-uv_build_backend.md)). From the `connectors-sdk` directory:

```bash
uv build
```

The sdist and wheel are written to `dist/`. Any PEP 517 frontend (`python -m build`, `pip wheel`) works as well.

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
