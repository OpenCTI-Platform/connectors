# Shared Directory

The `shared/` directory contains reusable components, tools, and configurations that are shared across different parts of the `connectors` mono repo. 
This directory is structured to provide common utilities that can be leveraged by multiple connectors to maintain consistency and avoid duplication.

## Structure

- **pylint_plugins/**: This subdirectory contains custom `pylint` plugins that are used to enforce code standards across the repository.
    - **check_stix_plugin/**: A custom `pylint` plugin designed to check for proper STIX2 object instantiation, ensuring that objects are instantiated with deterministic IDs. Refer to the [dedicated README](./pylint_plugins/check_stix_plugin/README.md) for details on its usage.
  - **tests/**: Contains test suites that validate the functionality of the pylint_plugins utilities.
- **tools/**
