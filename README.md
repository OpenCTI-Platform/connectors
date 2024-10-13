# OpenCTI connectors

[![Website](https://img.shields.io/badge/website-opencti.io-blue.svg)](https://opencti.io)
[![CircleCI](https://circleci.com/gh/OpenCTI-Platform/connectors.svg?style=shield)](https://circleci.com/gh/OpenCTI-Platform/connectors/tree/master)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)

The following repository is used to store the OpenCTI connectors for the platform integration with other tools and applications. To know how to enable connectors on OpenCTI, please read the [dedicated documentation](https://docs.opencti.io/latest/deployment/connectors).

## Connectors list and statuses

This repository is used to host connectors that are supported by the core development team of OpenCTI. Nevertheless, the community is also developping a lot of connectors, third-parties modules directly linked to OpenCTI. You can find the list of all available connectors and plugins in the [OpenCTI ecosystem dedicated space](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76).

## Contributing

If you want to help use improve or develop new connector, please check out the **[development documentation for new connectors](https://docs.opencti.io/latest/development/connectors)**. If you want to make your connector available to the community, **please create a Pull Request on this repository**, then we will integrate it to the CI and in the [OpenCTI ecosystem](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76).

Any connector must be fully validated through pylint. Example of commands:

To full check a connector
> pylint external-import/ransomwarelive/src/*.py

To apply specific rules on everything
> pylint **/*.py --disable=all --enable=no_generated_id_stix,no-value-for-parameter

## License

**Unless specified otherwise**, connectors are released under the [Apache 2.0](https://github.com/OpenCTI-Platform/connectors/blob/master/LICENSE). If a connector is released by its author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## About

OpenCTI is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenCTI-Platform/opencti/raw/master/.github/img/logo_filigran.png" width="300" /></a>