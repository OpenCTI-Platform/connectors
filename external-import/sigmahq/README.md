# OpenCTI SigmaHQ Connector

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2026-01-05 | -       |

## Introduction

The SigmaHQ connector enables automated ingestion of Sigma detection rules from the official Sigma main rule repository into OpenCTI as indicators. Sigma is a generic signature format for SIEM systems that allows detection engineers, threat hunters, and defensive security practitioners to collaborate on detection rules.

This connector imports more than 3000 detection rules across five distinct categories:

- Generic Detection Rules: Threat-agnostic rules designed to detect behaviors or implementations of techniques and procedures that may be used by potential threat actors
- Threat Hunting Rules: Broader-scope rules providing analysts with starting points to hunt for suspicious or malicious activity
- Emerging Threat Rules: Time-sensitive rules covering specific threats such as APT campaigns, zero-day vulnerability exploitation, and specific malware families
- Compliance Rules: Rules that identify compliance violations based on established security frameworks including CIS Controls, NIST, ISO 27001, and others
- Placeholder Rules: Template rules that receive their final meaning during conversion or implementation

By importing these rules as indicators in OpenCTI, organizations can enrich their threat intelligence platform with community-maintained detection logic, enhance their detection capabilities, and correlate Sigma rules with other threat intelligence entities such as TTPs, malware, and threat actors.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.9.5
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding these variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/).

