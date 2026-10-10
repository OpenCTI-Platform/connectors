# OpenCTI SigmaHQ Connector

| Status              | Date | Comment |
| ------------------- | ---- | ------- |
| Filigran Maintained | -    | -       |

## Introduction

The SigmaHQ connector enables automated ingestion of Sigma detection rules from the official Sigma main rule repository into OpenCTI as indicators. Sigma is a generic signature format for SIEM systems that allows detection engineers, threat hunters, and defensive security practitioners to collaborate on detection rules.

This connector imports more than 3000 detection rules across five distinct categories:

- Generic Detection Rules: Threat-agnostic rules designed to detect behaviors or implementations of techniques and procedures that may be used by potential threat actors
- Threat Hunting Rules: Broader-scope rules providing analysts with starting points to hunt for suspicious or malicious activity
- Emerging Threat Rules: Time-sensitive rules covering specific threats such as APT campaigns, zero-day vulnerability exploitation, and specific malware families
- Compliance Rules: Rules that identify compliance violations based on established security frameworks including CIS Controls, NIST, ISO 27001, and others
- Placeholder Rules: Template rules that receive their final meaning during conversion or implementation

By importing these rules as indicators in OpenCTI, organizations can enrich their threat intelligence platform with community-maintained detection logic, enhance their detection capabilities, and correlate Sigma rules with other threat intelligence entities such as TTPs, malware, and threat actors.

## Behavior

Each Sigma rule becomes an `Indicator` (`pattern_type: sigma`, the rule YAML as pattern) with:

- the rule metadata used by the Threat-Informed Defense Matrix, set only when the rule defines it:
  - `x_opencti_rule_status`: the Sigma `status` (`stable`, `test`, `experimental`, `deprecated`, `unsupported`),
  - `x_opencti_rule_level`: the Sigma `level` (`informational`, `low`, `medium`, `high`, `critical`),
  - `x_opencti_rule_logsource`: the Sigma `logsource` keys present in the rule (`category`, `product`, `service`), lowercased;
- one `indicates` relationship per ATT&CK technique or sub-technique tag (`attack.t1059`, `attack.t1059.001`), targeting the Attack Pattern whose id is derived from the MITRE id. Tactic tags (`attack.execution`) create no relationship;
- one `indicates` relationship per CVE tag (`cve.2024-1234`), targeting the Vulnerability.

Techniques are resolved against the platform once per rule package: a technique OpenCTI already holds (for example from the MITRE ATT&CK connector) is referenced under its current name and keeps its own author and markings, so the import never renames it. A technique OpenCTI does not hold yet is created under its MITRE id, with the SigmaHQ author and the configured TLP marking.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.9.5 (the rule metadata properties are stored from the OpenCTI release shipping the Threat-Informed Defense Matrix; older platforms ignore them)
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version (the connector pins `pycti==7.261008.0`)
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector. For more information regarding these variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

