# MITRE Datasets Connector

This connector collects data from the MITRE datasets in order to pre-populate your OpenCTI instance with information like the following:
* tool
* malware
* identity
* campaign
* relationship
* intrusion-set
* attack-pattern
* course-of-action
* marking-definition
* x-mitre-matrix
* x-mitre-tactic
* x-mitre-collection
* x-mitre-data-source
* x-mitre-data-component

## Configuration

The connector can be configured with the following variables:

| Env var | Default | Description |
| - | - | - |
| `MITRE_INTERVAL` | 7 | Number of the days between each MITRE datasets collection. |
| `MITRE_ENTERPRISE_FILE_URL` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json | Resource URL |
| `MITRE_MOBILE_ATTACK_FILE_URL` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json | Resource URL |
| `MITRE_ICS_ATTACK_FILE_URL` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json | Resource URL |
| `MITRE_CAPEC_FILE_URL` | https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json | Resource URL |

**Note:** in case you do not want to collect a specific data source, just pass `False` on the correspondent config option, e.g., `MITRE_CAPEC_FILE_URL=False`.

## Scope

In order to properly configure your connector, you should review the setting `CONNECTOR_SCOPE`, mainly the `marking-definition` and `external-reference-as-report` because these data may not be required by you.

The scope that you probably want as your configuration is the following:
`tool,report,malware,identity,campaign,intrusion-set,attack-pattern,course-of-action,x-mitre-data-source,x-mitre-data-component,x-mitre-matrix,x-mitre-tactic,x-mitre-collection`