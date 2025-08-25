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


## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__)

**Note:** in case you do not want to collect a specific data source, just pass `False` on the correspondent config option, e.g., `MITRE_CAPEC_FILE_URL=False`.

## Scope

In order to properly configure your connector, you should review the setting `CONNECTOR_SCOPE`, mainly the `marking-definition` and `external-reference-as-report` because these data may not be required by you.

The scope that you probably want as your configuration is the following:
`tool,report,malware,identity,campaign,intrusion-set,attack-pattern,course-of-action,x-mitre-data-source,x-mitre-data-component,x-mitre-matrix,x-mitre-tactic,x-mitre-collection`