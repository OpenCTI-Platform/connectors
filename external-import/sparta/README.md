# Aerospace SPARTA Dataset Connector

This connector collects data from the SPARTA dataset in order to pre-populate your OpenCTI instance with information like the following:
* attack-pattern
* course-of-action
* indicator


## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__)

## Scope

In order to properly configure your connector, you should review the setting `CONNECTOR_SCOPE`, mainly the `marking-definition` and `external-reference-as-report` because these data may not be required by you.

The scope that you probably want as your configuration is the following:
`attack-pattern,course-of-action,indicator`