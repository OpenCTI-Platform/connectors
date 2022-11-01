# OpenCTI SOC Prime Connector

The OpenCTI SOC Prime connector can be used to import Sigma rules from the SOC Prime Platform.
The connector leverages the SOC Prime Continuous Content Management API to get the rules.


## Installation

The OpenCTI SOC Prime connector is a standalone Python process that requires access to the OpenCTI platform, RabbitMQ and API Key to the SOC Prime CCM to be able to pull Sigma rules. RabbitMQ credentials and connection parameters
are provided by the OpenCTI API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-socprime:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

The connector can be configured with the following variables:

| Config Parameter                 | Docker env var                              | Default                      | Description                                                                                             |
| -------------------------------- | ------------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| `api_key`                        | `SOCPRIME_API_KEY`                          | `ChangeMe`                   | The SOC Prime CCM API Key                                                                               |
| `content_list_name`              | `SOCPRIME_CONTENT_LIST_NAME`                | `ChangeMe`                   | The name of the SOC Prime CCM Content List from which Sigma rules will be obtained                      |
| `interval_sec`                   | `SOCPRIME_INTERVAL_SEC`                     | `3600`                       | The import interval in seconds                                                                          |
| `siem_type`                      | `SOCPRIME_SIEM_TYPE`                        |                              | (Optional) Security platform formats for which extetrnal links will be generated. In case of using `config.yml`, it should be a list; and in case of Docker env var, it should be a string with comma-separeted values. See possibles values below. |

The list of possible values for the `siem_type` (`SOCPRIME_SIEM_TYPE`) variable:
* `ala-rule` — Microsoft Sentinel Rule
* `ala` — Microsoft Sentinel Query
* `elasticsearch` — Elasticsearch Query
* `xpack-watcher` — Elasticsearch Watcher
* `elasticsearch-rule` — Elasticsearch Detection Rule
* `kibana` — Kibana Saved Search
* `elastalert` — Elasticsearch ElastAlert
* `qradar` — Qradar Query
* `humio` — Humio Query
* `humio-alert` — Humio Alert
* `splunk` — Splunk Query
* `splunk_alert` — Splunk Alert
* `sumologic` — Sumo Logic Query
* `sumologic-cse` — Sumo Logic CSE Query
* `sumologic-cse-rule` — Sumo Logic CSE Rule
* `arcsight-esm` — ArcSight Rule
* `arcsight-keyword` — ArcSight Query
* `logpoint` — LogPoint Query
* `grep` — Regex Grep Query
* `powershell` — PowerShell Query
* `graylog` — Graylog Query
* `kafka` — Apache Kafka KSQL Query
* `rsa_netwitness` — RSA NetWitness Query
* `carbonblack` — Carbon Black Query
* `open-ioc` — FireEye OpenIOC
* `fireeye-helix` — FireEye Helix Query
* `chronicle` — Chronicle Security Rule
* `securonix` — Securonix Query
* `s1-events` — SentinelOne Events Query
* `s1-process` — SentinelOne Process State Query
* `mdatp` — Microsoft Defender for Endpoint Query
* `qualys` — Qualys IOC Query
* `sysmon` — Sysmon Rule
* `crowdstrike` — CrowdStrike Query
* `limacharlie` — LimaCharlie Rule
* `devo` — Devo Query
