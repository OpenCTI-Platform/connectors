# OpenCTI Malpedia Connector

![Malpedia Logo](https://malpedia.caad.fkie.fraunhofer.de/static/malpediasite/logo.png)

this connector imports knowledge from the [Malpedia Library](https://malpedia.caad.fkie.fraunhofer.de/).

The connector adds data for the following OpenCTI observable/indicator types:

* yara
* file-sha256 (Sample)

The connectors adds the following Entities:

* Malware
* Intrusion-Set
* External References

## Installation

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-malpedia:rolling` (replace `rolling` with the latest OpenCTI release version for production usage).

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml`file of OpenCTI.

## Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter                      | config.yml           | Docker environment variable      | Default    | Mandatory | Description                                                                            |
|--------------------------------|----------------------|----------------------------------|------------|-----------|----------------------------------------------------------------------------------------|
| Connector ID                   | id                   | `CONNECTOR_ID`                   | /          | Yes       | A unique `UUIDv4` identifier for this connector instance.                              |
| Connector Name                 | name                 | `CONNECTOR_NAME`                 | `Malpedia` | Yes       | Name of the connector.                                                                 |
| Connector Scope                | scope                | `CONNECTOR_SCOPE`                | `malpedia` | Yes       | Must be `malpedia`, not used in this connector.                                        |
| Connector Log Level            | log_level            | `CONNECTOR_LOG_LEVEL`            | /          | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| Connector Expose Metrics       | expose_metrics       | `CONNECTOR_EXPOSE_METRICS`       | `false`    | Yes       | If `True` use metrics.                                                                 |

Below are the parameters you'll need to set for Malpedia connector:

| Parameter                      | config.yml            | Docker environment variable      | Default | Mandatory | Description                                                             |
|--------------------------------|-----------------------|----------------------------------|---------|-----------|-------------------------------------------------------------------------|
| Malpedia Auth Key              | auth_key              | `MALPEDIA_AUTH_KEY`              | /       | Yes       | API authentication key                                                  |
| Malpedia Interval Sec          | internal_sec          | `MALPEDIA_INTERVAL_SEC`          | `86400` | Yes       | Interval in seconds before a new import is considered                   |
| Malpedia Import Intrusion Sets | import_intrusion_sets | `MALPEDIA_IMPORT_INTRUSION_SETS` | `true`  | Yes       | Choose if you want to import Intrusion-Sets from Malpedia               |
| Malpedia Import Yara           | import_yara           | `MALPEDIA_IMPORT_YARA`           | `true`  | Yes       | Choose if you want to import Yara rules from Malpedia                   |
| Malpedia Create Indicators     | create_indicators     | `MALPEDIA_CREATE_INDICATORS`     | `true`  | Yes       | Choose if you want to create Indicators Sample (File) from Malpedia     |
| Malpedia Create Observables    | create_observables    | `MALPEDIA_CREATE_OBSERVABLES`    | `true`  | Yes       | Choose if you want to create Observables Sample (File) from Malpedia    |


## Notes

Information The connector states takes 2 items into account to get started:
- The environment variable "config_interval_sec" is set to 86400 seconds or 24 hours by default.
- The version of Malpedia

So, apart from the first run, if the 24 hour interval is respected and there is a new version of Malpedia, the connector will be restarted.

---
The API authentication key. Can be retrieved with a valid account from:

https://malpedia.caad.fkie.fraunhofer.de/settings

If you are authenticated, then all entities created by the connector will be in TLP:AMBER, except for the Yara rules which are based on the TLP defined directly by Malpedia.

If you are not authenticated, by leaving this variable (auth_key) undefined or only public in the form of an empty string (""), all entities created by the connector will be in TLP:WHITE. This connector can therefore be used without an account.

If you choose to set environment variables such as import_intrusion_sets, import_yara, create_indicators, create_observables to false, the connector will simply skip the bundle creation steps for the selected category.

---
**Caution**

You should only enable update_existing_data for connectors that you consider a knowledge priority for specific entities. Entities created by other connectors might be overwritten.
