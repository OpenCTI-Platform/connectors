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

| Parameter `OpenCTI` | config.yml    | Docker environment variable | Mandatory | Description                                          |
|---------------------|---------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | `url`         | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | `token`       | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter `Connector` | config.yml        | Docker environment variable | Default    | Mandatory | Description                                                                                      |
|-----------------------|-------------------|-----------------------------|------------|-----------|--------------------------------------------------------------------------------------------------|
| ID                    | `id`              | `CONNECTOR_ID`              | /          | Yes       | A unique `UUIDv4` identifier for this connector instance.                                        |
| Name                  | `name`            | `CONNECTOR_NAME`            | `Malpedia` | Yes       | Name of the connector.                                                                           |
| Scope                 | `scope`           | `CONNECTOR_SCOPE`           | `malpedia` | Yes       | Must be `malpedia`, not used in this connector.                                                  |
| Log Level             | `log_level`       | `CONNECTOR_LOG_LEVEL`       | /          | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.           |
| Expose Metrics        | `expose_metrics`  | `CONNECTOR_EXPOSE_METRICS`  | `False`    | Yes       | If `True` use metrics.                                                                           |
| Duration Period       | `duration_period` | `CONNECTOR_DURATION_PERIOD` | /          | No        | Determines the time interval between each launch of the connector (current use `interval_sec`).  |
| Queue Threshold       | `queue_threshold` | `CONNECTOR_QUEUE_THRESHOLD` | `500`      | No        | Used to determine the limit (RabbitMQ) in MB at which the connector must go into buffering mode. |

Below are the parameters you'll need to set for Malpedia connector:

| Parameter `Malpedia`  | config.yml              | Docker environment variable      | Default     | Mandatory | Description                                                                                |
|-----------------------|-------------------------|----------------------------------|-------------|-----------|--------------------------------------------------------------------------------------------|
| Auth Key              | `auth_key`              | `MALPEDIA_AUTH_KEY`              | /           | Yes       | API authentication key                                                                     |
| Interval Sec          | `internal_sec`          | `MALPEDIA_INTERVAL_SEC`          | `86400`     | Yes       | Interval in seconds before a new import is considered                                      |
| Import Intrusion Sets | `import_intrusion_sets` | `MALPEDIA_IMPORT_INTRUSION_SETS` | `true`      | Yes       | Choose if you want to import Intrusion-Sets from Malpedia                                  |
| Import Yara           | `import_yara`           | `MALPEDIA_IMPORT_YARA`           | `true`      | Yes       | Choose if you want to import Yara rules from Malpedia                                      |
| Create Indicators     | `create_indicators`     | `MALPEDIA_CREATE_INDICATORS`     | `true`      | Yes       | Choose if you want to create Indicators Sample (File) from Malpedia                        |
| Create Observables    | `create_observables`    | `MALPEDIA_CREATE_OBSERVABLES`    | `true`      | Yes       | Choose if you want to create Observables Sample (File) from Malpedia                       |
| Default Marking       | `default_marking`       | `MALPEDIA_DEFAULT_MARKING`       | `TLP:CLEAR` | No        | If not defined in config, an authenticated user will have TLP:AMBER, otherwise TLP:CLEAR   |


## Notes

Information The connector states takes 2 items into account to get started:
- The environment variable "config_interval_sec" is set to 86400 seconds or 24 hours by default.
- The version of Malpedia

So, apart from the first run, if the 24 hour interval is respected and there is a new version of Malpedia, the connector will be restarted.

It's important to note that Malpedia imposes a rate limit, set to "60 API requests per minute" or "2000 API requests per hour". 
This limit is managed within this connector: if a request returns a status code of 429, in this case the request is automatically retried after a delay of 65 seconds (up to 3 attempts). 
If the value of "available_in" (variable returned by Malpedia) is greater than the value of "retry_delay" (Default value = 65 seconds), the latter will be used as the delay. 
Although this may slow down the connector during data recovery, it guarantees that the entire data set will be recovered without failures due to exceeding the throughput limit.

---
The API authentication key. Can be retrieved with a valid account from:

https://malpedia.caad.fkie.fraunhofer.de/settings

If you are authenticated, then all entities created by the connector will be in TLP:AMBER, except for the Yara rules which are based on the TLP defined directly by Malpedia.

If you are not authenticated, by leaving this variable (auth_key) undefined or only public in the form of an empty string (""), all entities created by the connector will be in TLP:WHITE. This connector can therefore be used without an account.

However, it is possible to use "default_marking" as an environment variable to customize your default marking.
Markings availables : "TLP:CLEAR", ""TLP:GREEN", "TLP:AMBER", "TLP:RED".

If you choose to set environment variables such as import_intrusion_sets, import_yara, create_indicators, create_observables to false, the connector will simply skip the bundle creation steps for the selected category.

