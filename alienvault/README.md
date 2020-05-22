# OpenCTI AlienVault Connector

The OpenCTI AlienVault connector can be used to import knowledge from the Alien Labs Open Threat Exchange (OTX) platform.
The connector leverages the OTX DirectConnect API to get the threat data of the subscribed pulses. 

**Note**: Requires joining the OTX threat intelligence community.

## Installation

The OpenCTI AlienVault connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-alienvault:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

The connector can be configured with the following variables:

| Config Parameter            | Docker env var                          | Default                                             | Description                                                                                               |
| --------------------------- | --------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `base_url`                  | `ALIENVAULT_BASE_URL`                   | `https://otx.alienvault.com`                        | The base URL for the OTX DirectConnect API.                                                               |
| `api_key`                   | `ALIENVAULT_API_KEY`                    | `ChangeMe`                                          | The OTX Key.                                                                                              |
| `tlp`                       | `ALIENVAULT_TLP`                        | `White`                                             | The TLP marking used for the imported objects in the OpenCTI.                                             |
| `pulse_start_timestamp`     | `ALIENVAULT_PULSE_START_TIMESTAMP`      | `2020-05-01T00:00:00`                               | The Pulses modified after this timestamp will be imported. Timestamp in ISO 8601 format, UTC.             |
| `report_type`               | `ALIENVAULT_REPORT_TYPE`                | `Threat Report`                                     | The type of imported reports in the OpenCTI.                                                              |
| `report_status`             | `ALIENVAULT_REPORT_STATUS`              | `New`                                               | The status of imported reports in the OpenCTI.                                                            |
| `guess_malware`             | `ALIENVAULT_GUESS_MALWARE`              | `false`                                             | The Pulse tags are used to guess (queries malwares in the OpenCTI) malwares related to the given Pulse.   |
| `interval_sec`              | `ALIENVAULT_INTERVAL_SEC`               | `1800`                                              | The import interval in seconds.                                                                           |
