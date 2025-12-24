# OpenCTI MISP Connector

## Installation

The MISP connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-misp:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

**Warning**: This connector is compatible with MISP >=2.4.135.3.

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding these variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Behavior

The MISP connector will check all new events or latest modified event since the last run for import. The import process has the following steps:

- Iterate other MISP events to import with the given parameters and on **modified events since the last run**.
- Convert each associated galaxy or tags to OpenCTI entities: `Threat actors` / `Intrusion sets` / `Malwares` / `Attack Patterns`.
- Convert each attribute to `Indicators`.
- Import all `Indicators`, `Threat actors`, `Intrusion sets`, `Malwares` and `Attack Patterns`.
- Create `indicates` relationships between the `Indicators` and `Threat actors` / `Malwares`.
- Create `uses` relationships between `Threat actors` / `Intrusion sets` / `Malwares` and `Attack patterns`.
- Create `indicates` relationships between the previously created `uses` relationships.

## Debugging

### No reports imported

When running the MISP Connector, it is sometimes a bit difficult to verify if the configured tags filter correctly. In case no reports are imported, please try this approach to improve your query.

When running the MISP connector, it also logs the query as shown in this example:

```
INFO:root:Listing Threat-Actors with filters null.
INFO:root:Connector registered with ID: 520cc948-5e3e-4df0-82c4-f3646ceee537
INFO:root:Starting ping alive thread
INFO:root:Initiate work for 520cc948-5e3e-4df0-82c4-f3646ceee537
INFO:root:Connector has never run
INFO:root:Fetching MISP events with args: {"tags": {"OR": ["APT", "Threat Type:APT"]}, "date_from": "2020-06-16", "limit": 50, "page": 1}
```

Take the query and do a curl test to see if MISP actually returns any events.

```
curl -i
-H "Accept: application/json"
-H "content-type: application/json"
-H "Authorization: YOUR API KEY"
--data '{"tags": {"OR": ["APT", "Threat Type:APT"]}, "date_from": "2020-06-16", "limit": 50, "page": 1}'
-X POST
http://YOURMISP.SERVER
```

You can also save your tags in a tags.json file and then simply reference curl to the file with `--data "@tags.json"`
Details: https://www.circl.lu/doc/misp/automation/#post-events

If MISP doesn't return anything with your curl query, try to see if any tag names differ from MISP's and alike. Once the query is returning events, the OpenCTI MISP connector should work as well.
