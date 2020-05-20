# OpenCTI Valhalla Connector

![Valhalla Logo](https://valhalla.nextron-systems.com/static/valhalla-logo.png)

this connector imports knowledge from the [Valhalla API](https://valhalla.nextron-systems.com/).
The connector adds data for the following Valhalla observable/indicator types:

* stix2 indicator pattern: yara

## Subscription

The demo rule set (also known as [signature-base](https://github.com/Neo23x0/signature-base))
contains free rules licensed under [CC-BY-NC](https://creativecommons.org/licenses/by-nc/4.0/)

Full access to the rule database requires an active subscription.
Subscriptions can be requested from https://www.nextron-systems.com/valhalla/

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-valhalla:rolling` (replace `rolling`
with the latest OpenCTI release version for production usage).

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

The connector can be configured with the following variables:

| Config Parameter       | Docker env var                   | Default | Description                                                 |
| -----------------------| -------------------------------- | ------- | ----------------------------------------------------------- |
| `api_key `             | `VALHALLA_API_KEY`               | `""`    | API authentication key                                      |
| `interval_sec`         | `VALHALLA_INTERVAL_SEC`          | `86400` | Interval in seconds before a new import is considered       |
| `update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | `false` | This will allow the connector to overwrite existing entries |
| `confidence_level`     | `CONNECTOR_CONFIDENCE_LEVEL`     | `3`     | The confidence level you give to the connector              |

## Notes

If you leave the `api_key` variable undefined or as empty string (`""`) only
demo rules are imported. Those are around 2000 rules from the [signature-base](https://github.com/Neo23x0/signature-base))
repository with additional information. So this connector can also be used
without an account to get an idea of the data.
