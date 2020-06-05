# OpenCTI Malpedia Connector

![Malpedia Logo](https://malpedia.caad.fkie.fraunhofer.de/static/malpediasite/logo.png)

this connector imports knowledge from the [Malpedia Library](https://malpedia.caad.fkie.fraunhofer.de/).

The connector adds data for the following OpenCTI observable/indicator types:

* yara
* file-sha256

The connectors adds the following Entities:

* Malware
* Intrusion-Set
* References

## Installation

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-malpedia:rolling` (replace `rolling` with the latest OpenCTI release version for production usage).

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml`file of OpenCTI.

## Configuration

The connector can be configured with the following variables:

| Config Parameter               | Docker env var                   | Default  | Description                                                 |
| -------------------------------| -------------------------------- | -------- | ----------------------------------------------------------- |
| `auth_key`                     | `MALPEDIA_AUTH_KEY`              |          | API authentication key                                      |
| `interval_sec`                 | `MALPEDIA_INTERVAL_SEC`          | `86400`  | Interval in seconds before a new import is considered       |
| `import_intrusion_sets`        | `MALPEDIA_IMPORT_INTRUSION_SETS` | `false`  | Choose if you want to import Intrusion-Sets from Malpedia   |
| `import_yara`                  | `MALPEDIA_IMPORT_YARA`           | `false`  | Choose if you want to import Yara rules from Malpedia       |
| `update_existing_data`         | `CONNECTOR_UPDATE_EXISTING_DATA` | `false`  | This will allow the connector to overwrite existing entries |
| `confidence_level`             | `CONNECTOR_CONFIDENCE_LEVEL`     | `3`      | The confidence level you give to the connector              |

## Notes

The API authentication key. Can be retrieved with a valid account from:

https://malpedia.caad.fkie.fraunhofer.de/settings

If you leave this variable undefined or as empty string (`""`) only public, TLP:WHITE entities are imported. So this connector can also be used without an account.

If you choose `false` for `import_intrusion_sets` only references for existing Intrusion-Sets are imported.

**Caution**

You should only enable `update_existing_data` for connectors that you consider a knowledge priority for the specific entities. Entities created by other connectors could be overwritten by this.
