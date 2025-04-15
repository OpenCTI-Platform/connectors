# OpenCTI Datasets Connector

This connector collects data from the OpenCTI datasets repository in order to pre-populate your OpenCTI instance with information like the following:
* companies (identity objects)
* industry sectors (identity objects)
* countries and regions (locations objects)

## Configuration

The connector can be configured with the following variables:

| Env var | Default | Description |
| - | - | - |
| `CONFIG_INTERVAL` | 7 | Number of the days between each MITRE datasets collection. |
| `CONFIG_REMOVE_CREATOR` | true | Remove creator identity from objects being imported |
| `CONFIG_SECTORS_FILE_URL` | https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json | Resource URL |
| `CONFIG_GEOGRAPHY_FILE_URL` | https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json | Resource URL |

**Note:** in case you do not want to collect a specific data source, just pass `False` on the correspondent config option, e.g., `MITRE_CAPEC_FILE_URL=False`.