# Google Threat Intelligence Connector

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2025-06-20 |    -    |

---

## Introduction

Google Threat Intelligence Feeds Connector ingests threat intelligence from the Google Threat Intel API and feeds it into the OpenCTI solution, focusing -for now- on STIX entities tied to report objects.
It extracts and transforms relevant data types report, location, sector, malware, intrusion-set, attack-pattern, vulnerability, and raw IOCs delivering structured, and ingest that in an intelligible way into OpenCTI.

Most of the data is extracted from the reports, but some entities are extracted from the report's relationships.
More information can be found in the [Google Threat Intel API documentation](https://gtidocs.virustotal.com/reference/reports).

> This connector requires a Google Threat Intel API key to function. You can obtain one by signing up for the Google Threat Intel service.5
> Reports Analysis are only available to users with the Google Threat Intelligence (Google TI) Enterprise or Enterprise Plus licenses.5

---

## Quick start

Here’s a high-level overview to get the connector up and running:

1. **Set environment variables**:
        - inside `docker-compose.yml`
2. **Pull and run the connector** using Docker:
```bash
        docker compose up -d
```

---

## Installation

### Requirements

- OpenCTI Platform version **6.6.10** or higher
- Docker & Docker Compose (for containerized deployment)
- Valid GTI API credentials (token)

---

## Configurations Variables

### OpenCTI Configuration

Below are the required parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker Environment Variable | Mandatory | Description                                    |
| ---           | ---        | ---                         | ---       | ---                                            |
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.               |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The API token for authenticating with OpenCTI. |

### Connector Configuration

Below are the required parameters you can set for running the connector:

| Parameter                 | config.yml        | Docker Environment Variable | Default                   | Mandatory | Description                                                                 |
| ---                       | ---               | ---                         | ---                       | ---       | ---                                                                         |
| Connector ID              | `id`              | `CONNECTOR_ID`              | /                         | Yes       | A unique `UUIDv4` identifier for this connector.                            |

Below are the optional parameters you can set for running the connector:

| Parameter                 | config.yml        | Docker Environment Variable | Default                                                                                                      | Mandatory | Description                                                                 |
| ---                       | ---               | ---                         | ---                                                                                                          | ---       | ---                                                                         |
| Connector Name            | `name`            | `CONNECTOR_NAME`            | Google Threat Intel Feeds                                                                                    | No        | The name of the connector as it will appear in OpenCTI.                     |
| Connector Scope           | `scope`           | `CONNECTOR_SCOPE`           | report,location,identity,attack_pattern,domain,file,ipv4,ipv6,malware,sector,intrusion_set,url,vulnerability | No        | The scope of data to import, a list of Stix Objects.                        |
| Connector Log Level       | `log_level`       | `CONNECTOR_LOG_LEVEL`       | error                                                                                                         | No        | Sets the verbosity of logs. Options: `debug`, `info`, `warn`, `error`.      |
| Connector Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD` | PT2H                                                                                                         | No        | The duration period between two schedule for the connector.                 |
| Connector TLP Level       | `tlp_level`       | `CONNECTOR_TLP_LEVEL`       | AMBER+STRICT                                                                                                 | No        | The TLP level for the connector. Options: `WHITE`, `GREEN`, `AMBER`, `RED`. |
| Connector Queue Threshold | `queue_threshold` | `CONNECTOR_QUEUE_THRESHOLD` | 500                                                                                                          | No        | The threshold for the queue size before processing.                         |

### GTI Configuration

Below are the required parameters you'll need to set for Google Threat Intel:

| Parameter                             | config.yml              | Docker Environment Variable | Default    | Mandatory | Description                                                 |
| ---                                   | ---                     | ---                         | ---        | ---       | ---                                                         |
| Google Threat Intel API Key           | `gti.api_key`           | `GTI_API_KEY`               |            | Yes       | The API key for Google Threat Intel.                        |

Below are the optional parameters you can set for Google Threat Intel:

| Parameter                                 | config.yml              | Docker Environment Variable | Default                           | Mandatory | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---                                       | ---                     | ---                         | ---                               | ---       | ---                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Google Threat Intel Import Start Date     | `gti.import_start_date` | `GTI_IMPORT_START_DATE`     | P1D                               | No        | The start date for importing data from Google Threat Intel.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Google Threat Intel API URL               | `gti.api_url`           | `GTI_API_URL`               | https://www.virustotal.com/api/v3 | No        | The API URL for Google Threat Intel.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Google Threat Intel Toggle Import Reports | `gti.import_reports`    | `GTI_IMPORT_REPORTS`        | True                              | No        | If set to `True`, the connector will import reports from Google Threat Intel.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Google Threat Intel Report Types          | `gti.report_types`      | `GTI_REPORT_TYPES`          | All                               | No        | The types of reports to import from Google Threat Intel. Can be a string separated by comma for multiple values. Valid values are: `All`, `Actor Profile`, `Country Profile`, `Cyber Physical Security Roundup`, `Event Coverage/Implication`, `Industry Reporting`, `Malware Profile`, `Net Assessment`, `Network Activity Reports`, `News Analysis`, `OSINT Article`, `Patch Report`, `Strategic Perspective`, `TTP Deep Dive`, `Threat Activity Alert`, `Threat Activity Report`, `Trends and Forecasting`, `Weekly Vulnerability Exploitation Report` |
| Google Threat Intel Report Origins        | `gti.origins`           | `GTI_ORIGINS`               | All                               | No        | The origin of the reports to import from Google Threat Intel. Can be a string separated by comma for multiple values. Valid values are: `All`, `partner`, `crowdsourced`, `google threat intelligence`.                                                                                                                                                                                                                                                                                                                                                   |

> 📅 The `import_start_date` can be formatted as a time zone aware datetime or as a duration (e.g., `1970-01-01T00:00:00+03:00` for January, 1st 1970 at 3AM in Timezone +3H or `P3D` for 3 days ago relative to NOW UTC).

## Development

## Contributing

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md).

### Running the Connector Locally

The connector is designed to be run in a Docker container. However, if you want to run it locally for development purposes, you can do so by following these steps:

1/ Clone the connector's repository:
```bash
    git clone <repository-url>
```

2/ Navigate to the connector directory
```bash
    cd external-import/google-ti-feeds
```

3/ Ensure you are using a Python 3.12 version

4/ Install the required dependencies:
```bash
pip install -e .[all]
```
(for legacy purposes, you can also use `pip install -r requirements.txt` that is in editable mode.)

5a/ Set the required variables:
In your shell:
```bash
        export OPENCTI_URL=<your_opencti_url>
        ...
```
OR sourcing a `.env` file:
```bash
        source .env
```
OR creating a "config.yml" file at the root of the project:
```yaml
       opencti:
           url: <your_opencti_url>
       ...
```

6/ Run the connector:
```bash
       GoogleTIFeeds
```
  or ignore 5b and run it with the environment variable:
```bash
      GoogleTIFeeds
```
 or by launching the main.py:
```bash
      python connector/__main__.py
```
 or by launching the module:
```bash
      python -m connector
```

### Commit

Note: Your commits must be signed using a GPG key. Otherwise, your Pull Request will be rejected.

### Linting and formatting

Added to the connectors linteing and formatting rules, this connector is developed and checked using ruff and mypy to ensure the code is type-checked and linted.
The dedicated configurations are set in the `pyproject.toml` file.
You can run the following commands to check the code:

```bash
   python -m isort .
   python -m black . --check
   python -m ruff check .
   python -m mypy .
   python -m pip_audit .
```

### Testing

To run the tests, you can use the following command:
```bash
    python -m pytest -svv
```
