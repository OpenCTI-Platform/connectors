# Google Threat Intelligence Connector

| Status | Date | Comment |
|--------|------|---------|
| Filigran Verified | -    | -       |

---

## Introduction

Google Threat Intelligence Feeds Connector ingests threat intelligence from the Google Threat Intel API and feeds it into the OpenCTI solution, focusing -for now- on STIX entities tied to report objects.
It extracts and transforms relevant data types report, location, sector, malware, intrusion-set, attack-pattern, vulnerability, and raw IOCs delivering structured, and ingest that in an intelligible way into OpenCTI.

Most of the data is extracted from the reports, but some entities are extracted from the report's relationships.
More information can be found in the [Google Threat Intel API documentation](https://gtidocs.virustotal.com/reference/reports).

> This connector requires a Google Threat Intel API key to function. You can obtain one by signing up for the Google Threat Intel service.5
> Reports Analysis are only available to users with the Google Threat Intelligence (Google TI) Enterprise or Enterprise Plus licenses.5

## **IMPORTANT API QUOTA LIMITATIONS**

> **CRITICAL:** Retrieving large volumes of historical threat intelligence data may trigger Google TI API quota limitations, which will **temporarily pause** the connector's data retrieval and ingestion processes.

The connector's ingestion state management system is specifically designed to handle these quota limitations gracefully:

- **State Persistence:** The connector tracks the `update_date` of the last successfully ingested entity, ensuring no data loss occurs during quota-induced pauses.
- **Automatic Resume:** When API quota limits reset and the service becomes available again, the connector will automatically resume data retrieval from exactly where it stopped.
- **Seamless Recovery:** No manual intervention or data re-synchronization is required, the connector will continue processing from the last recorded state.

## **IMPORTANT DATA LIMITATIONS**

> **IMPORTANT NOTE on Threat Actor/Malware Aliases:** The Google Threat Intelligence (GTI) platform aggregates data from both **curated** and **open-source** reports. 
Because the open-source data often uses **overlapping or conflicting aliases** for the same threat actors and malware, the **OpenCTI connector does not currently fetch these aliases from GTI.**

 - This means that the connector will not create relationships between threat actors and malware based on aliases, but instead will create new entries for each alias.  
 - This limitation affects the completeness of threat actor and malware entity relationships and may impact threat correlation capabilities.  
Please be aware of this constraint when using the imported data for analysis and reporting.  

> **NOTE:** The connector now provides configuration options `enable_malware_aliases` and `enable_threat_actor_aliases` (both default to `False`) that allow you to override this behavior and enable alias importing. However, **we strongly recommend keeping these disabled by default** as mentioned above. Enabling aliases is at your own discretion and responsibility.

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

- OpenCTI Platform version **6.7.7** or higher
- Docker & Docker Compose (for containerized deployment)
- Valid GTI API credentials (token)

---

## Configurations Variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

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
pip install -e .[dev,test]
```

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
