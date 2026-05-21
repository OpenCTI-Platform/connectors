# OpenCTI Intel 471 Connector v2

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

## Description

[Intel 471](https://www.intel471.com) delivers structured technical and non-technical intelligence on cyber threats. This connector allows for seamless ingestion of Intel 471 data into the OpenCTI platform.

### 🌐 The Evolution: Verity471
The connector now supports both the legacy **Titan** platform and the new **Verity471** platform. Verity471 acts as a **superset** of Titan: it maintains full functional parity with all existing Titan features while introducing expanded data coverage and streamlined stream logic.

## Data Streams & Platform Comparison

The following table outlines the data availability across both platforms.

| Stream | Titan Support | Verity471 Support | Produced Objects | Platform Notes |
| :--- | :---: | :---: | :--- | :--- |
| **Indicators** | ✅ | ✅ | `Indicator`, `Malware`, Observables | **Titan:** IPv4, File, URL.<br>**Verity:** Adds Domain and Email. |
| **YARA** | ✅ | ❌ | `Indicator`, `Malware` | **Verity:** Merged into the **Indicators** stream for a unified experience. |
| **Reports** | ✅ | ✅ | `Report`, `Malware`, Observables | **Titan:** Fintel, Info, Malware, Spot, Breach Alerts.<br>**Verity:** Adds Geopol intel reports. |
| **Vulnerabilities** | ✅ | ✅ | `Vulnerability` | Full parity across both platforms. |

> Each stream can be enabled or disabled and configured separately (see "Configuration" section for more details).

## 🚀 Migration Guide (Titan to Verity471)

Migrating is a straightforward "drop-in" replacement. Because Verity471 provides full parity for existing features, your current data and dashboards will remain consistent.

### Step 1: Prepare
* Ensure you have your Verity471 API credentials ready.

### Step 2: Update Configuration
Stop your current connector and modify your `docker-compose.yml` or `config.yml`:
1.  **Change Backend**: Set the `INTEL471_BACKEND` variable to `verity471`.
2.  **Update Credentials**: Input your new Verity471 API credentials.
3. **Reset State**: To avoid data overlap and prevent duplicate ingestion during the platform switch, update all `INTEL471_INITIAL_HISTORY_*` variables to the **current date** in epoch milliseconds (e.g., `1738756800000`). This ensures the connector starts fresh with Verity471 data from the moment of migration.
4. Note that **YARA** standalone settings are no longer relevant when using Verity471 and will be ignored, as that data now flows through the **Indicators** stream. You may remove these settings from your configuration to keep it clean.

### Step 3: Restart
Launch the connector. It will immediately begin ingesting the enriched Verity471 data (including new observables and Geopol reports) into your OpenCTI environment.

## Prerequisites

Intel 471 account with API credentials.

Available as part of Intel 471's paid subscriptions. For more information, please contact sales@intel471.com.

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Installation

For the installation process, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/).

## Running locally

### Stand-alone

This connector can run as a stand-alone Python program. It does require access to the running OpenCTI API instance
and the RabbitMQ queue. Provide configuration in `src/config.yaml`, install Python [dependencies](src/requirements.txt) and run it by calling [main.py](src/main.py).

### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t connector-intel471:latest`.
Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment.
Then, start the docker container with the provided `docker-compose.yml` or integrate it into the global `docker-compose.yml` file of OpenCTI.

## Usage

Navigate to **Data->Connectors->Intel471** and observe completed works and works in progress. They should start to appear after
configured intervals, if new data was available in Titan/Verity471.

To see the indicators created by Indicators stream, and YARA stream, navigate to **Observations->Indicators**.

To see the malware objects created by Indicators stream and YARA stream, navigate to **Arsenal->Malwares**.

To see the Reports created by Reports stream, navigate to **Analysis->Reports**.

To see the CVEs created by Vulnerabilities stream, navigate to **Arsenal->Vulnerabilities**.

**Pro-tip**: Creating a new user and API token for the connector can help you more easily track which STIX2 objects were created by the connector.
