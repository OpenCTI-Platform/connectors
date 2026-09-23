# OpenCTI Intel 471 Connector v2

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

## Description

[Intel 471](https://www.intel471.com) delivers structured technical and non-technical intelligence on cyber threats. This connector allows for seamless ingestion of Intel 471 data into the OpenCTI platform.

### 🌐 The Evolution: Verity471
The connector now supports both the legacy **Titan** platform and the new **Verity471** platform. Verity471 acts as a **superset** of Titan: it maintains full functional parity with all existing Titan features while introducing expanded data coverage and streamlined stream logic.

> **Note:** The Verity471 backend is available from release [`7.260317.0`](https://github.com/OpenCTI-Platform/connectors/releases/tag/7.260317.0) onwards.

## Data Streams & Platform Comparison

The following table outlines the data availability across both platforms.

| Stream | Titan Support | Verity471 Support | Produced Objects | Platform Notes |
| :--- | :---: | :---: | :--- | :--- |
| **Indicators** | ✅ | ✅ | `Indicator`, `Malware`, `Infrastructure`, Observables | **Titan:** IPv4, File, URL.<br>**Verity:** Adds Domain and Email. |
| **YARA** | ✅ | ❌ | `Indicator`, `Malware` | **Verity:** Merged into the **Indicators** stream for a unified experience. |
| **Reports** | ✅ | ✅ | `Report`, `Malware`, Observables | **Titan:** Fintel, Info, Malware, Spot, Breach Alerts.<br>**Verity:** Adds Geopol intel reports. |
| **Vulnerabilities** | ✅ | ✅ | `Vulnerability` | Full parity across both platforms. |

> Each stream can be enabled or disabled and configured separately (see "Configuration" section for more details).

### 🎯 Looking for threat hunt packages?

This connector ingests **intelligence** from Titan and Verity471 on a schedule. It does not cover Intel 471's
**detection content** — the curated hunt packages (sigma detections plus analyst runbooks, mitigation guidance and
validation procedures) published on [Intel 471 Hunter](https://hunter.cyborgsecurity.io/), formerly Cyborg Security.

For those, use the [Intel 471 Hunter connector](../../internal-enrichment/intel471-hunt/). It is an *internal
enrichment* connector: an analyst triggers it on a Threat-Actor, Campaign, Attack-Pattern, Vulnerability, Malware,
Tool, Sector or Location, and it attaches the matching hunt packages to that entity. The two connectors are
complementary and can run side by side.

> Hunter uses **separate credentials**: the Cyborg Security API is not yet integrated with the Verity471 API, so the
> Hunter API key is obtained through a different process and is not interchangeable with your Verity471 Client ID and
> Client Secret.

## 🚀 Migration Guide (Titan to Verity471)

Migrating is a straightforward "drop-in" replacement. Because Verity471 provides full parity for existing features, your current data and dashboards will remain consistent.

### Step 1: Prepare
* Ensure you have created an **Application** in the [**Intel 471 Developer Portal**](https://developer.intel471.com/) and noted the **Client ID** and **Client Secret** from that application (those are your _Verity471 API_ credentials).
* Add the APIs your enabled streams rely on to that application: **Indicators** and **Malware** for the Indicators stream, and **Reports** for both the Reports and the Vulnerabilities (CVEs) streams. See [Required Verity471 APIs](#required-verity471-apis).

### Step 2: Update Configuration
Stop your current connector and update its configuration — in the connector's settings in the OpenCTI UI if you deployed it from the marketplace, otherwise in your `docker-compose.yml` or `config.yml`:
1.  **Change Backend**: Set the `INTEL471_BACKEND` variable to `verity471`.
2.  **Update Credentials**: Input your new Verity471 API credentials.
3. **Reset State**: To avoid data overlap and prevent duplicate ingestion during the platform switch, update all `INTEL471_INITIAL_HISTORY_*` variables to the **current date** in epoch milliseconds (e.g., `1738756800000`). This ensures the connector starts fresh with Verity471 data from the moment of migration.
4. Note that **YARA** standalone settings are no longer relevant when using Verity471 and will be ignored, as that data now flows through the **Indicators** stream. You may remove these settings from your configuration to keep it clean.

### Step 3: Restart
Launch the connector. It will immediately begin ingesting the enriched Verity471 data (including new observables and Geopol reports) into your OpenCTI environment.

## 🧩 OpenCTI Platform Compatibility

The connector's own logic is compatible with **both OpenCTI 6.x and 7.x**. The only platform-specific part is the underlying client library (`pycti`), which must match the OpenCTI version of your instance.

* The **official, pre-built connector image** published by Filigran is locked to the **OpenCTI 7.x** platform (`pycti` is pinned to a 7.x release). It will **not** work out-of-the-box against OpenCTI 6.x.
* The legacy **Titan-only** releases of this connector are fully compatible with **OpenCTI 6.x**.

If you run **OpenCTI 6.x** and want the Verity471-enabled connector, you can build a compatible image yourself — the connector source code stays exactly the same, you only need to align the platform libraries in [`src/requirements.txt`](src/requirements.txt) to your instance:

1. Set `pycti` to the version matching your OpenCTI release (e.g. `pycti==6.9.x`).
2. Pin `connectors-sdk` to the matching platform tag (e.g. `...connectors.git@6.9.x#subdirectory=connectors-sdk`), since it also depends on `pycti`.

Then build the image as described in the [Docker](#docker) section below.

## Prerequisites

Intel 471 account with API credentials.

Available as part of Intel 471's paid subscriptions. For more information, please contact sales@intel471.com.

### Required Verity471 APIs

Verity471 credentials are the **Client ID** and **Client Secret** of an application created in the [Intel 471 Developer Portal](https://developer.intel471.com/). APIs are granted per application, so the application must include every API the streams you enable rely on:

| Stream | Enabled by | Required APIs |
| :--- | :--- | :--- |
| **Indicators** | `INTEL471_INTERVAL_INDICATORS` | Indicators, Malware |
| **Reports** | `INTEL471_INTERVAL_REPORTS` | Reports |
| **Vulnerabilities** (CVEs) | `INTEL471_INTERVAL_CVES` | Reports |

If an API is missing, the streams depending on it log an authorization error on every run while the remaining streams keep ingesting, as each stream runs as its own scheduled job.

> **YARA** needs no Verity471 API: it is a Titan-only stream, and on Verity471 that data arrives through the **Indicators** stream.

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

Any of them can be set in three interchangeable ways:

* **OpenCTI UI** — when the connector is deployed from the in-platform marketplace, every setting is entered in the connector's configuration form in the platform; there are no files to edit.
* **Environment variables** — e.g. `INTEL471_BACKEND=verity471`, as in the provided [`docker-compose.yml`](docker-compose.yml).
* **`config.yml`** — the same settings in YAML, e.g. `intel471.backend` (see [`src/config.yml.sample`](src/config.yml.sample)).

_The `opencti` and `connector` options are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Installation

The connector is published in OpenCTI's in-platform **connector catalog (marketplace)**, which is the quickest route: the platform deploys and runs it for you, and every setting is entered through the connector's configuration form in the UI instead of a file. Alternatively, deploy it yourself with Docker or as a stand-alone process — see [Running locally](#running-locally).

For the general installation process, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/).

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
