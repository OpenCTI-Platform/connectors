# OpenCTI Vulmatch Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner | -    | -       |

## Table of Contents

- [Introduction](#introduction)
  - [Screenshots](#screenshots)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
  - [Configuration Variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [Entity Mapping](#entity-mapping)
  - [Custom STIX Objects and OpenCTI Compatibility](#custom-stix-objects-and-opencti-compatibility)
  - [Processing Details](#processing-details)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

[Vulmatch](https://www.vulmatch.com/) is a web application that turns CVEs into STIX objects enriched with intelligence.

The OpenCTI Vulmatch Connector syncs vulnerability intelligence from Vulmatch to OpenCTI, enabling automated import of CVE data with CVSS scores, EPSS predictions, CWE/ATT&CK/CAPEC mappings, Known Exploits, and CPE software associations.

The OpenCTI Vulmatch Connector enriches vulnerability data with additional intelligence beyond what is available through the [NIST NVD CVE](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations/nist-nvd-cve), [CISA Known Exploited Vulnerabilities (KEV)](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations/cisa-kev), and [FIRST EPSS](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations/first-epss) Connectors.

> **Note**: This connector only works with Vulmatch Web. It does not support self-hosted Vulmatch installations at this time.

### Screenshots

![Vulmatch CVE list](media/vulmatch-cve-list.png)

![Vulmatch STIX Objects](media/vulmatch-cve-graph.png)

---

## Installation

### Requirements

- OpenCTI >= 6.5.10
- Vulmatch team subscribed to a plan with API access enabled
- Vulmatch API Key

### Generating an API Key

[![Creating a Vulmatch API Key to use with the Vulmatch OpenCTI Connector](https://img.youtube.com/vi/OabQepWZU4Q/0.jpg)](https://www.youtube.com/watch?v=OabQepWZU4Q)

[This video demonstrates the steps outlined below](https://www.youtube.com/watch?v=OabQepWZU4Q).

1. Log in to your Vulmatch account
2. Navigate to "Account Settings"
3. Locate the API section and select "Create New API Key"
4. Select the team you want to use and generate the key
  * If you don't see a team listed, you do not belong to a team on a plan with API access. Please upgrade the teams account to continue.
5. Copy the API Key for the OpenCTI Connector configuration

---

## Configuration

### Configuration Variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

A few notes on the Vulmatch-specific options:

- `VULMATCH_API_KEY` is the key generated in [Generating an API Key](#generating-an-api-key).
- `VULMATCH_SBOM_ONLY` selects one of the two ways to use the connector: ingest only the vulnerabilities related to products in your Vulmatch SBoM (`true`), or every vulnerability that matches the filters (`false`).
- The score filters (`VULMATCH_EPSS_SCORE_MIN`, `VULMATCH_CVSS_V2_SCORE_MIN`, `VULMATCH_CVSS_V3_SCORE_MIN` and `VULMATCH_CVSS_V4_SCORE_MIN`) are disabled with `-1`, which also includes the vulnerabilities that have no score.
- `VULMATCH_DAYS_TO_BACKFILL` uses the `created` value of the CVE and only applies to the initial data polling (backfill). Changing it after the backfill has completed has no effect.
- `CONNECTOR_DURATION_PERIOD` replaces the deprecated `VULMATCH_INTERVAL_DAYS`. When `VULMATCH_INTERVAL_DAYS` is set alone, its value (in days) is migrated to `CONNECTOR_DURATION_PERIOD`.

---

## Deployment

### Docker Deployment

Use the following `docker-compose.yml`:

```yaml
services:
  connector-vulmatch:
    image: opencti/connector-dogesec-vulmatch:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_VULMATCH_ID}
      - CONNECTOR_NAME=Vulmatch
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=P1D
      - VULMATCH_BASE_URL=https://api.vulmatch.com/
      - VULMATCH_API_KEY=${VULMATCH_API_KEY}
      - VULMATCH_SBOM_ONLY=false
      - VULMATCH_EPSS_SCORE_MIN=-1
      - VULMATCH_CVSS_V2_SCORE_MIN=-1
      - VULMATCH_CVSS_V3_SCORE_MIN=-1
      - VULMATCH_CVSS_V4_SCORE_MIN=-1
      - VULMATCH_DAYS_TO_BACKFILL=90
    restart: always
    depends_on:
      - opencti
```

### Manual Deployment

1. Clone the repository and navigate to the connector directory
2. Install dependencies: `pip install -r requirements.txt`
3. Configure `config.yml`
4. Run: `python main.py`

---

## Behavior

### Data Flow

```mermaid
graph LR
    %% Box 1: Vulmatch Web
    subgraph Vulmatch_Web["Vulmatch Web"]
        CVEs[Vulnerability Data]
    end

    %% Box 2: Vulmatch API
    subgraph Vulmatch_API["Vulmatch API"]
        API[API]
        Bundle[STIX Bundle]
        API --> Bundle
    end
    
    %% Box 3: OpenCTI
    subgraph OpenCTI["OpenCTI"]
        Connector[Connector]
        LocalProcessing[Local Processing]
        STIX[STIX Objects]

        Connector --> LocalProcessing
        LocalProcessing --> STIX

        STIX --> vulnerability[vulnerability]

        vulnerability --> indicator[Indicator]
        vulnerability --> attack-pattern-attck[ATT&CK Technique]
        vulnerability --> attack-pattern-capec[CAPEC Technique]
        vulnerability --> report-kev[KEV]
        vulnerability --> report-epss[EPSS]

        indicator --> software[Software]

    end

    %% Cross-section flow
    CVEs --> API
    Bundle --> Connector

```

### Entity Mapping

| Vulmatch Data | OpenCTI Entity | Notes |
|---------------------------|----------------|-------|
| CVE | Vulnerability | Representing the named CVE |
| CPE | Software | The hardware/OS/software impacted by CVE |
| Indicator | Indicator | Contains the CPE pattern vulnerable to the CVE |
| ATT&CK Enterprise Technique | Attack Pattern | MITRE ATT&CK techniques |
| CAPEC Technique | Attack Pattern | MITRE CAPEC techniques |
| KEV | Report | Known Exploited Vulnerabilities linked to a CVE |
| EPSS | Report | EPSS history of a CVE |

### Custom STIX Objects and OpenCTI Compatibility

#### Custom Objects

Vulmatch includes several custom STIX object types that are not currently supported by OpenCTI. These custom objects are:

* `exploit` (SDO)
    * Associated KEVs are still imported as reports. You just won't be able to see the actual exploits discovered by Vulmatch.
* `weaknesses` (SDO)
    * CWE references can still be found in the `vulnerability` objects imported.

The connector will reprocess the bundle it receives from Vulmatch to remove these objects.

#### Custom Relationships

In Vulmatch, `grouping` objects are used to model CPE matches in NVD (which are then linked to the actual CPE `software` objects).

Whilst OpenCTI does support the ingest of `grouping` objects, it does not support the use of custom `relationship_type` linking the Indicator to Grouping in Vulmatch. This is vital, because the `relationship_type` defines if the CPEs are vulnerable (or not) the the CVE. For example, Chrome might be vulnerable, but needs to be running on Windows to make if vulnerable.

The workaround:

We don't import any `grouping` objects (or `relationships`s referencing them)

We do however create `relationship` objects on the fly in this connector to link Vulnerabilities to known vulnerable CPEs (i.e. CPEs linked to `grouping` objects with a connection to the CVE `indicator` with `relationship_type=x-cpes-vulnerable`). The relationship objects are created as follows:

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "<vulnerability.published>",
    "modified": "<vulnerability.modified>",
    "relationship_type": "has",
    "source_ref": "software--<ID>",
    "target_ref": "vulnerability--<ID>",
    "description": "<SOFTWARE NAME> is vulnerable to <VULNERABILITY NAME>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d"
    ],
    "external_references": [
        {
            "source_name": "cve",
            "external_id": "<vulnerabilities.cve.id>",
            "url": "https://nvd.nist.gov/vuln/detail/<vulnerabilities.cve.id>"
        }
    ]
}

```

The UUIDv5 logic uses 

* namespace: `152ecfe1-5015-522b-97e4-86b60c57036d`
* value: `<relationship_type>+<source_ref>+<target_ref>`

This does mean some context is lost (i.e. not vulnerable CPEs, CPE Match information). However, this can be obtained in Vulmatch if needed.

### Processing Details

1. **Vulnerability Selection**:
   - Specify if vulnerabilities in SBoM or all vulnerabilities should be imported from Vulmatch

2. **Historical Import**:
   - On first run, backfills historical data
   - Maximum backfill period: 90 days
   - Configurable via `VULMATCH_DAYS_TO_BACKFILL`

3. **Incremental Updates**:
   - Polls at configured interval (default: 1 day)
   - Only fetches new/updated vulnerability intelligence since last run

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug`.

### Verification

Navigate to `Data` → `Ingestion` → `Connectors` → `Vulmatch` to verify the connector is working.

---

## Additional Information

### About Vulmatch

- **Website**: [vulmatch.com](https://www.vulmatch.com/)
- **Sign up**: Free tier available
- **Provider**: [dogesec](https://dogesec.com/)

### Support

- **OpenCTI Support**: For general connector installation help
- **dogesec Community Forum**: [community.dogesec.com](https://community.dogesec.com/) (recommended)
- **dogesec Support Portal**: [support.dogesec.com](https://support.dogesec.com/) (requires plan with email support)

### Use Cases

| Use Case | Description |
|---------|-------------|
| Vulnerability Intelligence | Enrich CVE data in OpenCTI with CVSS, EPSS, CWE, KEV, and vulnerable software relationships from Vulmatch. |
| Risk-Based Vulnerability Prioritization | Prioritize vulnerabilities using EPSS and CVSS scores to focus on the most likely and impactful threats. |