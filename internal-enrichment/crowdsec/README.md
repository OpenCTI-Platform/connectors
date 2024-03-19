# OpenCTI CrowdSec Connector

This is a OpenCTI connector which enriches your knowledge by using CrowdSec's CTI API.
Architecturally it is an independent python process which has access to the OpenCTI instance and CrowdSec's CTI API. It enriches knowledge about every incoming IP in OpenCTI by looking it up in CrowdSec CTI.

## Installation

### Requirements

- OpenCTI Platform >= 5.3.7

### Configuration
#### Recommanded default

  - OPENCTI_URL=http://opencti:8080
  - OPENCTI_TOKEN=<your OpenCTI API token>
  - CONNECTOR_ID=<a valid UUIV_v4>
  - CROWDSEC_MAX_TLP=TLP:AMBER
  - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
  - CONNECTOR_NAME=crowdsec
  - CROWDSEC_NAME=crowdsec
  - CROWDSEC_DESCRIPTION="CrowdSec CTI enrichment"
  - CONNECTOR_SCOPE=IPv4-Addr # MIME type or Stix Object
  - CONNECTOR_CONFIDENCE_LEVEL=100 # From 0 (Unknown) to 100 (Fully trusted)
  - CONNECTOR_LOG_LEVEL=error
  - CROWDSEC_KEY=<your API Key>
  - CROWDSEC_VERSION=v2 #v2 is the only supported version for now

#### Parameters meaning

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Option `Template`                                                                                                                                          |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                                                                                                 |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `template_attribute`                 | `TEMPLATE_ATTRIBUTE`                | Yes          | Additional setting for the connector itself                                                                                                                |
| `crowdsec_key`							| `CROWDSEC_KEY`                       | Yes       | The CrowdSec API key. See [instructions to obtain it](https://docs.crowdsec.net/docs/next/cti_api/getting_started/#getting-an-api-key)                                                                              |
| `crowdsec_max_tlp`						| `CROWDSEC_MAX_TLP`                   | Yes       | Do not send any data to CrowdSec if the TLP of the observable is greater than CrowdSec_MAX_TLP               |
| `crowdsec_name`							| `CROWDSEC_NAME`               		| Yes       | The CrowdSec organization name                                                                              |
| `crowdsec_description`					| `CROWDSEC_DESCRIPTION`               | Yes       | The CrowdSec organization description                                                                              |

### Additional information

This connector will lookup and edit incoming IPv4 entity.
Note that CrowdSec's CTI has quotas, this connector will poll it if quota is exceeded following exponential backoff.
