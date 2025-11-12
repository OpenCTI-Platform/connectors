![CrowdSec Logo](images/logo_crowdsec.png)

# OpenCTI CrowdSec internal enrichment connector

## User Guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Description](#description)
  - [Configuration](#configuration)
    - [Parameters meaning](#parameters-meaning)
    - [Recommended settings](#recommended-settings)
  - [Use case: enrich an observable](#use-case-enrich-an-observable)
    - [Example: Enrichment with recommended settings](#example-enrichment-with-recommended-settings)
  - [Additional information](#additional-information)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description

This is a OpenCTI connector which enriches your knowledge by using CrowdSec's CTI API.

Architecturally it is an independent python process which has access to the OpenCTI instance and CrowdSec's CTI API. 
It enriches knowledge about every incoming IP in OpenCTI by looking it up in CrowdSec CTI.

### Configuration

Configuration parameters are provided using environment variables as described below. Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.



#### Parameters meaning

| Docker environment variable                   | Mandatory | Type | Description                                                                                                                                                                                                                                         |
|-----------------------------------------------| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPENCTI_URL`                                 | Yes  | String    | The URL of the OpenCTI platform.                                                                                                                                                                                                                    |
| `OPENCTI_TOKEN`                               | Yes          | String  | The default admin token configured in the OpenCTI platform parameters file.                                                                                                                                                                         |
| `CONNECTOR_ID`                                | Yes          | String    | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                                                                                  |
| `CONNECTOR_NAME`                              | Yes          | String    | Name of the CrowdSec connector to be shown in OpenCTI.                                                                                                                                                                                              |
| `CONNECTOR_SCOPE`                             | Yes          | String    | Supported scopes: `IPv4-Addr`, `IPv6-Addr`                                                                                                                                                                                                          |
| `CONNECTOR_CONFIDENCE_LEVEL`                  | Yes          | Integer | The default confidence level  (an integer between 0 and 100).                                                                                                                                                                                       |
| `CONNECTOR_AUTO`                              | No | Boolean | Enable/disable auto-enrichment of observables. <br />Default: `false`                                                                                                                                                                               |
| `CONNECTOR_UPDATE_EXISTING_DATA`              | No | Boolean | Enable/disable update of existing data in database. <br />Default: `false`                                                                                                                                                                          |
| `CONNECTOR_LOG_LEVEL`                         | No         | String    | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). <br />Default: `info`                                                                                                                                 |
| `CROWDSEC_KEY`                                | Yes       | String | CrowdSec CTI  API key. See [instructions to obtain it](https://docs.crowdsec.net/docs/next/cti_api/getting_started/#getting-an-api-key)                                                                                                             |
| `CROWDSEC_API_VERSION`                        | No | String | CrowdSec API version. Supported version: `v2`. <br />Default: `v2`.                                                                                                                                                                                 |
| `CROWDSEC_MAX_TLP`                            | No     | String | Do not send any data to CrowdSec if the TLP of the observable is greater than `crowdsec_max_tlp`. <br />Default: `TLP:AMBER`                                                                                                                        |
| `CROWDSEC_LABELS_SCENARIO_NAME`               | No | Boolean | Enable/disable labels creation based on CTI scenario's name.<br />Default: `true`                                                                                                                                                                  |
| `CROWDSEC_LABELS_SCENARIO_LABEL`              | No | Boolean | Enable/disable labels creation based on CTI scenario's label.<br />Default: `true`                                                                                                                                                           |
| `CROWDSEC_LABELS_SCENARIO_COLOR`              | No | String | Color of scenario based labels.<br />Default: `#2E2A14` ![](./images/labels/2E2A14.png)                                                                                                                                                            |
| `CROWDSEC_LABELS_CVE`                         | No | Boolean | Enable/Disable CTI cve name based labels.<br />Default: `false`                                                                                                                                                                                    |
| `CROWDSEC_LABELS_CVE_COLOR`                   | No | String | Color of cve based labels.<br />Default: `#800080` ![](./images/labels/800080.png)                                                                                                                                                                 |
| `CROWDSEC_LABELS_MITRE`                       | No | Boolean | Enable/Disable CTI mitre technique based labels.<br />Default: `false`                                                                                                                                                                             |
| `CROWDSEC_LABELS_MITRE_COLOR`                 | No | String | Color of mitre technique based labels.<br />Default: `#000080` ![](./images/labels/000080.png)                                                                                                                                                     |
| `CROWDSEC_LABELS_BEHAVIOR`                    | No | Boolean | Enable/Disable CTI behavior based labels.<br />Default: `false`                                                                                                                                                                                    |
| `CROWDSEC_LABELS_BEHAVIOR_COLOR`              | No | String | Color of behavior based labels.<br />Default: `#808000` ![](./images/labels/808000.png)                                                                                                                                                            |
| `CROWDSEC_LABELS_REPUTATION`                  | No | Boolean | Enable/Disable CTI reputation based labels.<br />Default: `false`                                                                                                                                                                                  |
| `CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR`  | No | String | Color of malicious reputation label. <br />Default: `#FF0000` ![](./images/labels/FF0000.png)                                                                                                                                                       |
| `CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR` | No | String | Color of suspicious reputation label. <br />Default: `#FFA500` ![](./images/labels/FFA500.png)                                                                                                                                                      |
| `CROWDSEC_LABELS_REPUTATION_SAFE_COLOR`       | No | String | Color of safe reputation label. <br />Default: `#00BFFF` ![](./images/labels/00BFFF.png)                                                                                                                                                            |
| `CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR`      | No | String | Color of safe reputation label. <br />Default: `#808080` ![](./images/labels/808080.png)                                                                                                                                                            |
| `CROWDSEC_INDICATOR_CREATE_FROM`              | No | String | List of reputations to create indicators from (malicious, suspicious, known, safe) separated by comma. <br />Default: empty `''`.<br />If an IP is detected with a reputation that belongs to this list, an indicator based on the observable will be created. |
| `CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE`   | No | Boolean | Create attack patterns from MITRE techniques <br />If an indicator has been created, there will be a `targets` relationship between the attack pattern and the indicator. Otherwise, there will be a `related-to` relationship between the attack pattern and the observable <br />There will be a `targets` relationship between the attack pattern and a location created from targeted country.<br />Default `false` |
| `CROWDSEC_VULNERABILITY_CREATE_FROM_CVE` | No | Boolean | Create vulnerability from CVE.<br />There will  be a `related-to` relationship between the vulnerabilty and the observable<br />Default `true` |
| `CROWDSEC_CREATE_NOTE`                        | No | Boolean | Enable/disable creation of a note in observable for each enrichment.<br />Default: `false`                                                                                                                                                         |
| `CROWDSEC_CREATE_SIGHTING`                    | No | Boolean | Enable/disable creation of a sighting of observable related to CrowdSec organization.<br />Default: `true`                                                                                                                                         |
| `CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION` | No | Boolean | Enable/disable saving the last CrowdSec enrichment date in observable description.<br />Default: `true` |
| `CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS` | No | Number | Minimum delay (in seconds) between two CrowdSec enrichments.<br />Default: `300`<br />Use it to avoid too frequent calls to CrowdSec's CTI API.<br />Requires the last CrowdSec enrichment to be saved in the description, as we'll be comparing this date with the current one.<br />If  `CONNECTOR_AUTO` is `true` and if you are also using the [CrowdSec External Import connector](https://github.com/crowdsecurity/cs-opencti-external-import-connector), please ensure to also set `CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION=true`in the external import connector. |
| `CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS` | No | Boolean | Enable/Disable creation of a sighting of observable related to a targeted country<br />Default: `true`<br />Sighting count represents the percentage distribution of the targeted country among all the countries targeted by the attacker. |

You could also use the `config.yml`file of the connector to set the variable.  

In this case, please put the variable name in lower case and separate it into 2 parts using the first underscore `_`. For example, the docker setting `CROWDSEC_MAX_TLP=TLP:AMBER` becomes : 

```yaml
crowdsec:
    max_tlp: 'TLP:AMBER'
```

You will find a `config.yml.sample` file as example.



#### Recommended settings



  - CROWDSEC_LABELS_SCENARIO_NAME=true
  - CROWDSEC_LABELS_SCENARIO_LABEL=false
  - CROWDSEC_LABELS_CVE=true
  - CROWDSEC_LABELS_MITRE=true
  - CROWDSEC_LABELS_REPUTATION=true
  - CROWDSEC_INDICATOR_CREATE_FROM='malicious,suspicious,known'
  - CROWDSEC_CREATE_NOTE=true
  - CROWDSEC_CREATE_SIGHTING=true
  - CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS=false



### Use case: enrich an observable

If you create a `IPv4 address` or `IPv6 address` observable, this connector will enable you to enrich it with data retrieved from CrowdSec's CTI. 

If `CONNECTOR_AUTO` configuration is set to `true`, the observable will be automatically enriched when created. Otherwise, you'll need to enrich it manually by clicking on the enrichment icon and selecting the CrowdSec connector.

#### Example: Enrichment with recommended settings

In this example, we chose `146.70.186.190` as it is currently  reported for cve and mitre techniques.

Assuming you have an observable whose `IPv4-Addr` value is equal to `146.70.186.190` and you have set the settings recommended above, the result of a CrowdSec's enrichment should be similar to the following description: 

- With regard to the observable itself, you should see:
  - a list of dark olive green scenario name labels (`crowdsecurity/http-admin-interface-probing`, `crowdsecurity/http-bad-user-agent`, etc.)
  - a list of purple cve labels (`cve-2021-41773`, etc.)
  - a red `malicious`reputation label 
  - An external reference  to the [CrowdSec CTI's url](https://app.crowdsec.net/cti/146.70.186.190)
  - A note with some content (confidence, first seen, last seen, behaviors, targeted countries, etc.)
  - A list of relationships:
    - `related` relationships leading to vulnerabilities created from CVEs
    - `based-on` relationship leading to a CrowdSec CTI  indicator
  - A sighting related to CrowdSec with the first and last seen information
- As the `CROWDSEC_INDICATOR_CREATE_FROM` recommended setting contains `malicious` reputation, an indicator has been created with:
  - An external reference to the blocking list from which the flagged IP originates.
  - A list of `indicates` relationship leading to attack patterns created using mitre techniques
    - If you follow one of this relationship, you can navigate to the attack pattern created, where you will see
      - An external reference to the MITRE ATT&CK url
      - A list of `targets` relationships leading to location created from targeted countries (`Canada`, `Poland`, etc.)



### Additional information

This connector will lookup and edit incoming `IPv4-Addr` or `Ipv6-Addr` observable entity.
Note that CrowdSec's CTI has quotas, this connector will poll it if quota is exceeded following exponential backoff.
