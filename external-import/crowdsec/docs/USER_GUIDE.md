![CrowdSec Logo](images/logo_crowdsec.png)

# OpenCTI CrowdSec external import connector

## User Guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Description](#description)
  - [Configuration](#configuration)
    - [Parameters meaning](#parameters-meaning)
  - [Example: Enrichment with default settings](#example-enrichment-with-default-settings)
- [Performance and metrics](#performance-and-metrics)
  - [Light import vs Full import](#light-import-vs-full-import)
  - [Server 1 vs Server 2](#server-1-vs-server-2)
  - [Comparison by number of IPs](#comparison-by-number-of-ips)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description

The connector uses the CrowdSec API to collect IPs from CrowdSec CTI `smoke/search` [endpoint](https://crowdsecurity.github.io/cti-api/#/Freemium/get_smoke_search).


For each IP, an `Ipv4-Addr` or `IPv6-Addr` observable is created (or updated) and enriched. Enrichment depends on the configurations below. 

### Configuration

Configuration parameters are provided using environment variables as described below. Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.



#### Parameters meaning

| Docker environment variable                    | Mandatory | Type    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------------------- | --------- | ------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPENCTI_URL`                                  | Yes       | String  | The URL of the OpenCTI platform.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `OPENCTI_TOKEN`                                | Yes       | String  | The default admin token configured in the OpenCTI platform parameters file.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `CONNECTOR_ID`                                 | Yes       | String  | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `CONNECTOR_NAME`                               | Yes       | String  | Name of the CrowdSec import connector to be shown in OpenCTI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `CONNECTOR_SCOPE`                              | Yes       | String  | Supported scopes: `IPv4-Addr`, `IPv6-Addr`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `CONNECTOR_CONFIDENCE_LEVEL`                   | Yes       | Integer | The default confidence level  (an integer between 0 and 100).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `CONNECTOR_UPDATE_EXISTING_DATA`               | No        | Boolean | Enable/disable update of existing data in database. <br />Default: `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `CONNECTOR_LOG_LEVEL`                          | No        | String  | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). <br />Default: `info`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `CROWDSEC_KEY`                                 | Yes       | String  | CrowdSec CTI  API key. See [instructions to obtain it](https://docs.crowdsec.net/docs/next/cti_api/getting_started/#getting-an-api-key)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `CROWDSEC_IMPORT_QUERY`                        | No        | String  | Lucene Query for the `smoke/search` endpoint. [See documentation](https://docs.crowdsec.net/u/cti_api/search_queries/) for more details.<br />Default: `behaviors.label:"SSH Bruteforce"`                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `CROWDSEC_API_VERSION`                         | No        | String  | CrowdSec API version. Supported version: `v2`. <br />Default: `v2`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `CROWDSEC_IMPORT_INTERVAL`                     | No        | Number  | Interval in hours between two imports.<br />Default: `24`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `CROWDSEC_ENRICHMENT_THRESHOLD_PER_IMPORT`     | No        | Number  | Maximum number of IP addresses to enrich in one import.<br />Default: `2000`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `CROWDSEC_MAX_TLP`                             | No        | String  | Do not send any data to CrowdSec if the TLP of the observable is greater than `crowdsec_max_tlp`. <br />Default: `TLP:AMBER`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `CROWDSEC_TLP`                                 | No        | String  | TLP for created observable. Possible values are: `TLP_WHITE`, `TLP_GREEN`, `TLP_AMBER`, `TLP_RED` . If not set (`None` value), observable will be created without TLP. If an observable already exists, its TLP will be left unchanged.<br />Default: `None`                                                                                                                                                                                                                                                                                                                                                                          |
| `CROWDSEC_LABELS_SCENARIO_NAME`                | No        | Boolean | Enable/disable labels creation based on CTI scenario's name.<br />Default: `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `CROWDSEC_LABELS_SCENARIO_LABEL`               | No        | Boolean | Enable/disable labels creation based on CTI scenario's label.<br />Default: `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `CROWDSEC_LABELS_SCENARIO_COLOR`               | No        | String  | Color of scenario based labels.<br />Default: `#2E2A14` ![](images/labels/2E2A14.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `CROWDSEC_LABELS_CVE`                          | No        | Boolean | Enable/Disable CTI cve name based labels.<br />Default: `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `CROWDSEC_LABELS_CVE_COLOR`                    | No        | String  | Color of cve based labels.<br />Default: `#800080` ![](images/labels/800080.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `CROWDSEC_LABELS_MITRE`                        | No        | Boolean | Enable/Disable CTI mitre technique based labels.<br />Default: `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `CROWDSEC_LABELS_MITRE_COLOR`                  | No        | String  | Color of mitre technique based labels.<br />Default: `#000080` ![](images/labels/000080.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `CROWDSEC_LABELS_BEHAVIOR`                     | No        | Boolean | Enable/Disable CTI behavior based labels.<br />Default: `false`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `CROWDSEC_LABELS_BEHAVIOR_COLOR`               | No        | String  | Color of behavior based labels.<br />Default: `#808000` ![](images/labels/808000.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `CROWDSEC_LABELS_REPUTATION`                   | No        | Boolean | Enable/Disable CTI reputation based labels.<br />Default: `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR`   | No        | String  | Color of malicious reputation label. <br />Default: `#FF0000` ![](images/labels/FF0000.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR`  | No        | String  | Color of suspicious reputation label. <br />Default: `#FFA500` ![](images/labels/FFA500.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `CROWDSEC_LABELS_REPUTATION_SAFE_COLOR`        | No        | String  | Color of safe reputation label. <br />Default: `#00BFFF` ![](images/labels/00BFFF.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR`       | No        | String  | Color of safe reputation label. <br />Default: `#808080` ![](images/labels/808080.png)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `CROWDSEC_INDICATOR_CREATE_FROM`               | No        | String  | List of reputations to create indicators from (malicious, suspicious, known, safe) separated by comma. <br />Default: `'malicious,suspicious,known'`.<br />If an IP is detected with a reputation that belongs to this list, an indicator based on the observable will be created.                                                                                                                                                                                                                                                                                                                                                    |
| `CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE`    | No        | Boolean | Create attack patterns from MITRE techniques <br />If an indicator has been created, there will be a `targets` relationship between the attack pattern and the indicator. Otherwise, there will be a `related-to` relationship between the attack pattern and the observable <br />There will be a `targets` relationship between the attack pattern and a location created from targeted country.<br />Default `true`                                                                                                                                                                                                                |
| `CROWDSEC_VULNERABILITY_CREATE_FROM_CVE`       | No        | Boolean | Create vulnerability from CVE.<br />There will  be a `related-to` relationship between the vulnerabilty and the observable<br />Default `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `CROWDSEC_CREATE_NOTE`                         | No        | Boolean | Enable/disable creation of a note in observable for each enrichment.<br />Default: `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `CROWDSEC_CREATE_SIGHTING`                     | No        | Boolean | Enable/disable creation of a sighting of observable related to CrowdSec organization.<br />Default: `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION` | No        | Boolean | Enable/disable saving the last CrowdSec enrichment date in observable description.<br />Default: `true`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS`       | No        | Number  | Minimum delay (in seconds) between two CrowdSec enrichments.<br />Default: `86400` <br />Use it to avoid too frequent calls to CrowdSec's CTI API.<br />Requires the last CrowdSec enrichment to be saved in the description, as we'll be comparing this date with the current one.<br />if you are also using the [CrowdSec Internal Enrichment connector](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector), please ensure to also set `CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION=true` and a sufficiently high value of `CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS` in the internal enrichment connector. |
| `CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS` | No        | Boolean | Enable/Disable creation of a sighting of observable related to a targeted country<br />Default: `false`<br />Sighting count represents the percentage distribution of the targeted country among all the countries targeted by the attacker.                                                                                                                                                                                                                                                                                                                                                                                          |

You could also use the `config.yml`file of the connector to set the variable.  

In this case, please put the variable name in lower case and separate it into 2 parts using the first underscore `_`. For example, the docker setting `CROWDSEC_MAX_TLP=TLP:AMBER` becomes : 

```yaml
crowdsec:
    max_tlp: 'TLP:AMBER'
```

You will find a `config.yml.sample` file as example.



### Example: Enrichment with default settings

In this example, we chose `146.70.186.190` as it is currently  reported for cve and mitre techniques.

The result of a CrowdSec's enrichment should be similar to the following description: 

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



## Performance and metrics

As mentioned in [this blog article](https://blog.filigran.io/opencti-platform-performances-e3431b03f822), it's really hard tosay how long it will take to ingest thousands of IPs.
The most honest answer is :

> Well, it depends...

We carried out benchmarking tests on 2 separate servers  (Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz), using the OpenCTI 6.1 platform.

- **Server 1** with 8GB ram and 2 cores: we have allocated 2GB for Elastic Search
- **Server 2** with 32Gb ram and 8 cores: we have allocated 16GB for Elastic Search

We used the default `docker-compose.yml` file provided by OpenCTI. In particular, we have left 3 workers in both cases.

The benchmarks were performed on a fresh installation, with no other connectors running (other than the default ones).

We used two types of import configuration: 

- a **LIGHT** import with the poorest possible enrichment: create only an observable with an external reference pointing to the CrowdSec CTI url:

```yaml
- CROWDSEC_LABELS_REPUTATION=false
- CROWDSEC_LABELS_SCENARIO_NAME=false
- CROWDSEC_LABELS_SCENARIO_LABEL=false
- CROWDSEC_LABELS_CVE=false
- CROWDSEC_LABELS_MITRE=false
- CROWDSEC_LABELS_BEHAVIOR=false
- CROWDSEC_INDICATOR_CREATE_FROM=''
- CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE=false
- CROWDSEC_VULNERABILITY_CREATE_FROM_CVE=false
- CROWDSEC_CREATE_NOTE=false
- CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS=false
- CROWDSEC_CREATE_SIGHTING=false
```



- a **FULL** import with the richest possible enrichment: all labels, objects and relationships:


```yaml
- CROWDSEC_LABELS_REPUTATION=true
- CROWDSEC_LABELS_SCENARIO_NAME=true
- CROWDSEC_LABELS_SCENARIO_LABEL=true
- CROWDSEC_LABELS_CVE=true
- CROWDSEC_LABELS_MITRE=true
- CROWDSEC_LABELS_BEHAVIOR=true
- CROWDSEC_INDICATOR_CREATE_FROM='malicious,suspicious,known'
- CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE=true
- CROWDSEC_VULNERABILITY_CREATE_FROM_CVE=true
- CROWDSEC_CREATE_NOTE=true
- CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS=true
- CROWDSEC_CREATE_SIGHTING=true	
```



We analyzed 3 metrics:

- the *CrowdSec Python process time*: the time required by the connector's Python process to handle a given number of IPs. It measures the time needed to retrieve the CrowdSec CTI data, analyze all the IPs, format all the available data to enrich an observable and send all the necessary bundle to the OpenCTI workers.
- the *Total time for ingestion*: the total time to ingest all IP. This this the time elapsed between the start and end of the import.
- the *Average number of bundles ingested per seconds*



We have obtained the following benchmarks.

### Light import vs Full import

To compare a light import and a full import, we used the Server 1 for 2000 IP addresses.

|                                                | Light Import | Full Import      |
| ---------------------------------------------- | ------------ | ---------------- |
| CrowdSec Python process time                   | 90s          | 380s             |
| Number of bundles sent                         | 2000         | 39119            |
| Total time for ingestion                       | 393s (6m33s) | 7050s (2h25m30s) |
| Average number of bundles ingested per seconds | 5.08         | 5.55             |



We can see that, depending on enrichment quality, import time varies by a factor of 1 to 18.



### Server 1 vs Server 2

To compare Server 1 and Server 2 performances, we used a full import of 2000 IP addresses.

As the IP addresses retrieved and the associated CTI data vary from import to import, the number of bundles sent also varies.

|                                                | Server 1         | Server 2        |
| ---------------------------------------------- | ---------------- | --------------- |
| CrowdSec Python process time                   | 380s             | 289s            |
| Number of bundles sent                         | 39119            | 38980           |
| Total time for ingestion                       | 7050s (2h25m30s) | 4925s (1h22m5s) |
| Average number of bundles ingested per seconds | 5.55             | 7,91            |



We can see that, depending on server configuration, import time varies by a factor of 1 to 1,4



### Comparison by number of IPs

We also compared the time needed to ingest different numbers of IP addressses using Server 2 and a full import configuration.

|                                                | 2000 IPs        | 10000 IPs         | 50000 IPs             |
| ---------------------------------------------- | --------------- | ----------------- | --------------------- |
| CrowdSec Python process time                   | 289s            | 1436s (23m56s)    | 2236s (1h36m6s)       |
| Number of bundles sent                         | 38980           | 195519            | 971287                |
| Total time for ingestion                       | 4925s (1h22m5s) | 30346s (8h25m46s) | 305125s (3d12h45m25s) |
| Average number of bundles ingested per seconds | 7,91            | 6,44              | 3,18                  |



We can see that, with the current server configuration, the more IP addresses we ingest, the lower the average number of bundles ingested per second. 

As the time of writing, there are  [ongoing issues](https://github.com/OpenCTI-Platform/opencti/issues/4936) on the OpenCTI GitHub repository. We'll continue to monitor them to see what could be done to improve ingestion performance.











