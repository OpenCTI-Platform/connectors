# OpenCTI connectors

[![Website](https://img.shields.io/badge/website-opencti.io-blue.svg)](https://www.opencti.io)
[![CircleCI](https://circleci.com/gh/OpenCTI-Platform/connectors.svg?style=shield)](https://circleci.com/gh/OpenCTI-Platform/connectors/tree/master)
[![Slack Status](https://slack.luatix.org/badge.svg)](https://slack.luatix.org)

The following repository is used to store the OpenCTI connectors for the platform integration with other tools and applications. To know how to enable connectors on OpenCTI, please read the [dedicated documentation](https://opencti-platform.github.io/docs/installation/connectors).

## Connectors list and statuses

### External import connectors 

| Connector                               | Description                                   | Status                    | Last version                    |
| ----------------------------------------|-----------------------------------------------|---------------------------|---------------------------------|
| [AlienVault](alienvault)                | Import pulses from AlienVault                 | Released                  | 3.1.0                           |
| [AMITT](amitt)                          | Import datasets of the AMITT framework        | Released                  | 3.1.0                           |
| [CrowdStrike](crowdstrike)              | Import knowledge from CrowdStrike Falcon      | Released                  | 3.1.0                           |
| [Cryptolaemus](cryptolaemus)            | Import Emotet C2 from the Cryptolaemus group  | Released                  | 3.1.0                           |
| [CVE](cve)                              | Import CVE vulnerabilities                    | Released                  | 3.1.0                           |
| [COVID-19 CTC](cyber-threat-coalition)  | Import the COVID-19 CTC blacklist             | Released                  | 3.1.0                           |
| [Malpedia](malpedia)                    | Import the Malpedia malwares and indicators   | In development            | -                               |
| [MISP](misp)                            | Import MISP events                            | Released                  | 3.1.0                           |
| [MITRE](mitre)                          | Import the MITRE ATT&CK / PRE-ATT&CK datasets | Released                  | 3.1.0                           |
| [OpenCTI](opencti)                      | Import the OpenCTI datasets                   | Released                  | 3.1.0                           |

### Internal import files connectors

| Connector                                               | Description                                   | Status                    | Last version                    |
| --------------------------------------------------------|-----------------------------------------------|---------------------------|---------------------------------|
| [ImportFilePdfObservables](import-file-pdf-observables) | Import observables from PDF files             | Released                  | 3.1.0                           |
| [ImportFileStix](import-file-stix)                      | Import knwoledge from STIX 2.0 bundles        | Released                  | 3.1.0                           |

### Internal enrichment connectors

| Connector                         | Description                                                 | Status                    | Last version                    |
| ----------------------------------|-------------------------------------------------------------|---------------------------|---------------------------------|
| [IpInfo](ipinfo)                  | Enrich IP addresses with geolocation                        | Released                  | 3.1.0                           |
| [VirusTotal](virustotal)          | Enrich file hashes with corresponding hashes and file names | Released                  | 3.1.0                           |

### Internal export files connectors

| Connector                                | Description                                   | Status                    | Last version                    |
| -----------------------------------------|-----------------------------------------------|---------------------------|---------------------------------|
| [ExportFileCSV](export-file-csv)         | Export entities in CSV                        | Released                  | 3.1.0                           |
| [ExportFileSTIX](export-file-stix)       | Export entities in STIX 2.0 bundles           | Released                  | 3.1.0                           |

## License

**Unless specified otherwise**, connectors are released under the [Apache 2.0](https://github.com/OpenCTI-Platform/connectors/blob/master/LICENSE). If a connector is released by its author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## Contributing

We welcome your **[contributions for new connectors](https://opencti-platform.github.io/docs/development/connectors)**. Please feel free to fork the code, play with it, make some patches and send us pull requests using [issues](https://github.com/OpenCTI-Platform/connectors/issues).

## About

OpenCTI is a product powered by the collaboration of the [French national cybersecurity agency (ANSSI)](https://ssi.gouv.fr), the [CERT-EU](https://cert.europa.eu) and the [Luatix](https://www.luatix.org) non-profit organization.
