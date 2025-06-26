# AI based OpenCTI Document Import Connector (Powered by Ariane) 

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2025-03-18 |    -    |

This connector allows Enterprise Edition Organizations to feed information from document to OpenCTI, with more capabilities than regular Import Document connector. 

This connector add more extraction capabilities : it is possible to extract `Malware`, `Country` and `Intrusion-Set` entities.  

## General overview

OpenCTI data is coming from *import* connectors.

## Installation

### Requirements

- OpenCTI Platform >= 6.5.0

### Configuration

| Parameter                        | Docker envvar                           | Default                                | Mandatory | Description                                                                                   |
|----------------------------------|-----------------------------------------|----------------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `opencti_url`                    | `OPENCTI_URL`                           |                                        | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                  | `OPENCTI_TOKEN`                         |                                        | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                   | `CONNECTOR_ID`                          |                                        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`                 | `CONNECTOR_NAME`                        |                                        | Yes       | Option `ImportDocumentAI`                                                                     |
| `connector_auto`                 | `CONNECTOR_AUTO`                        | `false`                                | No        | Enable/disable auto import of report file                                                     |
| `connector_scope`                | `CONNECTOR_SCOPE`                       |                                        | Yes       | Supported file types: `'application/pdf','text/plain','text/html','text/markdown'`            |
| `connector_log_level`            | `CONNECTOR_LOG_LEVEL`                   | error                                  | No        | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_create_indicator`     | `CONNECTOR_CREATE_INDICATOR`            | `false`                                | No        | Create an indicator for each extracted observable                                             |
| `connector_web_service_url`      | `CONNECTOR_WEB_SERVICE_URL`             | `https://importdoc.ariane.filigran.io` | No        | The URL of the extraction service running the AI model (                                      |
| `connector_licence_key_pem`      | `CONNECTOR_LICENCE_KEY_PEM`             |                                        | Yes       | The license certificate in a PEM format (provided by Filigran to Enterprise Edition users)    |

### Debugging ###

In case the connector doesn't behave like it should, please change the `CONNECTOR_LOG_LEVEL` to `debug`.
This way you will get a log entry for every parsing step to verify each step.
Example

```
"timestamp": "2025-02-21T15:36:43.448532Z", "level": "INFO", "name": "api", "message": "Health check (platform version)..."}
{"timestamp": "2025-02-21T15:36:43.509792Z", "level": "INFO", "name": "api", "message": "Health check (platform version)..."}
{"timestamp": "2025-02-21T15:36:43.698952Z", "level": "INFO", "name": "ImportDocumentAI", "message": "Connector registered with ID", "attributes": {"id": "ChangeMe"}}
{"timestamp": "2025-02-21T15:36:43.699773Z", "level": "INFO", "name": "ImportDocumentAI", "message": "Starting PingAlive thread"}
{"timestamp": "2025-02-21T15:36:43.700252Z", "level": "DEBUG", "name": "ImportDocumentAI", "message": "PingAlive running."}
{"timestamp": "2025-02-21T15:36:43.700442Z", "level": "DEBUG", "name": "ImportDocumentAI", "message": "PingAlive ConnectorInfo", "attributes": {"connector_info": {"run_and_terminate": false, "buffering": false, "queue_threshold": 500.0, "queue_messages_size": 0.0, "next_run_datetime": null, "last_run_datetime": null}}}
{"timestamp": "2025-02-21T15:36:43.701104Z", "level": "INFO", "name": "ImportDocumentAI", "message": "Starting ListenQueue thread"}
{"timestamp": "2025-02-21T15:36:43.702909Z", "level": "INFO", "name": "ImportDocumentAI", "message": "ListenQueue connecting to rabbitMq."}
{"timestamp": "2025-02-21T15:37:23.808816Z", "level": "DEBUG", "name": "ImportDocumentAI", "message": "PingAlive running."}
{"timestamp": "2025-02-21T15:37:23.809170Z", "level": "DEBUG", "name": "ImportDocumentAI", "message": "PingAlive ConnectorInfo", "attributes": {"connector_info": {"run_and_terminate": false, "buffering": false, "queue_threshold": 500.0, "queue_messages_size": 0.0, "next_run_datetime": null, "last_run_datetime": null}}}
{"timestamp": "2025-02-21T15:37:26.935568Z", "level": "INFO", "name": "ImportDocumentAI", "message": "Message ack", "attributes": {"tag": 1}}
{"timestamp": "2025-02-21T15:37:26.935903Z", "level": "INFO", "name": "api", "message": "Reporting work update_received", "attributes": {"work_id": "work_ChangeMe_2025-02-21T15:37:26.830Z"}}
{"timestamp": "2025-02-21T15:37:26.999378Z", "level": "INFO", "name": "ImportDocumentAI", "message": "Processing new message"}
[...]
{"timestamp": "2025-02-21T15:37:32.028339Z", "level": "DEBUG", "name": "ImportDocumentAI", "message": "Results: [{'type': 'entity', 'category': 'Intrusion-Set', 'original_start': 4405, 'original_end': 4413, 'range': [4405, 4413], 'match': 'Andariel'}, {'type': 'entity', 'category': 'Malware', 'original_start': 4421, 'original_end': 4431, 'range': [4421, 4431], 'match': 'SmallTiger'}, {'type': 'entity', 'category': 'Malware', 'original_start': 1111, 'original_end': 1121, 'range': [1111, 1121], 'match': 'ModeLoader'}, {'type': 'observable', 'category': 'IPv4-Addr.value', 'original_start': 3044, 'original_end': 3056, 'range': [3044, 3056], 'match': '20.20.100.32'}, {'type': 'observable', 'category': 'IPv4-Addr.value', 'original_start': 3271, 'original_end': 3286, 'range': [3271, 3286], 'match': '45.61.148.153'}, {'type': 'observable', 'category': 'File.name', 'original_start': 3383, 'original_end': 3397, 'range': [3383, 3397], 'match': 'powershell.exe'}, {'type': 'observable', 'category': 'Url.value', 'original_start': 3446, 'original_end': 3478, 'range': [3446, 3478], 'match': 'http://45.61.148.153/pizza.jsp'}, {'type': 'observable', 'category': 'Url.value', 'original_start': 3453, 'original_end': 3478, 'range': [3453, 3478], 'match': '45.61.148.153/pizza.jsp'}, {'type': 'observable', 'category': 'File.hashes.MD5', 'original_start': 4443, 'original_end': 4475, 'range': [4443, 4475], 'match': '3525a8a16ce8988885d435133b3e85d8'}, {'type': 'observable', 'category': 'File.hashes.MD5', 'original_start': 4476, 'original_end': 4508, 'range': [4476, 4508], 'match': '45ef2e621f4c530437e186914c7a9c62'}, {'type': 'observable', 'category': 'File.hashes.MD5', 'original_start': 4509, 'original_end': 4541, 'range': [4509, 4541], 'match': '6a58b52b184715583cda792b56a0a1ed'}, {'type': 'observable', 'category': 'File.hashes.MD5', 'original_start': 4542, 'original_end': 4574, 'range': [4542, 4574], 'match': 'b500a8ffd4907a1dfda985683f1de1df'}]"}
{"timestamp": "2025-02-21T15:37:32.192447Z", "level": "INFO", "name": "ImportDocumentAI", "message": "Message processed, thread terminated", "attributes": {"tag": 1}}
[...]
```

### Supported formats

*Please open a feature requests in case the current implemention doesn't fit your needs*

**File input format**
- PDF file
- Text file
- HTML file
- MD file

**Extractable Entities/Stix Domain Objects**

| Extractable Entity | Based on                        | Example       | Stix entity type and field              | Note |
|--------------------|---------------------------------|---------------|-----------------------------------------|------|
| Attack Pattern     | MITRE ATT&CK Technique          | T1234.001     | AttackPattern.x_mitre_id                |      |
| Country            | Occurrence in the original text | France        | Location.name, Location.aliases         |      |
| Intrusion Set      | Occurrence in the original text | APT29         | IntrusionSet.name, IntrusionSet.aliases |      |
| Malware            | Occurrence in the original text | BadPatch      | Malware.name, Malware.aliases           |      |
| Vulnerability      | CVE Numbers                     | CVE-2020-0688 | Vulnerability.name                      |      |

**Extractable Observables/Stix Cyber Observables**

| Extractable Observable/SCO | Stix Reference fields                        | Supported          | Note |
|----------------------------|----------------------------------------------|--------------------|------|
| Artifact                   | -                                            | :x:                |      |
| AutonomousSystem           | AutonomousSystem.number                      | :heavy_check_mark: |      |
| Directory                  | -                                            | :x:                |      |
| Domain Name                | DomainName.value                             | :heavy_check_mark: |      |
| EMail Address              | EMail-Addr.value                             | :heavy_check_mark: |      |
| EMail Message              | -                                            | :x:                |      |
| File                       | File.name, File.hashes (MD5, SHA-1, SHA-256) | :heavy_plus_sign:  |      |
| IPv4 Address               | IPv4-Addr.value                              | :heavy_check_mark: |      |
| IPv6 Address               | IPv6-Addr.value                              | :heavy_check_mark: |      |
| MAC Address                | Mac-Addr.value                               | :heavy_check_mark: |      |
| Mutex                      | -                                            | :x:                |      |
| Network Traffic            | -                                            | :x:                |      |
| Process                    | -                                            | :x:                |      |
| Software                   | -                                            | :x:                |      |
| URL                        | Url.value                                    | :heavy_check_mark: |      |
| User Account               | -                                            | :x:                |      |
| Windows Registry Key       | WindowsRegistryKey.key                       | :heavy_plus_sign:  |      |
| X.509 Certificate          | -                                            | :x:                |      |

:heavy_check_mark: = Fully implemented
:heavy_plus_sign: = Not entirely implemented
:x: = Not implemented

*Reference: https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html*
