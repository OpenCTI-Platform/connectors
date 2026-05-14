# OpenCTI AssemblyLine Connector

| Status   | Date | Comment |
|----------|------|---------|
| Community | -    | -       |

This internal-enrichment connector submits OpenCTI `StixFile` /
`Artifact` observables to an [AssemblyLine](https://cybercentrecanada.github.io/assemblyline4_docs/)
instance for sandbox analysis and ingests the results back into
OpenCTI: malware-analysis verdict, malicious IOCs (domains, IPs,
URLs, file hashes), MITRE ATT&CK techniques observed at runtime, and
the AssemblyLine submission link as an external reference.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
  - [OpenCTI environment variables](#opencti-environment-variables)
  - [Base connector environment variables](#base-connector-environment-variables)
  - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

## Introduction

[AssemblyLine](https://cybercentrecanada.github.io/assemblyline4_docs/)
is a malware-analysis platform developed by the Canadian Centre for
Cyber Security. It can run files through a configurable pipeline of
static + dynamic analysers and reports back maliciousness scores,
extracted IOCs, ATT&CK technique observations, and submission
metadata.

This connector wires AssemblyLine into OpenCTI as an
**internal-enrichment** connector: whenever an analyst (or a
playbook) asks OpenCTI to enrich a `StixFile` or `Artifact` whose
content is available through OpenCTI's storage, the connector
downloads the file, submits it to AssemblyLine, polls until the
analysis completes (within a configurable timeout), and pushes
back:

- A `Malware-Analysis` SDO that records the AssemblyLine submission
  id, profile, verdict and score in the *Malware Analysis* section
  of the enriched observable.
- A `Note` summarising the verdict, the number of indicators
  created, and the AssemblyLine portal link.
- Optionally: STIX `Indicator` objects (and matching `Observable`
  objects linked via `based-on` relationships) for every malicious
  IOC AssemblyLine extracted (domains, IPs, URLs, dropped files).
- Optionally: `Attack-Pattern` objects for every MITRE ATT&CK
  technique observed at runtime, linked to the indicators with
  `related-to` relationships.
- An `External-Reference` on the enriched observable pointing back
  to the AssemblyLine submission.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- A reachable AssemblyLine 4 deployment with API credentials
  (`user` + `apikey`) authorised to submit files and read analysis
  results.

## Configuration variables

There are a number of configuration options, set through the
`config.yml` file (manual deployment) or through environment
variables in `docker-compose.yml` (Docker deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter           | config.yml         | Docker environment variable    | Default                   | Mandatory | Description                                                                |
|---------------------|--------------------|--------------------------------|---------------------------|-----------|----------------------------------------------------------------------------|
| Connector ID        | `id`               | `CONNECTOR_ID`                 |                           | Yes       | A unique `UUIDv4` identifier for this connector instance.                  |
| Connector Type      | `type`             | `CONNECTOR_TYPE`               | `INTERNAL_ENRICHMENT`     | No        | Must be `INTERNAL_ENRICHMENT`.                                             |
| Connector Name      | `name`             | `CONNECTOR_NAME`               | `AssemblyLine`            | No        | Name of the connector as displayed in the OpenCTI UI.                      |
| Connector Scope     | `scope`            | `CONNECTOR_SCOPE`              | `Artifact,StixFile`       | No        | Comma-separated list of observable types this connector enriches.          |
| Connector Auto      | `auto`             | `CONNECTOR_AUTO`               | `true`                    | No        | Whether the connector auto-enriches newly created in-scope observables.    |
| Confidence Level    | `confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL`   | `80`                      | No        | Default confidence (0 – 100) used on created STIX objects.                 |
| Log Level           | `log_level`        | `CONNECTOR_LOG_LEVEL`          | `info`                    | No        | One of `debug`, `info`, `warn`, `error`.                                   |

### Connector extra parameters environment variables

| Parameter                      | config.yml                  | Docker environment variable             | Default                  | Mandatory | Description                                                                                                                                                              |
|--------------------------------|-----------------------------|-----------------------------------------|--------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AssemblyLine URL               | `url`                       | `ASSEMBLYLINE_URL`                      |                          | Yes       | Base URL of the AssemblyLine 4 deployment, e.g. `https://assemblyline.example.com`.                                                                                      |
| AssemblyLine User              | `user`                      | `ASSEMBLYLINE_USER`                     |                          | Yes       | AssemblyLine API user name.                                                                                                                                              |
| AssemblyLine API Key           | `apikey`                    | `ASSEMBLYLINE_APIKEY`                   |                          | Yes       | AssemblyLine API key associated with `user`.                                                                                                                             |
| Verify SSL                     | `verify_ssl`                | `ASSEMBLYLINE_VERIFY_SSL`               | `true`                   | No        | Set to `false` to disable TLS verification (self-signed AssemblyLine deployments).                                                                                       |
| Submission Profile             | `submission_profile`        | `ASSEMBLYLINE_SUBMISSION_PROFILE`       | `static_with_dynamic`    | No        | AssemblyLine submission profile. One of `static`, `dynamic`, `static_with_dynamic`.                                                                                      |
| Submission Classification      | -                           | `ASSEMBLYLINE_CLASSIFICATION`           | `TLP:C`                  | No        | AssemblyLine classification marker attached to every submission.                                                                                                         |
| Submission Timeout (s)         | `timeout`                   | `ASSEMBLYLINE_TIMEOUT`                  | `600`                    | No        | Maximum number of seconds to wait for a submission to complete before giving up.                                                                                         |
| Force Resubmit                 | `force_resubmit`            | `ASSEMBLYLINE_FORCE_RESUBMIT`           | `false`                  | No        | When `true`, every enrichment re-submits the file even if AssemblyLine already has results for it.                                                                       |
| Max File Size (MB)             | `max_file_size_mb`          | `ASSEMBLYLINE_MAX_FILE_SIZE_MB`         | `1`                      | No        | Files larger than this size are skipped (the AssemblyLine API would reject them anyway).                                                                                 |
| Include Suspicious IOCs        | `include_suspicious`        | `ASSEMBLYLINE_INCLUDE_SUSPICIOUS`       | `false`                  | No        | When `true`, suspicious-rated IOCs are imported alongside malicious-rated ones.                                                                                          |
| Create Attack Patterns         | `create_attack_patterns`    | `ASSEMBLYLINE_CREATE_ATTACK_PATTERNS`   | `true`                   | No        | When `true`, MITRE ATT&CK techniques observed by AssemblyLine become `Attack-Pattern` SDOs in OpenCTI.                                                                   |
| Create Malware Analysis        | `create_malware_analysis`   | `ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS`  | `true`                   | No        | When `true`, the connector emits a `Malware-Analysis` SDO that surfaces in the *Malware Analysis* section of the observable.                                             |
| Create Observables             | `create_observables`        | `ASSEMBLYLINE_CREATE_OBSERVABLES`       | `true`                   | No        | When `true`, an `Observable` is created next to each generated `Indicator` and linked through a `based-on` relationship.                                                 |
| Sequential Mode                | `sequential_mode`           | `ASSEMBLYLINE_SEQUENTIAL_MODE`          | `true`                   | No        | When `true`, the connector waits for AssemblyLine to be idle (no in-flight submission) before sending a new one — this prevents overloading the platform.                |
| Sequential Poll Interval (s)   | `poll_interval`             | `ASSEMBLYLINE_POLL_INTERVAL`            | `30`                     | No        | Seconds between idle-checks when `sequential_mode` is enabled.                                                                                                            |

## Deployment

### Docker Deployment

Configure `internal-enrichment/assemblyline/docker-compose.yml` and
start the connector:

```bash
docker compose up -d
```

### Manual Deployment

```bash
cp src/config.yml.sample src/config.yml
# edit src/config.yml and fill in opencti.token, assemblyline.url,
# assemblyline.user, assemblyline.apikey, ...
pip3 install -r src/requirements.txt
python3 src/main.py
```

## Usage

Once the connector is registered with OpenCTI, enrichment is
triggered either automatically (if `CONNECTOR_AUTO=true`) on every
in-scope observable, or manually from the OpenCTI UI on a `StixFile`
or `Artifact` observable.

## Behavior

1. The connector downloads the observable's file content via the
   OpenCTI storage API.
2. The file is submitted to AssemblyLine through `assemblyline-client`
   with the configured profile and classification.
3. The connector polls until the submission reaches a terminal
   state, or until `ASSEMBLYLINE_TIMEOUT` seconds have elapsed.
4. AssemblyLine results are converted into OpenCTI STIX objects:
   - `Malware-Analysis` SDO for the *Malware Analysis* section.
   - `Indicator` + `Observable` pairs for every malicious IOC.
   - `Attack-Pattern` SDOs for every MITRE ATT&CK technique
     observed.
   - A `Note` summarising the verdict + counts.
   - An `External-Reference` pointing back to the AssemblyLine
     submission.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to get verbose tracing of:

- The AssemblyLine submission URL and id.
- Per-step polling state and elapsed time.
- The raw tag / IOC counts extracted from the AssemblyLine result.

## Additional Information

- [AssemblyLine 4 documentation](https://cybercentrecanada.github.io/assemblyline4_docs/)
- [`assemblyline-client` PyPI](https://pypi.org/project/assemblyline-client/)
