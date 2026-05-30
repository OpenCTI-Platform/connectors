# CVEProject cvelistV5 connector

An alternative CVE connector that fetches updates straight from the
[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) GitHub
repository instead of querying the NVD REST API. The connector clones the
repository locally and uses `git log` to discover the records that were
added or modified between two runs.

## Summary

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker deployment](#docker-deployment)
  - [Manual deployment](#manual-deployment)
- [Behavior](#behavior)
  - [Initial population](#initial-population)
  - [Pull CVE updates](#pull-cve-updates)
  - [Errors](#errors)
- [Usage](#usage)
- [Sources](#sources)

---

### Introduction

CVE records are fetched from the [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
repository. Each record follows the [CVE v5.1 schema](https://github.com/CVEProject/cve-schema/tree/main)
and is transformed into a STIX 2.1 `Vulnerability` object. Information that
cannot be expressed natively in STIX 2.1 is attached as STIX `Note` objects
linked to the vulnerability.

Extra information that the connector exposes as notes includes:

- **Workarounds**
- **Solutions**
- **Configurations** that make the vulnerability more severe
- **Exploits** that are publicly documented

When the affected products of a CVE expose `cpes` or `versions` entries, the
connector also creates `Software` and `Identity` (vendor) objects, plus the
relationships between them (`software has vulnerability`,
`software related-to vendor`). This makes it possible to display the
organizations exposed to a given vulnerability by relying on existing
`Software` observables.

### Requirements

- OpenCTI Platform version 6.6 or higher
- Outbound HTTPS access to `github.com` so the connector can clone and pull
  the upstream repository
- A persistent volume for the clone (a few GB) when running in Docker

### Configuration variables

Below are the parameters you need to set for OpenCTI connectivity:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the generic connector parameters:

| Parameter               | config.yml          | Docker environment variable    | Default                              | Mandatory | Description                                                                                       |
|-------------------------|---------------------|--------------------------------|--------------------------------------|-----------|---------------------------------------------------------------------------------------------------|
| Connector ID            | `id`                | `CONNECTOR_ID`                 | /                                    | Yes       | A unique `UUIDv4` identifier for this connector instance.                                         |
| Connector Name          | `name`              | `CONNECTOR_NAME`               | `CVEProject cvelistV5`               | No        | Name of the connector as displayed in the OpenCTI UI.                                             |
| Connector Scope         | `scope`             | `CONNECTOR_SCOPE`              | `identity,vulnerability,software`    | No        | The scope of data produced by the connector.                                                      |
| Log Level               | `log_level`         | `CONNECTOR_LOG_LEVEL`          | `info`                               | No        | Verbosity of the logs: `debug`, `info`, `warn`, or `error`.                                       |
| Duration Period         | `duration_period`   | `CONNECTOR_DURATION_PERIOD`    | `PT1H`                               | No        | ISO 8601 duration between two runs (e.g. `PT1H` for hourly, `P1D` for daily).                     |

Below are the connector specific parameters:

| Parameter            | config.yml           | Docker environment variable    | Default                                          | Mandatory | Description                                                                                                              |
|----------------------|----------------------|--------------------------------|--------------------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------|
| Repository URL       | `repo_url`           | `CVELISTV5_REPO_URL`           | `https://github.com/CVEProject/cvelistV5.git`    | No        | URL of the upstream git repository. Override only if you maintain a private mirror.                                      |
| Repository branch    | `repo_branch`        | `CVELISTV5_REPO_BRANCH`        | `main`                                           | No        | Branch to track in the upstream repository.                                                                              |
| Local clone path     | `local_path`         | `CVELISTV5_LOCAL_PATH`         | `/opt/cvelistV5`                                 | No        | Local path where the clone is kept. Should map to a persistent volume in production.                                     |
| History start year   | `history_start_year` | `CVELISTV5_HISTORY_START_YEAR` | `2024`                                           | No        | Oldest year of CVE records to import on the **initial** run. Minimum recommended value is `2019` for CVSS v3.1 coverage. |

### Deployment

#### Docker deployment

Build a docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-cvelistv5:latest
```

Update the environment variables in `docker-compose.yml` with the appropriate
values for your environment, then start the container:

```shell
docker compose up -d
```

In production, mount a named volume on `/opt/cvelistV5` so the clone survives
container restarts (a sample volume declaration is provided in
`docker-compose.yml`).

#### Manual deployment

Create `config.yml` from `config.yml.sample` and adjust the configuration
variables (especially `ChangeMe` placeholders).

Install the Python dependencies, preferably in a virtual environment:

```shell
pip3 install -r src/requirements.txt
```

Then start the connector from the `src` directory:

```shell
python3 main.py
```

### Behavior

#### Initial population

For the first run, the connector clones `CVEProject/cvelistV5`. Depending on
network throughput this can take a few minutes. Once the clone is complete,
the connector walks the `cves/<year>/` folders starting from
`history_start_year` and converts every CVE record into a STIX bundle which
is sent to OpenCTI.

#### Pull CVE updates

After the initial run, the connector waits for the duration defined by
`CONNECTOR_DURATION_PERIOD`. On every subsequent run it fetches the latest
commits, lists the JSON files that changed since the previous run, and
re-imports them. The state stores the ISO 8601 timestamp of the previous run
under the key `last_run`.

#### Errors

Per-record failures are logged with the offending CVE identifier and the
connector keeps processing the remaining files. Runs that fail before any
record is processed (typically network errors during the `git fetch`) are
reported as failed work in the OpenCTI UI.

### Usage

After installation, the connector requires no manual interaction. It will
run periodically according to the configured duration. To force a run, open
*Data* → *Connectors* in OpenCTI, find the connector and click the refresh
icon.

The Software objects created by the connector can be linked to your
organizations via the standard OpenCTI relationship editor, in order to
visualize the vulnerabilities affecting your fleet.

### Sources

- [The CVE Project repository](https://github.com/CVEProject/cvelistV5)
- [Default CVE connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cve)
- [CISA KEV connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cisa-known-exploited-vulnerabilities)
