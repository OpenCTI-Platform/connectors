# OpenCTI External Ingestion Connector Template

Import data from a MISP source (feed or MISP files stored in S3).

Table of Contents

- [OpenCTI External Ingestion Connector Template](#opencti-external-ingestion-connector-template)
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
  - [Additional information](#additional-information)

## Introduction

## Installation

### Requirements

- OpenCTI Platform >= 6...

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                              |
|-----------------|------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type       | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                            |
| Connector Name  | name       | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                                  | config.yml                                                   | Docker environment variable                                  | Default    | Mandatory | Description                                                      |
|--------------------------------------------|--------------------------------------------------------------|--------------------------------------------------------------|------------|-----------|------------------------------------------------------------------|
| Source type (url / s3)                     | misp_feed.source_type                                        | MISP_FEED_SOURCE_TYPE                                        | url        | No        | Source type for the MISP feed (url or s3).                       |
| MISP Feed URL                              | misp_feed.url                                                | MISP_FEED_URL                                                |            | No        | The URL of the MISP feed (required if `source_type` is `url`).   |
| MISP Feed SSL Verify                       | misp_feed.ssl_verify                                         | MISP_FEED_SSL_VERIFY                                         | True       | No        | Whether to verify SSL certificates for the feed URL.             |
| MISP Bucket Name                           | misp_feed.bucket_name                                        | MISP_BUCKET_NAME                                             |            | No        | Bucket Name where the MISP's files are stored                    |
| MISP Bucket Prefix                         | misp_feed.bucket_prefix                                      | MISP_BUCKET_PREFIX                                           |            | No        | Used to filter imports                                           |
| AWS Endpoint URL                           | N/A                                                          | AWS_ENDPOINT_URL                                             |            | No        | URL to specify for compatibility with other S3 buckets (MinIO)   |
| AWS Access Key                             | N/A                                                          | AWS_ACCESS_KEY_ID                                            |            | No        | Access key used to access the bucket                             |
| AWS Secret Access Key                      | N/A                                                          | AWS_SECRET_ACCESS_KEY                                        |            | No        | Secret  key used to access the bucket                            |
| MISP Feed Import From Date                 | misp_feed.import_from_date                                   | MISP_FEED_IMPORT_FROM_DATE                                   |            | No        | Start date for importing data from the MISP feed.                |
| MISP Feed Create Reports                   | misp_feed.create_reports                                     | MISP_FEED_CREATE_REPORTS                                     | True       | No        | Whether to create reports from MISP feed data.                   |
| MISP Feed Report Type                      | misp_feed.report_type                                        | MISP_FEED_REPORT_TYPE                                        | misp-event | No        | The type of reports to create from the MISP feed.                |
| MISP Feed Create Indicators                | misp_feed.create_indicators                                  | MISP_FEED_CREATE_INDICATORS                                  |            | No        | Whether to create indicators from the MISP feed.                 |
| MISP Feed Create Observables               | misp_feed.create_observables                                 | MISP_FEED_CREATE_OBSERVABLES                                 |            | No        | Whether to create observables from the MISP feed.                |
| MISP Feed Create Tags as Labels            | misp_feed.create_tags_as_labels                              | MISP_CREATE_TAGS_AS_LABELS                                   | True       | No        | Whether to convert tags into labels.                             |
| MISP Feed Guess Threats From Tags          | misp_feed.guess_threats_from_tags                            | MISP_FEED_GUESS_THREAT_FROM_TAGS                             | False      | No        | Whether to infer threats from tags.                              |
| MISP Feed Author From Tags                 | misp_feed.author_from_tags                                   | MISP_FEED_AUTHOR_FROM_TAGS                                   | False      | No        | Whether to infer authors from tags.                              |
| MISP Feed Markings From Tags               | misp_feed.markings_from_tags                                 | MISP_FEED_MARKINGS_FROM_TAGS                                 | False      | No        | Whether to infer markings from tags.                             |
| MISP Feed Create Object Observables        | misp_feed.create_object_observables                          | MISP_FEED_CREATE_OBJECT_OBSERVABLES                          | False      | No        | Whether to create object observables.                            |
| MISP Feed Import To IDS No Score           | misp_feed.import_to_ids_no_score                             | MISP_FEED_IMPORT_TO_IDS_NO_SCORE                             | True       | No        | Import data without a score to IDS.                              |
| MISP Feed Import With Attachments          | misp_feed.import_with_attachments                            | MISP_FEED_IMPORT_WITH_ATTACHMENTS                            | False      | No        | Whether to import attachments from the feed.                     |
| MISP Feed Import Unsupported Observables   | misp_feed.import_unsupported_observables_as_text             | MISP_FEED_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT             | False      | No        | Import unsupported observables as plain text.                    |
| Import Unsupported Observables Transparent | misp_feed.import_unsupported_observables_as_text_transparent | MISP_FEED_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT_TRANSPARENT | True       | No        | Whether to import unsupported observables transparently as text. |

The S3 client used is boto3, [Configuration Guide](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html. It is now almost fully configurable via environment variables.

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from recorded-future/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
