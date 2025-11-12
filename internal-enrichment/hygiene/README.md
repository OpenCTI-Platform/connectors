# OpenCTI Internal Enrichment Hygiene Connector

## Status Filigran

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

## Introduction

**Introducing Hygiene**

This is an internal enrichment connector that uses the following external
projects to look for observable values in the database that you might want to
delete / decay because they are known to lead to false-positives when used for
detection:

* [misp-warninglists](https://github.com/MISP/misp-warninglists)

The connector works for the following OpenCTI observable types:

* IPv4-Addr
* IPv6-Addr
* Domain-Name
* StixFile
* Artifact

And works also for the Indicators based on these observables types.

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-hygiene:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Requirements

- tldextract==5.3.0
- pydantic-settings==2.10.1
- pycti==6.7.15
- git+http://github.com/MISP/PyMISPWarningLists.git@main#egg=pymispwarninglists

## Configuration variables environment

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)

## Behavior

1. Adds a `hygiene` or `hygiene_parent` label by default on items that correspond to a warning list entry. These are configurable(both color and label name)
2. Sets the score of all related indicators to a value based on the number of
   reported entries (1:15, >=3:10, >=5:5, default:20).

## Performance and Multi-threading

The connector now supports multi-threaded processing for significant performance improvements:

- **Parallel Processing**: Process up to 100 indicators/observables simultaneously using ThreadPoolExecutor
- **Direct Thread Pool Submission**: Messages are immediately submitted to the thread pool for processing
- **Thread-safe Operations**: All warning list searches are protected with thread locks
- **Automatic Resource Management**: ThreadPoolExecutor handles queueing and worker management internally
- **Statistics Tracking**: Monitor processing rates, hits, errors, active tasks, and average processing time
- **Graceful Shutdown**: Properly handles shutdown signals and waits for all active tasks to complete

### Configuration

Set the number of parallel workers using the `HYGIENE_MAX_WORKERS` environment variable:
- Default: 100 workers
- Range: 1-500 workers
- Set to 1 for sequential processing (old behavior)

### Performance Metrics

The connector logs statistics every 100 processed messages, including:
- Total messages processed
- Total warning list hits
- Processing errors
- Average processing time per message
- Number of active tasks vs max workers

### Architecture

The multi-threaded architecture is extremely simple:
1. The main thread receives messages from RabbitMQ via the standard OpenCTI helper
2. Each message is immediately submitted to a ThreadPoolExecutor
3. The thread pool handles all queuing and worker management automatically
4. Workers process messages in parallel, limited only by the max_workers setting