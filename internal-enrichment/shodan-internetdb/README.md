# OpenCTI Shodan InternetDB Connector

## Description

The InternetDB API provides a lot less data than a regular Shodan IP lookup, however it's free for non-commercial use.

This connector enriches IPv4 observables with domains, CPEs, Vulns, and Tags reported by the Shodan InternetDB API.

* InternetDB Website: [https://internetdb.shodan.io/](https://internetdb.shodan.io/)
* InternetDB Docs: [https://internetdb.shodan.io/docs](https://internetdb.shodan.io/docs)

## Configuration

### Install

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

| Docker Env variable      | config variable   | Default   | Description                                      |
|--------------------------|-------------------|-----------|--------------------------------------------------|
| SHODAN_MAX_TLP           | max_tlp           | TLP:CLEAR | The max TLP allowed to be sent to the Shodan API |
| SHODAN_SSL_VERIFY        | ssl_verify        | true      | Verify SSL connections to the API endpoint       |

## Installation

Please refer to [this](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8) in OpenCTI's documentation as the authoritative source on installing connectors.

### Docker

Build a Docker Image using the provided `Dockerfile`.
Example: `docker build . -t opencti-shodan-internetdb:latest`.
Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment.
Then, start the docker container with the provided `docker-compose.yml`

### Manual/VM Deployment

Create a file `config.yml` based off the provided `config.yml.sample`. 
Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment.
The `id` attribute of the `connector` should be a freshly generated UUID. 
Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` 
Then, run the `python3 -m shodan_internetdb` command to start the connector


## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`.

## Verification

To verify the connector is working, you can navigate to Data->Data Curation in the OpenCTI platform and see the new imported data there.
For troubleshooting or additional verification, please view the Connector logs.
