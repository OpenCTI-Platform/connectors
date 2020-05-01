# OpenCTI Malpedia Connector

this connector imports knowledge from the [Malpedia Library](https://malpedia.caad.fkie.fraunhofer.de/).

The connector adds data for the following OpenCTI observable/indicator types:

* yara
* file-sha256

The connectors adds the following Entities:

* Malware
* Threat Actor

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-malpedia:rolling` (replace `rolling`
with the latest OpenCTI release version for production usage).

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

The connector can be configured with the following variables:

#### BASE_URL

Base url for the malpedia website. Must end in a "/".
default = 'https://malpedia.caad.fkie.fraunhofer.de/'

#### AUTH_KEY

API authentication key. Can be retreived with a valid account from:
https://malpedia.caad.fkie.fraunhofer.de/settings

default = 'ChangeMe'

#### INTERVAL_SEC

Interval in seconds before a new import is considered.

default = 86400 (== 1 day)

#### IMPORT_ACTORS

Choose if you want to import Threat Actors from Malpedia.
If you choose `False` only references for existing Threat Actors are imported.

default = False

#### CONNECTOR_UPDATE_EXISTING_DATA

This will allow the connector to overwrite existing extries.

**Caution** 
You should only enable this for connectors that you consider a knowledge priority for the specific entities.

default = False

#### CONNECTOR_CONFIDENCE_LEVEL

The confidence level you give to the connector.