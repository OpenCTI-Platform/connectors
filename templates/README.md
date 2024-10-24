# OpenCTI Templates

Table of Contents

- [OpenCTI Templates](#opencti-templates)
  - [Introduction](#introduction)
  - [Preparation](#preparation)
    - [Docker Environment](#docker-environment)
      - [Docker Compose Basics](#docker-compose-basics)
    - [Local Environment](#local-environment)
  - [How to create a new connector](#how-to-create-a-new-connector)
    - [Files and folder structure](#files-and-folder-structure)
    - [Development](#development)
      - [Common](#common)
      - [External Import Specification](#external-import-connectors-specifications)
      - [Internal Enrichment Specification](#internal-enrichment-connectors-specifications)
      - [Stream specifications](#stream-connectors-specifications)
    - [Tests](#tests)
  - [Useful Resources](#useful-resources)

---

## Introduction

This folder contains the templates to be used within OpenCTI.
The examples included are intended to simplify the original connector deployment and to be able to simply work when being deployed from scratch.

## Preparation

To develop and test your connector, you need a running OpenCTI instance with the frontend and the messaging broker accessible.

### Docker Environment

Assuming that OpenCTI is deployed using Docker using the steps on the following documentation: [OpenCTI Docker Deployment](https://docs.opencti.io/latest/deployment/installation/#using-docker), 

Since the deployment of OpenCTI connectors uses `docker-compose.yml` files, it is considered that this approach is the best option to be consistent with the deployment.

Using `docker-compose.yml` files makes the code clearer even when the learning curve needs some Docker knowledge.

However, this effort is always needed since connectors are expected to be run in production using  `docker compose up`.

#### Docker Compose Basics

To engage with OpenCTI deployed systems in a different folder, it is relevant to understand how Docker networking works.
Services deployed within a given `docker-compose.yml` file are attached to a specifically created network which uses the name of the folder as the network name.
Hence, if OpenCTI is deployed the official [Docker repository](https://github.com/opencti/docker), the network name would be `docker_default`. 

However, when deploying a specific connector we are using a different `docker-compose.yml` file. 
This has a direct impact: since the new container is NOT defined in the same `docker-compose.yml` file in which the platform is deployed, and we have to manually attach the container to the previously created network.

To be consistent with the original deployment, we are assuming the the original network is created using the official OpenCTI project (note that credentials may be set manually):

```
git clone https://github.com/OpenCTI-Platform/docker
cd docker
(cat << EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMePlease
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
ELASTIC_MEMORY_SIZE=4G
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_REPORT_ID=$(cat /proc/sys/kernel/random/uuid)
EOF
) > .env
docker compose up --build 
```

Note that this approach implies that the project is cloned into a folder named `docker` being the default network name.
Docker networking creates by default a network using the name of the folder where the `docker-compose.yml` is located (in this case, `docker`) to create a new default network named `docker_default`.

This Docker network is the one which is manually attached to the services found in the `docker-compose.yml` of the connectors. 
Thus, the hostnames of the services defined in the main OpenCTI deployment can be used (e.g., `http://opencti:8080`).

```
networks:
  default:
    external: true
    name: docker_default
```

### Local environment

Assuming that OpenCTI is deployed locally following those instructions from documentation: [Manual Installation](https://docs.opencti.io/latest/deployment/installation/#manual-installation)

For development purpose, simply run the python script locally until everything works as it should

```shell
$ virtualenv env
$ source ./env/bin/activate
$ pip install -r requirements
$ cp config.yml.sample config.yml
# Define the opencti url and token, as well as the connector's id
$ vim config.yml
$ python main.py
# Example of logs
INFO:root:Listing Threat-Actors with filters null.
INFO:root:Connector registered with ID: a2de809c-fbb9-491d-90c0-96c7d1766000
INFO:root:Starting ping alive thread
...
```

## How to create a new connector

First, identify what type of connector you need.
Copy the folder contents of the corresponding template in the suitable folder:

```
cp templates/external-import external-import/[CONNECTOR_NAME]
```

Complete environment variables in docker-compose.yml file (for Docker container deployment) or config.yml file (for local deployment) and test it before going on:

```
cd external-import/[CONNECTOR_NAME]

# If working with docker
docker compose up -build

# If working locally
cd src
pip install -r requirements.txt
python main.py
```

### Changing the template

There are a few files in the template we need to change for our connector to be unique. You can check for all places you need to change you connector name with the following command (the output will look similar):

```shell
# search for the term "template" in files within the current directory 
# and all its subdirectories
$ grep -Ri template

# Output
./docker-compose.yml:  connector-template:
./docker-compose.yml:    image: opencti/connector-template:6.2.4
./docker-compose.yml:      - CONNECTOR_TEMPLATE_API_BASE_URL=CHANGEME
./docker-compose.yml:      - CONNECTOR_TEMPLATE_API_KEY=CHANGEME
./Dockerfile:COPY src /opt/opencti-connector-template
./Dockerfile:RUN cd /opt/opencti-connector-template && \
./entrypoint.sh:cd /opt/opencti-connector-template
./README.md:# OpenCTI External Ingestion Connector Template
./README.md:- [OpenCTI External Ingestion Connector Template](#opencti-external-ingestion-connector-template)
./src/config.yml:  id: 'external-import-template'
./src/config.yml:  name: 'Connector Template'
./src/config.yml:connector_template:
./src/config.yml.sample:  name: 'External Import Connector Template'
./src/external_import_connector/__init__.py:__all__ = ["ConnectorTemplate"]
./src/external_import_tests/test_template_connector.py:class TestTemplateConnector(object):
./src/main.py:from external_import_connector import ConnectorTemplate
./src/main.py:        connector = ConnectorTemplate()
```

Required changes:

1. Change `Template` or `template` mentions to your connector name e.g. `ImportCsv` or `importcsv`
2. Change `TEMPLATE` mentions to your connector name e.g. `IMPORTCSV`
3. Change `Template_Scope` mentions to the required scope of your connector. For processing imported files, that can be the Mime type e.g. `application/pdf` or for enriching existing information in OpenCTI, define the STIX object's name e.g. Report. Multiple scopes can be separated by a simple ,
4. Change `Template_Type` to the connector type you wish to develop. The OpenCTI types are defined hereafter:
   - EXTERNAL_IMPORT
   - INTERNAL_ENRICHMENT
   - INTERNAL_EXPORT_FILE
   - INTERNAL_IMPORT_FILE
   - STREAM


### Files and folder structure

Below is an example of a straightforward structure:

- **main.py**: The entry point of the connector.
- **tests**: Folder containing test cases.
- **connector**: Folder holding the main logic of the connector.
- **connector.py**: The core process of the connector.
- **config_variables.py**: Contains all necessary configuration variables.
- **client_api.py**: Manages API calls.
- **converter_to_stix.py**: Converts imported data into STIX objects.

Our goal is to keep concepts clearly separated.

```
external-import
└── src
    ├── external_import_connector
    │   ├── __init__.py
    │   ├── client_api.py
    │   ├── config_variables.py
    │   ├── connector.py
    │   ├── converter_to_stix.py
    │   └── utils.py
    ├── external_import_tests
    │   ├── __init__.py
    │   ├── common_fixtures.py
    │   ├── fixtures
    │   └── test_template_connector.py
    ├── config.yml.sample
    ├── main.py
    ├── requirements.txt
    └── test-requirements.txt
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
├── README.md

```

### Development

Afterward, locate the following sections which can be located in `def process_message(self, data)` or in `def _collect_intelligence(self)` depending on the type of connector.

```
        # ===========================
        # === Add your code below ===
        # ===========================
        ...
        # ===========================
        # === Add your code above ===
        # ===========================
```

#### Common

When logging a message, use the helper:

```shell
self.helper.connector_logger.[info/debug/warning/error]
```

To create a bundle, use the helper:

```shell
self.helper.stix2_create_bundle(stix_objects)
```

To send the bundle to RabbitMQ, use the helper:

```shell
self.helper.send_stix2_bundle(stix_objects_bundle)
```

To create a STIX object, use stix2 library and ⚠️ Always generate ID to have a predictive ID, use pycti library:

```python
import stix2
from pycti import Indicator

indicator = stix2.Indicator(
  id=Indicator.generate_id("pattern"),
  created_by_ref="created_by",
  name="name",
  description="description",
  pattern="pattern",
  pattern_type="pattern_type",
  valid_from="valid_from",
  labels="labels",
  confidence="confidence",
  object_marking_refs="object_markings",
  custom_properties="custom_properties",
) 
```

#### External import connectors specifications

- **Interval handling**

This method allows you to schedule the process to run at a certain intervals.
This specific scheduler from the pycti connector helper will also check the queue size of a connector.
If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold, the connector's main process will not run until the queue is ingested and reduced sufficiently, allowing it to restart during the next scheduler check. (default is 500MB)
It requires the `duration_period` connector variable in ISO-8601 standard format

Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes

Configurations
```
connector:
  id: 'external-import-template'
  type: 'EXTERNAL_IMPORT'
  name: 'Connector Template'
  scope: 'ChangeMe'
  log_level: 'info'
  duration_period: 'PT10S'
```
Code 
```
self.helper.schedule_iso(
    message_callback=self.process_message,
    duration_period=self.config.duration_period,
)
```

- **Initiate a new work**

Initialize a new job and process it once data is imported

```
work_id = self.helper.api.work.initiate_work(
    self.helper.connect_id, friendly_name
)

self.helper.api.work.to_processed(work_id, message)
```

Get current state

```
current_state = self.helper.get_state()
```

Set new state

```
self.helper.set_state()
```

#### Internal enrichment connectors specifications

Listen to event triggered on OpenCTI

```
self.helper.listen(message_callback=self.process_message)
```

#### Stream connectors specifications

Listen to live streams from the OpenCTI platform.

The method continuously monitors messages from the platform
The connector have the capability to listen a live stream from the platform.
The helper provide an easy way to listen to the events.

```
self.helper.listen_stream(message_callback=self.process_message)
```

### Tests

Testing is crucial for several reasons:

1. **Ensuring Quality**: Tests help detect and fix bugs early, ensuring the code meets requirements.
2. **Maintaining Stability**: They prevent new changes from breaking existing functionality and support continuous integration.
3. **Facilitating Collaboration**: Tests act as documentation and enable safe code refactoring.
4. **Increasing Confidence**: Thorough testing ensures the code is reliable and ready for release.
5. **Efficiency**: Early bug detection reduces costs and time in the long run.

## Useful Resources

- [Connector Development Documentation](https://docs.opencti.io/latest/development/connectors/)
- [Deployment and setup](https://docs.opencti.io/latest/deployment/overview/)
- [Connectors Ecosystem](https://docs.opencti.io/latest/deployment/connectors/)