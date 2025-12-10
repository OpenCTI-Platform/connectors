# OpenCTI Templates

Table of Contents

- [OpenCTI Templates](#opencti-templates)
  - [Introduction](#introduction)
  - [Preparation](#preparation)
    - [Docker Environment](#docker-environment)
      - [Docker Compose Basics](#docker-compose-basics)
    - [Local Environment](#local-environment)
  - [How to create a new connector](#how-to-create-a-new-connector)
    - [Create a new connector using the script](#create-a-new-connector-using-the-script)
    - [Manual creation](#manual-creation)
      - [Changing the template](#changing-the-template)
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

However, this effort is always needed since connectors are expected to be run in production using `docker compose up`.

#### Docker Compose Basics

To engage with OpenCTI deployed systems in a different folder, it is relevant to understand how Docker networking works.
Services deployed within a given `docker-compose.yml` file are attached to a specifically created network which uses the name of the folder as the network name.
Hence, if OpenCTI is deployed the official [Docker repository](https://github.com/opencti/docker), the network name would be `docker_default`.

However, when deploying a specific connector we are using a different `docker-compose.yml` file.
This has a direct impact: since the new container is NOT defined in the same `docker-compose.yml` file in which the platform is deployed, and we have to manually attach the container to the previously created network.

To be consistent with the original deployment, we are assuming the the original network is created using the official OpenCTI project (note that credentials may be set manually):

```shell
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

<br>

## How to create a new connector

First, identify what type of connector you need. To develop a connector, you have to start by defining the use case—ask yourself, "What do I want to achieve with this connector?"

### Create a new connector using the script

You MUST be on templates folder.
You can create a new connector by simply running the following command:

```shell
sh create_connector_dir.sh -t <TYPE> -n <NAME>
```

Where `<TYPE>` is the type of connector you want to create (`external-import`,`internal-enrichment`,`stream`, `internal-import-file`, `internal-export-file`) and `<NAME>` is the name of the connector.

### Manual creation

Copy the folder contents of the corresponding template in the suitable folder:

```shell
cp templates/external-import external-import/[CONNECTOR_NAME]
```

Complete environment variables in `docker-compose.yml file` (for Docker container deployment) or `config.yml` file (for local deployment) and test it before going on:

```shell
cd external-import/[CONNECTOR_NAME]

# If working with docker
docker compose up -build

# If working locally
cd src
pip install -r requirements.txt
python main.py
```

#### Changing the template

There are a few files in the template we need to change for our connector to be unique. You can check for all places you need to change you connector name with the following command (the output will look similar):

```shell
# search for the term "template" in files within the current directory
# and all its subdirectories
$ grep -Ri template

# Output
./config.yml:  id: 'external-import-template'
./config.yml:  name: 'Template Connector'
./config.yml:template:
./config.yml.sample:  name: 'External Import Template Connector'
./docker-compose.yml:  connector-template-connector:
./docker-compose.yml:    image: opencti/connector-template:6.8.13
./docker-compose.yml:      - TEMPLATE_API_BASE_URL=CHANGEME
./docker-compose.yml:      - TEMPLATE_API_KEY=CHANGEME
./Dockerfile:COPY src /opt/opencti-connector-template
./Dockerfile:RUN cd /opt/opencti-connector-template && \
./entrypoint.sh:cd /opt/opencti-connector-template
./README.md:# OpenCTI External Ingestion Template Connector
./README.md:- [OpenCTI External Ingestion Template Connector](#opencti-external-ingestion-connector-template)
./src/connector/__init__.py:__all__ = ["TemplateConnector"]
./src/main.py:from connector import TemplateConnector
./src/main.py:        connector = TemplateConnector()
./tests/test_main.py:from connector import TemplateConnector
```

Required changes:

1. Change `Template` or `template` mentions to your connector name e.g. `ImportCsv` or `import_csv`/`import-csv`
2. Change `TEMPLATE` mentions to your connector name e.g. `IMPORTCSV`
3. Change `Template_Scope` mentions to the required scope of your connector. For processing imported files, that can be the Mime type e.g. `application/pdf` or for enriching existing information in OpenCTI, define the STIX object's name e.g. Report. Multiple scopes can be separated by a simple ,

<br>

### Files and folder structure

Below is an example of a straightforward structure:

- **\_\_metadata\_\_**: Folder containing the connector's metadata (for documentation/deployment).
- **src**: Folder containing the deployable code.
- **src/main.py**: The entry point of the connector.
- **src/connector**: Folder holding the main logic of the connector.
- **src/connector/connector.py**: The core process of the connector.
- **src/connector/converter_to_stix.py**: Converts imported data into STIX objects.
- **src/connector/settings.py**: Defines and validates the configuration variables.
- **src/template_client/api_client.py**: Manages API calls.
- **tests**: Folder containing test cases.

Our goal is to keep concepts clearly separated.

```
external-import
├── __metadata__
|   ├── connector_manifest.json
|   ├── connector_config_schema.json
|   └── logo.png
├── src
|   ├── connector
|   │   ├── __init__.py
|   │   ├── connector.py
|   │   ├── converter_to_stix.py
|   │   ├── settings.py
|   │   └── utils.py
|   ├── template_client
|   │   ├── __init__.py
|   │   └── api_client.py
|   ├── main.py
|   └── requirements.txt
├── tests
│   ├── tests_connector
|   │   └── test_settings.py
│   ├── conftest.py
│   ├── test_main.py
|   └── test-requirements.txt
├── config.yml.sample
├── docker-compose.yml
├── Dockerfile
├── entrypoint.sh
├── README.md

```

<br>

### Development

Afterward, locate the following sections which can be located in `def process_message(self, data)` or in `def _collect_intelligence(self)` depending on the type of connector.

```python
        # ===========================
        # === Add your code below ===
        # ===========================
        ...
        # ===========================
        # === Add your code above ===
        # ===========================
```

#### Common

##### When logging a message, use the helper:

```python
self.helper.connector_logger.[info/debug/warning/error]
```

##### To create a bundle, use the helper:

```python
self.helper.stix2_create_bundle(stix_objects)
```

##### To send the bundle to RabbitMQ, use the helper:

```python
self.helper.send_stix2_bundle(stix_objects_bundle)
```

##### To create objects to ingest:

**[NEW]**  
To create an OpenCTI object (STIX2.1 compliant object), use our [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors/tree/master/connectors-sdk) library:

```python
from connectors_sdk.models import Indicator, OrganizationAuthor, TLPMarking

author = OrganizationAuthor(name="author")
tlp_marking = TLPMarking(level="green")

indicator = Indicator(
  # id is automatically generated, no need create one
  name="name",
  description="description",
  pattern="pattern",
  pattern_type="pattern_type",
  valid_from="valid_from",
  labels=["label_1", "label_2"],
  markings=[tlp_marking],
  author=author,
  # custom properties (extension of STIX2.1 spec)
  score=50,
)
stix_indicator = indicator.to_stix2_object()
```

**[DEPRECATED]**  
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
  object_marking_refs="object_markings",
  custom_properties="custom_properties",
)
```

<br>

#### Formatting / Linting

⚠️ Any connector **should be validated** through pylint for linter. Example of commands:

Install necessary dependencies:

```shell
cd shared/pylint_plugins/check_stix_plugin
pip install -r requirements.txt
```

You can directly run it in CLI to lint a dedicated directory or python module :

```shell
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint <path_to_my_code> --load-plugins linter_stix_id_generator
```

If you only want to test the custom module :

```shell
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint <path_to_my_code> --disable=all --enable=no_generated_id_stix,no-value-for-parameter,unused-import --load-plugins linter_stix_id_generator
```

Note: no_generated_id_stix is a custom checker available in [shared tools](../shared/README.md)

<br>

⚠️ Any connector **should be formatted** through black and isort:

```commandline
black .
isort --profile black .
```

<br>

⚠️ Any commits **should be signed and verified** through GPG signature.

<br>

#### External import connectors specifications

- **Interval handling**

This method allows you to schedule the process to run at a certain intervals.
This specific scheduler from the pycti connector helper will also check the queue size of a connector.
If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold, the connector's main process will not run until the queue is ingested and reduced sufficiently, allowing it to restart during the next scheduler check. (default is 500MB)
It requires the `duration_period` connector variable in ISO-8601 standard format

Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes

Configurations

```yml
connector:
  id: "external-import-template"
  name: "Template Connector"
  scope: "ChangeMe"
  log_level: "info"
  duration_period: "PT10S"
```

Code

```python
self.helper.schedule_iso(
    message_callback=self.process_message,
    duration_period=self.config.connector.duration_period,
)
```

- **Initiate a new work**

Initialize a new job and process it once data is imported

```python
work_id = self.helper.api.work.initiate_work(
    self.helper.connect_id, friendly_name
)

self.helper.api.work.to_processed(work_id, message)
```

Get current state

```python
current_state = self.helper.get_state()
```

Set new state

```python
self.helper.set_state()
```

#### Internal enrichment connectors specifications

Listen to event triggered on OpenCTI

```python
self.helper.listen(message_callback=self.process_message)
```

#### Stream connectors specifications

Listen to live streams from the OpenCTI platform.

The method continuously monitors messages from the platform
The connector have the capability to listen a live stream from the platform.
The helper provide an easy way to listen to the events.

```python
self.helper.listen_stream(message_callback=self.process_message)
```

### Tests

Testing is crucial for several reasons:

1. **Ensuring Quality**: Tests help detect and fix bugs early, ensuring the code meets requirements.
2. **Maintaining Stability**: They prevent new changes from breaking existing functionality and support continuous integration.
3. **Facilitating Collaboration**: Tests act as documentation and enable safe code refactoring.
4. **Increasing Confidence**: Thorough testing ensures the code is reliable and ready for release.
5. **Efficiency**: Early bug detection reduces costs and time in the long run.

### Metadata

Metadata allows some automations to be executed on the connector:

- automatically add the connector to the XTM Hub connectors catalog
- generate essential parts of the connector's documentation (in its README, XTM Hub, OpenCTI, etc...)

The connector's manifest must contain the info below (all fields are required):

```json
{
  "title": "Template Connector", # Official name of the connector
  "slug": "template", # name of the connector's directory
  "description": "Template description of the connector",
  "short_description": "Template short description (summary) of the connector",
  "logo": "external-import/template/__metadata__/logo.png", # Path of the logo if it exists, otherwise `null`
  "use_cases" : ["Open Source Threat Intel"],
  "verified": false, # DO NOT CHANGE - FOR INTERNAL USE ONLY
  "last_verified_date": null, # DO NOT CHANGE - FOR INTERNAL USE ONLY
  "playbook_supported": false, # Whether the connector is compatible with playbooks on OpenCTI (for connectors of type `INTERNAL_ENRICHMENT` only)
  "max_confidence_level": 50,
  "support_version": ">=6.8.12",
  "subscription_link": null, # Link to subscribe to the external service
  "source_code": "https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/template",
  "manager_supported": false, # DO NOT CHANGE - FOR INTERNAL USE ONLY
  "container_version": "rolling",
  "container_image": "opencti/connector-template", # Docker image name
  "container_type": "EXTERNAL_IMPORT" # Type of the connector (`EXTERNAL_IMPORT`, `INTERNAL_ENRICHMENT`, `INTERNAL_EXPORT_FILE`, `INTERNAL_IMPORT_FILE` or `STREAM`)
}

```

<br>

## Useful Resources

- [Connector Development Documentation](https://docs.opencti.io/latest/development/connectors/)
- [Deployment and setup](https://docs.opencti.io/latest/deployment/overview/)
- [Connectors Ecosystem](https://docs.opencti.io/latest/deployment/connectors/)
