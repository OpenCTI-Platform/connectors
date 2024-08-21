# OpenCTI Templates

Table of Contents

- [OpenCTI Templates](#opencti-templates)
  - [Introduction](#introduction)
  - [Preparation](#preparation)
    - [Docker Environment](#docker-environment)
      - [Docker Compose Basics](#docker-compose-basics)
    - [Local Environment](#local-environment)
  - [How to create a new connector](#how-to-create-a-new-connector)

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
$ pip3 install -r requirements
$ cp config.yml.sample config.yml
# Define the opencti url and token, as well as the connector's id
$ vim config.yml
$ python3 main.py
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
cp templates/internal-enrichment internal-enricment/[CONNECTOR_NAME]
```

Set the `.env` file and test it before going on:

```
cd internal-enrichment/[CONNECTOR_NAME]
docker compose up -build
```

### Files and folder structure

### Best Practices

## Useful Resources


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