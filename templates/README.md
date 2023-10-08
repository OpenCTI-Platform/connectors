# OpenCTI Templates

This folder contains several templates to be used within OpenCTI.
The examples included are intended to simplify the original connector deployment and to be able to simply work when being deployed from scratch.

## Assumptions

These templates assume that OpenCTI is deployed using Docker.
Since the deployment of OpenCTI connectors uses `docker-compose.yml` files, it is considered that this approach is the best option to be consistent with the deployment.

Note that the usage of `config.yml` files for development as suggested in previous verions is mainly omitted. 
Using `docker-compose.yml` files makes the code clearer even when the learning curve needs some Docker knowledge.
However, this effort is always needed since connectors are expected to be run in production using  `docker compose up`.

## Docker Compose Basics

To engage with OpenCTI deployed systems in a different folder, it is relevant to understand how Docker networking works.
Services deployed within a given `docker-compose.yml` file are attached to a specifically created network which uses the name of the folder as the network name.
Hence, if OpenCTI is deployed the oficial [Docker repository](https://github.com/opencti/docker), the network name would be `docker_default`. 

However, when deploying a specific connector we are using a different `docker-compose.yml` file. 
This has a direct impact: since the new container is NOT defined in the same `docker-compose.yml` file in which the platform is deplyoyed we have to manually attach the container to the previously created network.

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
Thus, the hostnames of the services defined in the main OpenCTI deployment can be used (e. g., `http://opencti:8080`).

```
...

networks:
  default:
    external: true
    name: docker_default
```

## How to create a new connector

First, identify what type of connector you need.
Copy the folder contents of the corresponding template in the suitable folder:

```
cp templates/internal-enrichment internal-enricment/myconnector
```

Set the `.env` file and test it before going on:

```
cd internal-enrichment/myconnector
docker compose up -build
```

To update it , locate the constructor of the connector in `./str/main.py` and add any capture of specific environment variables :

```
    def __init__(self):
        """Initialization of the connector
        
        Note that additional attributes for the connector can be set after the super() call.
        
        Standarised way to grab attributes from environment variables is as follows:
        
        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")
        
        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.
        
        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization."""
        super().__init__()
```

For example, capture a new environment vairble named `MY_ATTRIBUTE` as follows using `os.environ.get()`:

```
        super().__init__()
        self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")
```

Afterwards, locate the following sections which can be located in `def process_message(self, data)` or in `def _collect_intelligence(self)` depending on the type of connector.

```
        # ===========================
        # === Add your code below ===
        # ===========================
        ...
        # ===========================
        # === Add your code above ===
        # ===========================
```