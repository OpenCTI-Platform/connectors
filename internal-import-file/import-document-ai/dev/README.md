# Development Environment (`dev`)

This directory contains resources and tools for local development and testing of the Import Document AI connector. It provides a mock REST API, sample responses, and configuration files to facilitate development without requiring access to production services.

## Purpose

- **Local Testing:** Simulate API responses and test connector features in isolation.
- **Mock Server:** Use `fake_rest.py` to emulate the behavior of the external Document AI service.
- **Sample Responses:** Predefined JSON files in `responses/` directory for various scenarios (success, errors, etc.).
- **Docker Support:** Dockerfile and docker-compose setup for easy environment management.

## Quick Start

### Install dev requirements

```bash
python -m pip install -r dev-requirements.txt
```

### Create a fake PEM certificate

```bash
python -c 'import pprint; from fake_rest import generate_fake_certificate; print(generate_fake_certificate("test", None, None, False).decode())'
```

### Use it dev/docker_compose.yml (or via a .env aside)

**Note**: The fake webservice only checks the time validity and the "common name" of the certificate. See `fake_rest.V1AuthMiddleware` docstring for more info.

Example of .env

```bash
OPENCTI_ADMIN_EMAIL=ChangeMe
OPENCTI_ADMIN_PASSWORD=ChangeMe
OPENCTI_ADMIN_TOKEN=ChangeMe # python -c "from uuid import uuid4; print(uuid4())"
MINIO_ROOT_USER=ChangeMe
MINIO_ROOT_PASSWORD=ChangeMe
RABBITMQ_DEFAULT_USER=ChangeMe
RABBITMQ_DEFAULT_PASS=ChangeMe
SMTP_HOSTNAME=localhost
ELASTIC_MEMORY_SIZE=2g
IMPORT_DOCUMENT_AI_API_BASE_URL=ChangeMe
IMPORT_DOCUMENT_AI_API_KEY="
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"
```

### Build and Run All needed services with Docker Compose

```bash
docker compose up --build
```

Then go to [http://localhost:8080/dashboard/data/ingestion/connectors](http://localhost:8080/dashboard/data/ingestion/connectors) to verify that the connector is attached to the OpenCTI platform.

This will start:

- the mock REST API server defined in `fake_rest.py`
- a fully functionnal OpenCTI platform with needed services
- the connector
- import-file-stix connector (needed when using `Drafts` and `Workbenches`)

**Note:** Currently, the connector and its dependencies are launched simultaneously without waiting for each service to be fully ready. This may result in some error messages during startup, but the Docker restart policies will ensure that all services are running correctly after a short delay.

### Modify responses as needed

The fake server always returns a predefined response stored in the `dev/responses` directory. The `docker-compose` file mounts and binds this directory, allowing you to directly edit the JSON files to change the responses of the fake REST API.

### Alternative:  Use without docker

You can also run the fake REST API server without Docker by executing the following command:

```bash
cd dev
python -m pip install -r dev-requirements.txt
python -m uvicorn fake_rest:app --host 0.0.0.0 --port 5000
```

This will start the server on port 5000, and you can access it at `http://localhost:5000`.
