# Elastic Threat Intel Connector

This connector allows organizations to feed their Elastic platform using OpenCTI knowledge. It has three modes: `ecs`, `ecs_no_signals`, and `stix`.

`ecs` mode writes indicator objects in ECS format to Elasticsearch for the purpose of using ECS-formatted "[indicator match](https://www.elastic.co/guide/en/security/current/rules-ui-create.html#create-indicator-rule)"
rules in the Detection Engine. It will also create a background thread to poll for matches in the `.siem-signals-*` indices and will record them in OpenCTI as Sightings.

`ecs_no_signals` is the similar, it just avoids the polling of signals. Usefull, for example, if multiple elastic connectors are running for the same target instance. 

`stix` mode writes the raw STIX objects used internally by OpenCTI to the index specified.

This connector uses the OpenCTI *events stream*, so it consumes knowledge in real time and updates `indicator` documents in ECS format. It also creates a background thread to poll for matches and update the OpenCTI indicators with sightings.

## Quick Start

We recommend running this connector from a container, when appropriate. If you build the container according to the directions below, you can pass in a detailed config, or specify configuration via environment variables. By default the container
looks for a config at the path `/app/config.yml`. You should specify a different location if you need with the `-c` flag. Review the usage:

```shell
docker run --rm -ti elastic-connector:latest --help
```

It's probably easiest to grab a copy of the reference config (`config.reference.yml`) and rename it `config.yml`. Make the necessary changes for your environment and pass it into the container.

```shell
docker run --rm -ti --volume $(pwd)/config.yml:/app/config.yml elastic-connector:latest
```

### Requirements

- OpenCTI Platform >= 5.0.0
- Elastic platform >= 7.14.0
- Python 3.9.x (may work with lower version 3.x, but it was developed with 3.9)

### Configuration

Detailed configuration can be managed via the configuration file as noted in the quick start. The script looks for `config.yml` in the current directory, but a different path can be given on the command line. The "current directory" is `/app` in the
Docker container.

Optionally, many of the configuration points can be handled solely by environment variables as noted in the table below. This can be helpful to spin up a quick container to only specify what you need beyond the defaults. Lastly, the environment
variable `CONNECTOR_JSON_CONFIG` takes a JSON equivalent of the `config.yml` and will override all configuration values.

| YAML Parameter                    | Environment Var              | Mandatory | Description                                                                                                                                                              |
|-----------------------------------|------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti.token`                   | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                                              |
| `opencti.url`                     | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                                                                                                         |
| `opencti.ssl_verify`              | `OPENCTI_SSL_VERIFY`         | No        | Set to `False` to disable TLS certificate validation. Defaults to `True`                                                                                                 |
| `connector.confidence_level`      | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The default confidence level for created sightings (a number between 0 and 100).                                                                                         |
| `connector.id`                    | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                       |
| `connector.log_level`             | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                            |
| `connector.mode`                  | `CONNECTOR_MODE`             | No        | Must be 'ecs' for ECS-formatted threat indicator documents, 'ecs_no_signals' if signal polling is not desired, or 'stix' for raw OpenCTI STIX documents. Defaults to 'ecs'.                                                  |
| `connector.name`                  | `CONNECTOR_NAME`             | Yes       | The name of the Elastic instance, to identify it if you have multiple Elastic instances connectors.                                                                      |
| `connector.scope`                 | `CONNECTOR_SCOPE`            | Yes       | Must be `elastic`, not used in this connector.                                                                                                                           |
| `connector.type`                  | `CONNECTOR_TYPE`             | Yes       | Must be `STREAM` (this is the connector type).                                                                                                                           |
| `connector.start_timestamp`       | `CONNECTOR_START_TIMESTAMP`  | No        | Must be a Unix timestamp like `1655890657402` or an ISO date like `2022-05-22T09:17:08.520Z`                                                                             |
| `connector.live_stream_id`        | `CONNECTOR_LIVE_STREAM_ID`   | No        | Must be a generated guid or a string `live` if you want to collect all events type                                                                                       |
| `connector.live_stream_start_timestamp`   | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP`   | No        | Must be a Unix timestamp like `1655890657402` or an ISO date like `2022-05-22T09:17:08.520Z`                                                        |
| `cloud.auth`                      | `CLOUD_AUTH`                 | No        | Auth info for cloud instance of Elasticsearch Cloud                                                                                                                      |
| `cloud.id`                        | `CLOUD_ID`                   | No        | Cloud ID for cloud instance of Elasticsearch                                                                                                                             |
| `output.elasticsearch.api_key`    | `ELASTICSEARCH_APIKEY`       | No        | The Elasticsearch ApiKey (recommended authentication, see [apikey docs](https://www.elastic.co/guide/en/elasticsearch/reference/master/security-api-create-api-key.html) |
| `output.elasticsearch.hosts`      | `ELASTICSEARCH_HOSTS`        | No        | The Elasticsearch instance URL.                                                                                                                                          |
| `output.elasticsearch.password`   | `ELASTICSEARCH_PASSWORD`     | No        | The Elasticsearch password (ApiKey is recommended).                                                                                                                      |
| `output.elasticsearch.username`   | `ELASTICSEARCH_USERNAME`     | No        | The Elasticsearch login user (ApiKey is recommended).                                                                                                                    |
| `output.elasticsearch.ssl_verify` | `ELASTICSEARCH_SSL_VERIFY`   | No        | Set to `False` to disable TLS certificate validation. Defaults to `True`                                                                                                 |
| `output.elasticsearch.reduced_privileges` | `ELASTICSEARCH_REDUCED_PRIVILEGES`   | No        | Set to `True` to disable additional access checks for Elasticsearch if the access does not includes ' manage" cluster-privileges. Defaults to `False`                                                                                                 |
|                                   | `CONNECTOR_JSON_CONFIG`      | No        | (Optional) environment variable allowing full configuration via a single environment variable using JSON. Helpful for some container deployment scenarios.               |


## Building Container

To build the container to run on Docker, Kubernetes, or other OCI runtime, simply run the build from this directory.

```shell
docker build -t elastic-connector:latest .
```

## Building virtual environment

This connector uses [Python Poetry](https://python-poetry.org/) to manage dependencies. If you want to run the project locally, create a virtual environment using your favorite tool (I like pyenv, but the virtualenv module would be just fine). See the
Poetry installation docs on how to install it.

```shell
# Install runtime dependencies
poetry install --no-dev

# Configure connector as noted above
cp config.reference.yml config.yml

# Run main script, it was installed to your virtualenv bin/ dir.
elastic-connector
```

If you want to run tests and do other development things use poetry to install those deps.

```shell
poetry install

# Run all tests tests (flake8, black, isort, unit tests in tests/ dir)
pytest
```

### Using a Constrained API key

Especially for service-based accounts, such as this connector, it's highly recommended that you create an
[API key](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html) with
reduced permissions. This can be done via the Elasticsearch REST API or via the
[Kibana UI](https://www.elastic.co/guide/en/kibana/master/api-keys.html). For the best fine-grained control, you can
use "Dev Tools" in Kibana.

Here's an example API request that creates credentials valid for 365 days (see `expiration` value) and allows
the connector full management over indices and aliases matching `opencti*` and read-only access to the indices
that the [Detection Engine](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html)
writes to. This could be further constrained since most of the cluster permissions are actually only needed
during initial setup of index templates and ILM policy.


```
POST /_security/api_key?pretty
{
  "name": "opencti",
  "expiration": "365d",
  "role_descriptors": {
    "opencti_privileges": {
      "cluster": [
        "monitor",
        "cluster:admin/ilm/get",
        "cluster:admin/ilm/put",
        "manage_index_templates"
      ],
      "indices": [
        {
          "names": [
            "opencti*"
          ],
          "privileges": [
            "all",
            "manage_follow_index"
          ],
          "field_security": {
            "grant": [
              "*"
            ]
          },
          "allow_restricted_indices": false
        }
      ],
      "run_as": []
    },
    "protections_privileges": {
      "cluster": [],
      "indices": [
        {
          "names": [
            ".siem-signals-*"
          ],
          "privileges": [
            "read"
          ],
          "field_security": {
            "grant": [
              "*"
            ],
            "except": []
          },
          "allow_restricted_indices": false
        }
      ],
      "run_as": []
    }
  },
  "metadata": {
    "application": "opencti",
    "environment": {
      "tags": [
        "dev",
        "staging"
      ]
    }
  }
}
```

### Using a Constrained API key without cluster privileges

In combination with the configuration flag "output.elasticsearch.reduced_privileges", the following API request generates API-keys that allow access only to the specific index pattern `opencti*`. 

```
POST /_security/api_key?pretty
{
  "name": "opencti",
  "expiration": "365d",
  "role_descriptors": {
    "opencti_privileges": {
      "cluster": [],
      "indices": [{
        "names": [
          "opencti*"
        ],
        "privileges": [
          "all"
        ],
        "field_security": {
          "grant": [
            "*"
          ]
        },
        "allow_restricted_indices": false
        }
      ],
      "run_as": []
    },
    "protections_privileges": {
      "cluster": [],
      "indices": [
        {
          "names": [
            ".siem-signals-*"
          ],
          "privileges": [
            "read"
          ],
          "field_security": {
            "grant": [
              "*"
            ],
            "except": []
          },
          "allow_restricted_indices": false
        }
      ],
      "run_as": []
    }
  },
  "metadata": {
    "application": "opencti",
    "environment": {
      "tags": [
        "dev",
        "staging"
      ]
    }
  }
}
```