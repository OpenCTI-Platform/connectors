# OpenCTI Threat Bus Connector

This connector enables STIX-2 indicator export from OpenCTI to [Threat Bus](https://github.com/tenzir/threatbus), the threat intelligence dissemination layer for open-source security tools. Using this connector, you can deeply integrate your OpenCTI threat intelligence with both detection tools and databases, like [VAST](https://github.com/tenzir/vast), [Zeek](https://github.com/zeek/zeek), or [CIF-3](https://github.com/csirtgadgets/bearded-avenger).

The connector consumes the OpenCTI *events stream* (SSE) to process indicator updates in near-real time. It forwards STIX-2 indicators to Threat Bus via [ZeroMQ](https://zeromq.org/).

### Configuration

The connector requires a configuration file or certain environment variables to start up. See the following table for details.

| Config Parameter             | Environment Variable         | Mandatory | Description |
| ---------------------------- | -----------------------------| --------- | ----------- |
| `opencti.url`                | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform. |
| `opencti.token`              | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file. |
| `connector.id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector. |
| `connector.type`             | `CONNECTOR_TYPE`             | Yes       | Must be `STREAM` (this is the connector type). |
| `connector.name`             | `CONNECTOR_NAME`             | Yes       | An arbitrary name for this connector. Unused. |
| `connector.scope`            | `CONNECTOR_SCOPE`            | Yes       | Must be `threatbus`. |
| `connector.confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The confidence_level of relationships created by the connector. Unused. |
| `connector.log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error`. |
| `threatbus.zmq_host`         | `THREATBUS_ZMQ_HOST`         | Yes       | The Threat Bus host (IP address or hostname). |
| `threatbus.zmq_receive_port` | `THREATBUS_ZMQ_RECEIVE_PORT` | Yes       | The Threat Bus ZMQ receive port spawned by the [ZMQ-App plugin](https://docs.tenzir.com/threatbus/plugins/apps/zmq-app). |

## Installation & Usage

This section covers both the installation of the connector and basic installation instructions for a Threat Bus endpoint to connect with.

### Install and Run the Connector

You can run the connector either locally or via Docker.

#### Local Setup

We recommend using a virtual environment for local instalations. Use `pip` to install the `src/requirements.txt` file.

```
virtualenv venv
source venv/bin/activate
pip install -r src/requirements.txt`
```

Copy the `config.yaml.example` and modify it accordingly for your setup. See above for details about parameter values. You can then simply invoke the connector directly:

```
cp src/config.yaml.example src/config.yaml
# vim src/config.yaml    # change parameters
python src/connector.py
```

#### Docker Setup

Build a local container image to run the latest version of the connector via Docker. We use the Docker tag `:rolling` to indicate that this is a local image.

```
docker build -t opencti/connector-threatbus:rolling .
```

If you started your OpenCTI setup using docker-compose, you can simply add a service snip for this connector to your OpenCTI `docker-compose-dev.yaml`. See the `docker-compose.yaml` file in this folder for an example. Change the image tag to `:rolling` to use the container you just built in the step above. 


### Install and Run Threat Bus

[Threat Bus](https://github.com/tenzir/threatbus) is [plugin-based](https://docs.tenzir.com/threatbus/plugins/overview). This connector is designed to send indicator updates via [ZeroMQ](https://zeromq.org/). To use it with Threat Bus, please install the Threat Bus [ZMQ-App plugin](https://docs.tenzir.com/threatbus/plugins/apps/zmq-app) on your Threat Bus host. We recommend using a virtual environment for local installations.

```
virtualenv venv
source venv/bin/activate
pip install threatbus threatbus-zmq-app
```

See the [docs](https://docs.tenzir.com/threatbus/plugins/apps/zmq-app) for more detailed instructions.

Once installed, you can start Threat Bus and all installed plugins directly from the CLI:

```
threatbus -c threatbus-config.yaml
```

If the ZMQ-app plugin is installed correctly, it is ready to receive indicators on the configured port. From here on, Threat Bus handles indicator distribution to all subscribed tools, such as [VAST](https://github.com/tenzir/vast) or [Zeek](https://github.com/zeek/zeek) in near-real time. Indicator updates in OpenCTI will almost immediately find their way deep into your monitoring tools for retro- and live-matching.
