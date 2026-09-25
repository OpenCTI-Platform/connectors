# docker-dev

A small harness to build and run any `external-import` connector in a container,
with your working copy mounted inside it. Edit the connector on the host, rerun
it or its tests in the container — no rebuild needed between edits.

## Requirements

- Docker with the Compose plugin (`docker compose`, not `docker-compose`)
- `make`
- An OpenCTI instance the connector can reach

## Configure

`CONNECTOR_NAME` in [.env](.env) selects the connector. It must match a folder
name under [../external-import/](../external-import/):

```dotenv
COMPOSE_PROJECT_NAME=xtm
CONNECTOR_NAME=cisa-known-exploited-vulnerabilities
```

The dev image expects the connector's own Dockerfile to copy `src` to
`/opt/opencti-connector-$CONNECTOR_NAME`, which is the usual layout. Connectors
that install their sources elsewhere (e.g. `/opt/connector`) will not work
without adjusting the symlink in [Dockerfile](Dockerfile).

> [!WARNING]
> The connector must have a `tests/` folder containing a `test-requirements.txt`.
> The dev image copies `tests/` and installs `tests/test-requirements.txt`, so
> `make dev` fails for connectors that don't have them.

## Commands

Run these from this directory.

| Command | What it does |
| --- | --- |
| `make build` | Builds `../external-import/$CONNECTOR_NAME/Dockerfile` and tags it `current-connector:local` |
| `make dev` | Runs `make build`, then builds the dev layer and opens a shell in the container |
| `make clean` | Removes the compose containers, locally built images and volumes |

## What the dev layer adds

[Dockerfile](Dockerfile) builds on top of `current-connector:local`, with the
connector folder as build context:

- `/opt/src` is a symlink to `/opt/opencti-connector-$CONNECTOR_NAME`, the
  sources installed by the connector's image. It lets
  `tests/test-requirements.txt` resolve its `-r ../src/requirements.txt` line.
- `tests/` is copied to `/opt/tests`, and `git` and `build-base` are installed
  before `pip install -r tests/test-requirements.txt`.
- The container runs as the unprivileged `developer` user (uid 1000).

## Launch a connector

```sh
make dev
```

You land in a `sh` shell in `/opt`. Two mounts are in place:

| Host | Container |
| --- | --- |
| `../external-import/$CONNECTOR_NAME/src` | `/opt/opencti-connector-$CONNECTOR_NAME` (also reachable as `/opt/src`) |
| `../external-import/$CONNECTOR_NAME/tests` | `/opt/tests` |

Start the connector:

```sh
cd /opt/src
python main.py
```

Or run the tests (dependencies are already installed):

```sh
pytest /opt/tests
```

Because `src` and `tests` are bind-mounted, changes on the host take effect on
the next `python main.py` or `pytest` run. Rerun `make dev` only when you change
`requirements.txt`, `test-requirements.txt` or a Dockerfile.

## Connector configuration

Connectors read their settings from a `config.yml` next to `main.py`, or from
environment variables. Copy the sample into `src/` so it lands in the mount:

```sh
cp ../external-import/$CONNECTOR_NAME/config.yml.sample \
   ../external-import/$CONNECTOR_NAME/src/config.yml
```

Then fill in at least `opencti.url`, `opencti.token` and `connector.id` (any
UUIDv4). `src/config.yml` is untracked by design, so do not commit it.

If OpenCTI runs on the host, `http://localhost` is not reachable from inside the
container. Use `http://host.docker.internal:8080`, or attach the container to
the OpenCTI Docker network.

## Switching connectors

Change `CONNECTOR_NAME` in [.env](.env) and run `make dev` again. The
`current-connector:local` tag is reused, so only one connector image exists at a
time.
