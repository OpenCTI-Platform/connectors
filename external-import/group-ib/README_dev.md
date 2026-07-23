# OpenCTI Connector


[![Python](https://img.shields.io/badge/python-v3.11+-blue?logo=python)](https://www.python.org/downloads/release/python-3110/)
[![OpenCTI](https://img.shields.io/badge/opencti-v6.8.12+-orange?)](https://github.com/OpenCTI-Platform/opencti/releases/tag/6.8.12)


The OpenCTI Connector


## **Content**

As OpenCTI has a dependency on ElasticSearch, you have to set vm.max_map_count before running the containers,
as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```sh
sudo sysctl -w vm.max_map_count=1048575
```

To make this parameter persistent, add the following to the end of your /etc/sysctl.conf:

```sh
vm.max_map_count=1048575
```


```sh
$ pip3 install black flake8 pycti
# Fork the current repository, then clone your fork
$ git clone https://github.com/YOUR-USERNAME/connectors.git
$ cd connectors
$ git remote add upstream https://github.com/OpenCTI-Platform/connectors.git
# Create a branch for your feature/fix
$ git checkout -b [branch-name]
# Copy the appropriate template directory for the connector type
$ cp -r templates/$connector_type $connector_type/$myconnector
$ cd $connector_type/$myconnector
$ ls -R
# Dockerfile              docker-compose.yml      requirements.txt
# README.md               entrypoint.sh           src

./src:
# main.py   requirements.txt   dev.requirements.txt   config.yml.sample
# connector/   client/   adapters/   pipeline/   models/   support/   _data/   docs/

./src/connector:
# connector.py   settings.py   utils.py   logging_config.py
#   connector.py    — ExternalImportConnector run loop (scheduling, work, state)
#   settings.py     — ConfigConnector + Pydantic settings models
#   utils.py        — validation helpers
#   logging_config.py — stdout + rotating file logging

./src/client:
# api_client.py   — Group-IB TI API boundary (builds the ciaops TIAdapter)

./src/adapters:
# adapter.py   stix_adapter_*.py   (STIX conversion — the converter_to_stix role)



./src/support:
# mitre_mapper.py   note_markdown.py   incident_note_markdown.py
# portal_external_refs.py   text_normalize.py

./src/pipeline:
# collect_intelligence.py   collection_dispatch.py

```

```sh
$ grep -Ri template .
```

```sh
$ python3 -m venv venv
$ source ./venv/bin/activate
$ pip3 install -r src/requirements.txt
$ cp src/config.yml.sample src/config.yml
# Define the opencti url and token, as well as the connector's id
$ vim src/config.yml
$ cd src && python3 main.py
```

## Formatting (development only)

Runtime uses **`requirements.txt`** only. For local development, install pinned tools from **`dev.requirements.txt`** (Black + isort + flake8 + pre-commit; line length **88** via `pyproject.toml`).

```sh
pip install -r dev.requirements.txt
# optional: run hooks on every commit from this connector root
pre-commit install
pre-commit run --all-files   # first-time check of the whole tree
```

Manual one-off (without pre-commit):

```sh
black src
isort src
```

Push your change:

```sh
git add [file(s)]
git commit -m "[connector_name] descriptive message"
git push origin [branch-name]
# Open a pull request with the title "[connector_name] message"
```


## Deployment internals

The client-facing `README.md` shows a single `docker compose up -d` flow. The notes below cover build details, manual (non-Docker) deployment, and the dispatch architecture.

### Docker build — `pycti` pin

Before building the Docker image, set the version of `pycti` in `src/requirements.txt` to match your OpenCTI server. Example: if OpenCTI is `6.8.4`, set `pycti==6.8.4`. If you skip this, pip resolves the latest `pycti` and the SDK initializer may break (the SDK is tightly coupled to the platform version).

```bash
docker compose up -d --build
# -d for detached
```

### Manual Deployment (without Docker)

Install runtime dependencies (preferably in a virtual environment), then run the connector from `src/` and leave it running. OpenCTI uses RabbitMQ and `schedule_iso` for cadence; do **not** invoke `main.py` from cron.

```bash
pip3 install -r src/requirements.txt
cd src
python3 main.py
```

In production wrap `python3 main.py` in systemd/supervisor, or run the shipped Docker image (see `Dockerfile` / `docker-compose.yml`).

### Accessing settings in code

Every value documented in the client-facing parameter reference is available on the OpenCTI helper:

```python
self.helper.connector_name
self.helper.connector_id
# …
```

Use this pattern when adding new internal helpers — avoid reaching back into raw `os.environ`.


## Dispatch architecture

Each TI collection is routed to one of two flows in `pipeline/collect_intelligence.py` (via `SPECIAL_COLLECTIONS.get(collection)` → `_run_special` / `_run_default_flow`), using the maps and dataclasses defined in `pipeline/collection_dispatch.py`.

- **Default flow** (`pipeline/collect_intelligence.py:_run_default_flow`) — used by report-style collections. The connector runs the IOC-extractor and emits a `Report` plus extracted observables and linked SDOs. The per-collection IOC flags live in `pipeline/collection_dispatch.py:IOC_OBSERVABLE_FLAGS` (which observable types are emitted with `is_ioc=True`).
- **Special flow** (`pipeline/collection_dispatch.py:SPECIAL_COLLECTIONS`) — collection-specific handlers in `adapters/stix_adapter_*_mixin.py`. Each handler returns its own bundle shape (incident-centric, indicator-only, identity-only, etc.) tailored to the source data.

Special-collection handler map (current):

| Collection | Handler |
|------------|---------|
| `compromised/access`             | `CompromisedMixin.generate_compromised_access` |
| `compromised/account_group`      | `CompromisedMixin.generate_compromised_account_group` |
| `compromised/bank_card_group`    | `CompromisedMixin.generate_compromised_bank_card_group` |
| `compromised/spd`                | `CompromisedMixin.generate_compromised_spd` |
| `compromised/masked_card`        | `StixAdapterSpecialMixin.generate_compromised_masked_card` |
| `compromised/discord`            | `StixAdapterSpecialMixin.generate_compromised_discord` |
| `compromised/messenger`          | `StixAdapterSpecialMixin.generate_compromised_messenger` |
| `malware/cnc`                    | `StixAdapterSpecialMixin.generate_malware_cnc` |
| `malware/config`                 | `MalwareMixin.generate_malware_config` |
| `hi/open_threats`                | `OsiHiMixin.generate_hi_open_threats` |
| `ioc/primary`                    | `OsiHiMixin.generate_ioc_primary` |
| `osi/git_repository`             | `OsiHiMixin.generate_osi_git_repository` |
| `osi/public_leak`                | `OsiHiMixin.generate_osi_public_leak` |
| `osi/vulnerability`              | `OsiHiMixin.generate_osi_vulnerability` |
| `attacks/ddos`                   | `StixAdapterSpecialMixin.generate_attacks_ddos` |
| `attacks/deface`                 | `StixAdapterSpecialMixin.generate_attacks_deface` |
| `attacks/phishing_group`         | `StixAdapterSpecialMixin.generate_attacks_phishing_group` |
| `attacks/phishing_kit`           | `StixAdapterSpecialMixin.generate_attacks_phishing_kit` |
| `darkweb/forums`                 | `StixAdapterSpecialMixin.generate_darkweb_forums` |

All other collections go through the default flow. Note: `apt/threat_actor` and `hi/threat_actor` stay on the **default flow** but now also emit a profile `Note` (injected in `SdoMixin.generate_stix_threat_actor`, gated by `_ACTOR_PROFILE_COLLECTIONS`).


## File logging

These extra settings control optional rotating-file logging in addition to stdout. Intended for **development** — production deployments should rely on `docker compose logs` or the OpenCTI work history.

| Environment variable | Default | Description |
|---|---|---|
| `TI_API__EXTRA_SETTINGS__ENABLE_FILE_LOGGING` | `false` | Writes a rotating `connector.log` inside the directory below. Mount the directory as a volume in `docker-compose.yml` to keep logs on the host. |
| `TI_API__EXTRA_SETTINGS__LOG_FILE_DIR` | `/opt/connector/logs` | Directory for the rotating log file. |
| `TI_API__EXTRA_SETTINGS__LOG_FILE_MAX_BYTES` | `10485760` | Maximum size in bytes of a single rotating log file. |
| `TI_API__EXTRA_SETTINGS__LOG_FILE_BACKUP_COUNT` | `5` | Number of rotated log files to keep. |


## Preserve manual labels — implementation scope

`preserve_manual_labels` is implemented by omitting `x_opencti_labels` in `models._common.BaseEntity._labels_kv()` (and the same pattern on the Discord/Messenger Note helper). It does not remove label-like text embedded in Note **markdown** (e.g. labels moved by `store_report_labels_in_note` or hunting-rule metadata rendered in chat Notes).

For threat reports with `store_report_labels_in_note: false`, the Report SDO may still carry an empty label list on update; combine with OpenCTI workflow testing if analysts rely on Report-level labels.
