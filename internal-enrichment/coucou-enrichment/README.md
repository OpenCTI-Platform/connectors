# OpenCTI Coucou Enrichment Connector

Reference internal enrichment connector, not meant for release. It calls no external API.

When triggered on an IPv4 observable, it:

- sets the observable description to `coucou from enrichment`;
- adds the label `enriched` (existing labels are kept, the label is not duplicated on re-run);
- links it to the malware `supra coucou` with a `communicates-with` relationship (malware → IP).
  The malware and relationship ids are deterministic, so a re-run updates them instead of creating duplicates.

It works by modifying the observable in the received bundle and sending the bundle back, so it is
also usable as a playbook step.

## Configuration

| Parameter          | config.yml                         | Environment variable              | Default             | Mandatory |
|--------------------|------------------------------------|-----------------------------------|---------------------|-----------|
| OpenCTI URL        | `opencti.url`                      | `OPENCTI_URL`                     |                     | Yes       |
| OpenCTI token      | `opencti.token`                    | `OPENCTI_TOKEN`                   |                     | Yes       |
| Connector ID       | `connector.id`                     | `CONNECTOR_ID`                    |                     | Yes       |
| Connector name     | `connector.name`                   | `CONNECTOR_NAME`                  | `Coucou Enrichment` | No        |
| Connector scope    | `connector.scope`                  | `CONNECTOR_SCOPE`                 | `IPv4-Addr`         | No        |
| Auto enrichment    | `connector.auto`                   | `CONNECTOR_AUTO`                  | `false`             | No        |
| Log level          | `connector.log_level`              | `CONNECTOR_LOG_LEVEL`             | `error`             | No        |
| Max TLP level      | `coucou_enrichment.max_tlp_level`  | `COUCOU_ENRICHMENT_MAX_TLP_LEVEL` | `amber+strict`      | No        |

## Run locally

```shell
cp config.yml.sample config.yml   # then fill in the OpenCTI URL/token and a UUIDv4 connector id
pip install -r src/requirements.txt
python src/main.py
```

Then in OpenCTI, open an IPv4 observable, click **Enrichment** and run **Coucou Enrichment**.
The IP gets the description and the label, and its **Knowledge** tab shows the `supra coucou` malware
linked with "communicates with".

## Tests

```shell
pip install -r tests/test-requirements.txt
python -m pytest tests
```
