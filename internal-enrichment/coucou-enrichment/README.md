# OpenCTI Coucou Enrichment Connector

Reference internal enrichment connector, not meant for release. It calls no external API.

When triggered on an IPv4 observable, it:

- sets the observable description to `coucou from enrichment`;
- adds the label `enriched` (existing labels are kept, the label is not duplicated on re-run);
- links it to the malware `supra coucou` with a `communicates-with` relationship (malware → IP).
  The malware and relationship ids are deterministic, so a re-run updates them instead of creating duplicates;
- creates a note `coucou super note` containing the observable, with the abstract `coucou note on <IP>`.
  Each IP gets its own note, and a re-run updates it instead of creating a duplicate.

When triggered on a domain name observable, it links it to 3 new IPv4 observables of random values,
with a `resolves-to` relationship from the domain name to each IP. The values are random, so each
run links 3 new IPs. The domain name itself is left unchanged.

It works by modifying the observable in the received bundle and sending the bundle back, so it is
also usable as a playbook step.

## Configuration

| Parameter          | config.yml                         | Environment variable              | Default             | Mandatory |
|--------------------|------------------------------------|-----------------------------------|---------------------|-----------|
| OpenCTI URL        | `opencti.url`                      | `OPENCTI_URL`                     |                     | Yes       |
| OpenCTI token      | `opencti.token`                    | `OPENCTI_TOKEN`                   |                     | Yes       |
| Connector ID       | `connector.id`                     | `CONNECTOR_ID`                    |                     | Yes       |
| Connector name     | `connector.name`                   | `CONNECTOR_NAME`                  | `Coucou Enrichment` | No        |
| Connector scope    | `connector.scope`                  | `CONNECTOR_SCOPE`                 | `IPv4-Addr,Domain-Name` | No    |
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
linked with "communicates with", and the note `coucou super note` lists the IP in its contained entities.
On a domain name, its **Knowledge** tab shows the 3 IPs linked with "resolves to".

## Tests

```shell
pip install -r tests/test-requirements.txt
python -m pytest tests
```
