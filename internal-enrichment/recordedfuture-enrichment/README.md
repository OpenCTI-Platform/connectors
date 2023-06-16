# OpenCTI Recorded Future Feeds Connector
*Contact jonah.feldman@recordedfuture.com with questions*
## Description

This connector enriches individual OpenCTI Observables with Recorded Future Information. Currently enrichment of IP Address (ipv4 and ipv6), URLs, Domains, and Hashes (MD5, SHA1, and SHA256) is supported.

## Data Model
Each enrichment pulls down an Indicator's Recorded Future Risk Score, any triggered Risk Rules, and Strings of Evidence to justify a rule being triggered. Their equivalents in OpenCTI's STIX2 model is

- Indicator -> Indicator
- Risk Score -> Note attached to Indicator
- Risk Rule -> Attack Pattern, the relationship defined as Indicator "indicates" Attack Pattern
- Evidence String -> Note Attached to Indicator

Also note that the Indicator's STIX2 confidence field is set to the Risk Score. However, at this time OpenCTI does not automatically import the STIX2 confidence field as the OpenCTI score, it's logical equivalent


## Installation

Please refer to [these](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://www.notion.so/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://www.notion.so/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.

### Docker
Build a Docker Image using the provided `Dockerfile`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`
### Manual/VM Deployment
Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. The `id` attribute of the `connector` should be a freshly generated UUID. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 rf_enrichment.py` command to start the connector


## Usage
To enrich an observable, first click on it in the Signatures tab of the OpenCTI platform (or navigate to an observable another way). Click on either the Linked Observables or Knowledge Tab.  In the "Enrichment Connectors", locate the Recorded Future Enrichment connector. The connector may automatically begin to enrich the observable. If not (or if you want to re-enrich the indicator), click on the refresh button next to the indicator to enrich
## Verification
After enriching the indicator, click on the Overview tab. You should now see a series of Notes from Recorded Future containing Evidence Strings and the Risk Score. Click on an indicator under the "Indicators composed with this observable" header (one should be created if it did not exist before). This indicator will have the same notes, and you should also see relationships with a number of TTPs/Attack Patterns which represent the Recorded Future Risk Rules



