# RST Threat Feed Connector for OpenCTI by RST Cloud

The **RST Threat Feed Connector** integrates RST Cloud threat intelligence feeds into OpenCTI. This connector imports Indicators (IP, Domain, URL, Hash) with their relationships to malware, TTPs, tools, threat groups, sectors, CVE, and other objects. This enhances the capability of OpenCTI by providing actionable threat intelligence data, allowing users to make informed decisions based on the latest information from ([RST Threat Feed](https://www.rstcloud.com/rst-threat-feed/)).

The feed delivers approximately 200K indicators daily, with the ability to filter by score. Each indicator has an individual score, allowing OpenCTI to keep indicator scores updated when inactive indicators become active again (c2 went offline, a domain had no A DNS entry, a phishing website was not active, etc). Scoring is aligned with OpenCTI scoring algorithms and allows you to set a custom decay speed in your platform.

![RST Cloud and OpenCTI Scoring and Decay algorithms integration](scoring.png "RST Cloud and OpenCTI Scoring and Decay algorithms integration")

Data scored between 0 and 20 is typically considered noisy. Data with a score of 45+ is used in SIEMs for real-time detection, while data scored 55+ is used for active blocking. However, everyone can set their own thresholds to find the optimal balance for their needs.

Data can be retrieved every hour or daily, depending on the use case. The feed includes multiple threat categories.
| Examples of Threat Categories |              |            |            |
| ----------------------------- | ------------ | ---------- | ---------- |
| backdoor                      | banker       | bootkit    | botnet     |
| c2                            | cryptomining | downloader | drainer    |
| dropper                       | fraud        | keylogger  | malware    |
| phishing                      | proxy        | raas       | ransomware |
| rat                           | rootkit      | scam       | scan       |
| screenshotter                 | shellprobe   | spam       | spyware    |
| stealer                       | tor_exit     | trojan     | vpn        |
| vulndriver                    | webattack    | wiper      |            |

## Key Features

- **Lots of contextual information**: Indicators come with additional info including threat category, malware name, threat actor names, tools and frameworks, TTPs, CVE, industry tags, reference to the source of the indicator and more.
- **OpenCTI Integration**: Seamlessly integrates the fetched data into OpenCTI's database.
- **Customizable Data Ingestion**: Users can specify a score threshold to control what indicators are being imported and also configure to import only new indicators.
- **Customizable Detection Flag**: Users can specify per each indicator type what is the score threshold to mark an Indicator as ready for detection (x_opencti_detection=true|false)

This connector empowers users with an expanded and in-depth insight into the cyber threat landscape by tapping into the detailed threat intelligence delivered by RST Cloud.

## Requirements
- OpenCTI Platform version 6.8.12 or higher (connectors-sdk / verified connector standards).
- An API Key for accessing RST Cloud (trial@rstcloud.net).

## Recommended connectors
This connector is aligned with data populated by common OpenCTI connectors. We recommend to install the following connectors alongside with RST Threat Feed Connector:
 - MITRE Datasets (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/mitre)
 - OpenCTI Datasets (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/opencti)
 - CISA Known Exploited Vulnerabilities (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cisa-known-exploited-vulnerabilities)
 - **RST Threat Library** is an optional, paid add-on for RST Threat Feed customers who want access to a comprehensive threat taxonomy and alias mapping (https://rstcloud.com/rst-threat-library/) 

 By default, the RST Threat Feed connector maps threat names from the RST codename taxonomy to format that is used public repositories (MITRE, Malpedia) where possible. However, many threat names are not present in public taxonomies. With RST Threat Library, you get:
  - All aliases of the same threat name, not just the primary code.
  - Unified threat profiles, enabling you to correlate and consume intelligence from multiple sources (e.g., MITRE, Recorded Future, Microsoft, CrowdStrike, and many more) under a single taxonomy.
  - Enhanced context and mapping for threat actors, malware, campaigns, tools, TTPs, and vulnerabilities.

**Note:**  
The RST Threat Feed connector includes basic mapping to public taxonomies for free. RST Threat Library is a separate subscription for customers who need full aliasing and advanced threat profile mapping. For more information or to request access, contact [trial@rstcloud.net](mailto:trial@rstcloud.net).


## Configuration

Configuring the connector is straightforward. The minimal setup requires entering the RST Cloud API key and specifying the OpenCTI connection settings. Below is the full list of parameters you can configure:

| Parameter                                          | Docker envvar                                | Mandatory | Description                                                                                                                                                                                                  |
| -------------------------------------------------- | -------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| OpenCTI URL                                        | `OPENCTI_URL`                                | Yes       | The URL of the OpenCTI platform.                                                                                                                                                                             |
| OpenCTI Token                                      | `OPENCTI_TOKEN`                              | Yes       | Token used to call OpenCTI. With auto-create on, this is an admin token used only to create the service account. With auto-create off, this must be the API token of the `[C]` user that should own the import. |
| Auto-create service account                       | `CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT`      | No        | Default: `false`. `true` creates or reuses a Connectors-group user named `[C] <CONNECTOR_NAME>` and imports as that user. See [Service accounts](#service-accounts).                                          |
| Service account confidence                         | `CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT_CONFIDENCE_LEVEL` | No | Max confidence for the auto-created service account. Default: `50`.                                                                                                                                          |
| Connector ID                                       | `CONNECTOR_ID`                               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                                                                                    |
| Connector Name                                     | `CONNECTOR_NAME`                             | Yes       | Name of the connector. For example: `RST Threat Feed` or `RST Threat Feed - Domain`.                                                                                                                         |
| Connector Scope                                    | `CONNECTOR_SCOPE`                            | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. E.g. application/json                                                                                               |
| Log Level                                          | `CONNECTOR_LOG_LEVEL`                        | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                                                                                       |
| Duration Period                                    | `CONNECTOR_DURATION_PERIOD`                  | No        | ISO-8601 interval between runs (default `PT24H`). Replaces legacy `RST_THREAT_FEED_INTERVAL`.                                                                                                                |
| Queue Threshold                                    | `CONNECTOR_QUEUE_THRESHOLD`                  | No        | Max RabbitMQ queue size in MB before pausing ingestion (default `500`).                                                                                                                                      |
| Update Existing Data                               | `CONNECTOR_UPDATE_EXISTING_DATA`             | No        | Whether to update existing STIX objects (default `true`).                                                                                                                                                    |
| RST Threat Feed API Key                            | `RST_THREAT_FEED_APIKEY`                     | Yes       | Your API Key for accessing RST Cloud.                                                                                                                                                                        |
| RST Threat Feed Base URL                           | `RST_THREAT_FEED_BASEURL`                    | No        | By default, use https://api.rstcloud.net/v1. In some cases, you may want to use a local API endpoint                                                                                                         |
| HTTP / HTTPS proxy (standard)                      | `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`    | No        | Honored for feed downloads (and MITRE mapping fetch). Use these in proxy-only networks.                                                                                                                      |
| Explicit feed proxy override                       | `RST_THREAT_FEED_PROXY`                      | No        | Optional connector-specific proxy URL. When set, overrides env proxies for feed downloads only. When empty, standard `HTTP(S)_PROXY` is used.                                                              |
| SSL Verification                                   | `RST_THREAT_FEED_SSL_VERIFY`                 | No        | Default: `true`. If set to `false`, SSL verification is disabled (use with caution, sometimes needed when SSL inspection is enabled).                                                                        |
| Enable IP Threat Feed                              | `RST_THREAT_FEED_IP`                         | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for IP addresses.                                                                                                               |
| Enable Domain Threat Feed                          | `RST_THREAT_FEED_DOMAIN`                     | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for domains.                                                                                                                    |
| Enable URL Threat Feed                             | `RST_THREAT_FEED_URL`                        | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for URLs.                                                                                                                       |
| Enable Hash Threat Feed                            | `RST_THREAT_FEED_HASH`                       | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for file hashes (MD5, SHA1, SHA256).                                                                                            |
| Threat Feed Data Fetch Interval                    | `RST_THREAT_FEED_LATEST`                    | No        | Default: `day`. Defines how often the latest threat feed data is fetched. Options: `1h`, `4h`, `12h`, or `day`.                                                                                              |
| RST Threat Feed Connection Timeout                 | `RST_THREAT_FEED_CONTIMEOUT`                 | No        | Connection timeout to the API. Default (sec): `30`                                                                                                                                                           |
| RST Threat Feed Read Timeout                       | `RST_THREAT_FEED_READTIMEOUT`                | No        | Read timeout for each feed. Our API redirects the connector to download data from AWS S3. If the connector is unable to fetch the feed in time, increase the read timeout. Default (sec): `120`              |
| RST Threat Feed Download Retry Count               | `RST_THREAT_FEED_RETRY`                      | No        | Default (attempts): `2` . Defines the number of attempts to download the feed.                                                                                                                               |
| RST Threat Feed Max Retries                        | `RST_THREAT_FEED_MAX_RETRIES`                | No        | Maximum number of retry attempts for connection issues when sending the data to OpenCTI. Default: `3`                                                                                                        |
| RST Threat Feed Retry Delay                        | `RST_THREAT_FEED_RETRY_DELAY`                | No        | Initial delay in seconds before retrying a failed connection to OpenCTI. Default: `10`                                                                                                                       |
| RST Threat Feed Retry Backoff Multiplier           | `RST_THREAT_FEED_RETRY_BACKOFF_MULTIPLIER`   | No        | Multiplier applied to the retry delay for exponential backoff between retries to send data to OpenCTI. For example, with a delay of 10 and multiplier 2.0, delays will be 10, 20, 40 seconds. Default: `2.0` |
| RST Threat Feed Minimal Score to Import            | `RST_THREAT_FEED_MIN_SCORE_IMPORT`           | No        | Import only indicators with risk score more than X. The objects that are related to these indicators will also be imported with corresponding relations. Default (score): `20`                               |
| RST Threat Feed Minimum Score for IP Detection     | `RST_THREAT_FEED_MIN_SCORE_DETECTION_IP`     | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                                       |
| RST Threat Feed Minimum Score for Domain Detection | `RST_THREAT_FEED_MIN_SCORE_DETECTION_DOMAIN` | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                                       |
| RST Threat Feed Minimum Score for URL Detection    | `RST_THREAT_FEED_MIN_SCORE_DETECTION_URL`    | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                                       |
| RST Threat Feed Minimum Score for Hash Detection   | `RST_THREAT_FEED_MIN_SCORE_DETECTION_HASH`   | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                                       |
| Import only New Indicators                         | `RST_THREAT_FEED_ONLY_NEW`                   | No        | Defines if you only want to import indicators with recent "First Seen" or also want to re-import changes to the indicators with "Last Seen" >= yesterday. Default: `true`                                    |
| Import only Attributed Indicators                  | `RST_THREAT_FEED_ONLY_ATTRIBUTED`            | No        | Defines if you only want to import indicators that are attributed to known threats. Default: `false`                                                                                                         |
| Keep named vulnerabilities                         | `RST_THREAT_FEED_KEEP_NAMED_VULNS`           | No        | Defines if the connector needs to create named vulnerabilities like ldapnightmare as separate objects or it should just use CVE numbers. Default: `true`                                                     |
| Create custom TTPs                                 | `RST_THREAT_FEED_CREATE_CUSTOM_TTPS`         | No        | A user can select if `attack-pattern` objects with custom names that are still not present in the MITRE ATT&CK framework are to be created or not. Options are `true`, `false`. Default: `true`              |
| Create MITRE TTPs                                  | `RST_THREAT_FEED_CREATE_MITRE_TTPS`          | No        | Create Attack-Pattern objects for MITRE TTP IDs. Can produce many relationships. Default: `false`                                                                                                            |
| Create network-traffic patterns                    | `RST_THREAT_FEED_CREATE_NETWORK_TRAFFIC_PATTERNS` | No   | How to model IP indicators that list ports. `skip` (default): ipv4-addr indicator only. `add`: also create one network-traffic indicator that ORs every listed port. `replace`: network-traffic indicator only when ports are present; IPs without ports stay ipv4-addr indicators. Those indicators use the IP detection score threshold. |

Each feed is sent as one bundle, ordered **author → marking definitions → entities (including sector identities) → relationships**, with `cleanup_inconsistent_bundle=True`. Failed works are marked `in_error` before retry so they do not stack in OpenCTI.

## Service accounts

Indicators are stored as the OpenCTI user that owns `OPENCTI_TOKEN` after startup. Auto-create is how that user becomes `[C] RST Threat Feed - Domain` (or the other connector names) instead of the admin account.

In OpenCTI, open **Settings → Security → Users** and look for a user named `[C]` plus the connector's `CONNECTOR_NAME`. With `docker-compose-multiple-connectors.yml` those users are:

| Compose service | User to look for |
| --- | --- |
| `connector-rst-threat-feed-hourly` | `[C] RST Threat Feed - Hourly` |
| `connector-rst-threat-feed-ip` | `[C] RST Threat Feed - IP` |
| `connector-rst-threat-feed-domain` | `[C] RST Threat Feed - Domain` |
| `connector-rst-threat-feed-url` | `[C] RST Threat Feed - URL` |
| `connector-rst-threat-feed-hash` | `[C] RST Threat Feed - Hash` |

A single shared `OPENCTI_TOKEN` in `.env` is one account. Each service that must import as its own `[C]` user needs its own token variable.

### No service account yet

1. Set `CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT=true`.
2. Set `OPENCTI_TOKEN` to an admin token that can create users and API tokens.
3. Start the connector. On first start it creates the `[C]` user in the Connectors group, creates an API token, and imports as that user.

If the container then restarts and the log shows `Create token for user` followed by `AUTH_REQUIRED` / HTTP 401, the account may already exist from that attempt. Follow the steps below. Do not delete the connector to retry auto-create; startup fails on the new token, not because the user is missing.

### Service account already exists

1. Leave the `[C]` user in place.
2. On that user, create one API token and copy it once. OpenCTI does not show the token again.
3. Put it in the env file under a name used only by that service, for example `RST_THREAT_FEED_DOMAIN_OPENCTI_TOKEN`.
4. In that service, set `OPENCTI_TOKEN` to that variable and set `CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT=false`.

```yaml
- OPENCTI_TOKEN=${RST_THREAT_FEED_DOMAIN_OPENCTI_TOKEN}
- CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT=false
```

Auto-create left on will revoke the connector token and issue a new one at every start. Turn it off when that new token is rejected and the container stays in `Restarting` with `AUTH_REQUIRED`. With it off, the service keeps importing as the `[C]` user whose token you set.

