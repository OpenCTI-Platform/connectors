# OpenCTI connector for Bitdefender Intelligence Feeds

This connector imports configured itdefender Threat Intelligence feeds (file hashes, URLs, IP addresses) into OpenCTI.

## Installation

### Threat Intelligence License

In order to use this connector you must first obtain the Threat Intelligence license from Bitdefender. This license is different from the license to a Bitdefender Endponint Security product you might have.

Bitdefender Threat Intelligence feeds are Bitdefender's own product based on the data seen by Bitdefender protected endpoints and servers, by honeypots and the data coming from in-labs malware analysis, Sandbox detonations and other sources. All feeds contain both the information about the actual threat. Some entries also contain the related indicators information (such as other files, IPs or domain names associated with the threat). Some entries also contain the location, victim and actor attribution information.

The following feeds are available:

- `file`: file Reputation feed with the entries containing the hashes of malicious files;
- `ip`: IP reputation feed with the entries containing the malicious IPv4 and IPv6 addresses;
- `web`: Domain/URL reputation feed with the entries containing the malicious URLs and domains;

Your license can give you access to one or multiple feeds. To obtain such license, please visit the following link: https://www.bitdefender.com/en-us/oem/contact/threat-intelligence-solutions-contact?icid=ref%7Cb%7Copencti%7Coem-trial&campaign=2026_Aug_WW_B2B2B_FCM_Partner_Generated_Cybersecurity_at_Scale_OpenCTI

### Configuration

#### Required variables

Besides the standard OpenCTI connector related variables, the following configuration options must be defined:

| Env. Variable       | Config Var. |  Description |
|---------------------|-------------|--------------|
| BITDEFENDER_API_KEY | api_key     | A string, Threat Intelligence license key from Bitdefender |
| BITDEFENDER_FEEDS   | feeds       | Comma-separated list of Threat Intel feeds to import. Supported values are `file` (file reputation feed), `web` (Web reputation feed) and `ip` (IP reputation feed). Feeds must be available in your license |

### Optional variables

The following configuration variables are optional.

| Env. Variable       | Config Var. |  Description |
|---------------------|-------------|--------------|
| `BITDEFENDER_MIN_CONFIDENCE` | min_confidence | Number; defines the minimal confidence level (1-99) for the feed entry to be imported. Default is 75. |
| `BITDEFENDER_MIN_SEVERITY`   | min_severity | Number; defines the minimal severity level (1-99) for the feed entry to be imported. Default is 1 |
| `BITDEFENDER_INCLUDE_REVOKED` | include_revoked | String, defines whether to include the indicators for revoked entries. Can be "true" (include), "false" (exclude those; default), and "only (only import those entries) |
| `BITDEFENDER_EXCLUDE_RELATED_INDICATORS` | exclude_related_indicators | Boolean, defines whether to exclude the related indicators (which provide relationship data). By default those are included |
| `BITDEFENDER_INCLUDE_SUSPICIOUS` | include_suspicious | String, defines whether to include the entries which are marked as suspicious. Can be "true" (include), "false" (exclude those; default), and "only (only import those entries) |

The settings `BITDEFENDER_MIN_CONFIDENCE` and `BITDEFENDER_MIN_SEVERITY` work together; an indicator must match both minimum levels to be imported. Both have values ranged from 1 (minimal confidence) to 99 (maximum confidence).

## Manual Docker deployment 

Until the source is merged into OpenCTI connectors, you can run the connector from a separate source directory:

- Copy the directory content into the machine you're running OpenCTI on (we assume `/home/opencti/connector-bitdefender` in this example);

- Add the following entry into your opencti docker-compose.yml into the services section, following the `connector-mitre` section at the same ident level as connector-mitre:

```` {.yml}
  connector-bitdefender:
    image: python:3.12
    volumes:
      - /home/opencti/connector-bitdefender/:/connector-bitdefender
    depends_on:
      opencti:
        condition: service_healthy
    restart: always
    working_dir: /connector-bitdefender
    command: ["bash", "entrypoint.sh"]
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=9aae46c5-9e5a-4379-9f1b-49202674de3f
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=bitdefender-import-feed
      - CONNECTOR_SCOPE=indicator,file,ipv4-addr
      - CONNECTOR_LOG_LEVEL=info
      - BITDEFENDER_FEED_API_KEY=<REPLACE ME>
      - BITDEFENDER_FEED_INTERVAL_MINUTES=60
      - BITDEFENDER_FEEDS_LIST=file web ip
````

and start the Docker:
        
```bash
docker compose up --build
```

## Authorship and Code License

The connector source code is copyrighted (C) 2026 by Bitdefender and is licensed under GNU AGPLv3 license.
