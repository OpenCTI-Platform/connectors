# OpenCTI TAXII2 Connector
*Contact jonahbfeldman@gmail.com with questions*
## Description
This is a generic TAXII2 connector for [OpenCTI](https://github.com/OpenCTI-Platform/opencti). It automates the importing of collection(s) from a specified TAXII2 Server. Since TAXII2 servers natively serve data in STIX2.x, this connector does not do any conversion, and simply imports the STIX2 bundles as-is.


## Configuration
There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment). Since the `opencti` and `connector` options are the same as any other Connector, I'm only going to address the `taxii2` options

| Docker Env variable | config variable | Description
| --------------------|-----------------|------------
| TAXII2_DISCOVERY_URL   | discovery_url      | Discovery URL of TAXII2 Server
| TAXII2_USERNAME     | username        | Username credential to access TAXII Server
| TAXII2_PASSWORD     | password        | Password credential to access TAXII Server
| TAXII2_USE_TOKEN    | false           | Switch from using username and password to using a single token as authentication method.
| TAXII2_TOKEN        | token           | Token string from taxii server.
| TAXII2_USE_APIKEY   | false           | Switch from using username and password to using a key/value pair as authentication method.
| TAXII2_APIKEY_KEY   | apikey          | API key - name of the HTTP header.
| TAXII2_APIKEY_VALUE | value           | The secret value set as the header value.
| TAXII2_v21          | v2.1            | Boolean statement to determine if the TAXII Server is V2.0 or V2.1. Defaults to False (V2.0)
| TAXII2_COLLECTIONS  | collections     | Specify what TAXII Collections you want to poll. Syntax Detailed below
| TAXII2_INITIAL_HISTORY| initial_history| In hours, the "lookback" window for the intial Poll. This will limit the respones only to STIX2 objects that were added to the collection during the specified lookback time. In all subsequent polls, the `interval` configuration option is used to determine the lookback window
| TAXII2_INTERVAL     | interval        | In hours, the amount of time between each run of the connector. This option also sets the "lookback" window for all polls except the first one
| VERIFY_SSL          | verify_ssl      | Boolean statement on whether to require an SSL/TLS connection with the TAXII Server. Default to True
| TAXII2_CREATE_INDICATORS | true | Boolean statement on whether to create indicators
| TAXII2_CREATE_OBSERVABLES | true | Boolean statement on whether to create observables
| TAXII2_ADD_CUSTOM_LABEL | false | Boolean statement on whether to add custom label to all indicators. Default to False
| TAXII2_CUSTOM_LABEL | string | String to use for custom label. Requires TAXII2_ADD_CUSTOM_LABEL to be configured.
| TAXII2_FORCE_PATTERN_AS_NAME | false | Boolean statement on whether to force name to be contents of pattern. Default to False
| TAXII2_FORCE_MULTIPLE_PATTERN_NAME | string | String to use for indicators that contain multiple indicators in a single pattern. Requires TAXII2_FORCE_PATTERN_AS_NAME to be configured.
| TAXII2_STIX_CUSTOM_PROPERTY_TO_LABEL | false | Boolean statement on whether to create a label from a stix custom property.
| TAXII2_STIX_CUSTOM_PROPERTY | string | String to match the stix custom property you wish to add as a label e.g. x_foo. Requires TAXII2_STIX_CUSTOM_PROPERTY_TO_LABEL to be configured.

### Collections and API roots
TAXII 2.0 introduced a new concept into the TAXII standard called an "API Root." API Roots are logical groupings of TAXII Collections and Channels that allow for better organization and federated access. More information can be found in the [TAXII2 standard](https://docs.oasis-open.org/cti/taxii/v2.1/csprd01/taxii-v2.1-csprd01.pdf)

Unfortunately, the introduction of API Roots makes it more complicated to configure which Collections to poll from. To solve that issue, this connector uses dot notation to specify which collection(s) the user wants to poll, using the format `<API Root>.<Collection Name>`. So if you wanted to poll the `Enterprise ATT&CK` and `Mobile ATT&CK` collections in the API Root `stix` in MITRE's free TAXII2 server, your config variable would like

`stix.Enterprise ATT&CK,stix.Mobile ATT&CK`

Furthermore, this argument supports the use of `*` as a wildcard operator. To Poll all collections in the `STIX` API Root, you could use the syntax `stix.*` If you wanted to poll all collections in the server, you can use the syntax `*.*`

Finally, please note that the "title" of an API Root differs from it's pathing in a URL. For example, the title could be "Malware analysis" whereas the URL for an API Root could just be some_url/malware/. In the Collections parameters, please specify the URL path of an API Root, **not** its title

## Installation

Please refer to [these](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://filigran.notion.site/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://filigran.notion.site/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.


### Docker
Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t opencti-taxii2-import:latest`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`
### Manual/VM Deployment
Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 rf_feeds.py` command to start the connector
## Usage
After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`. However, if you would like to force an immediate poll of the TAXII Server, navigiate to Data management -> Connectors and Workers in the OpenCTI platform. Find the "Recorded Future Risk Lists" connector, and click on the refresh button to reset the connector's state and force a new poll of the Collections. Please note that this will be considered a "first" poll and thus will use the `TAXII2_INITIAL_HISTORY` variable

## Verification
To verify the connector is working, you can navigate to Data->Data Curation in the OpenCTI platform and see the new imported data there. For troubleshooting or additional verification, please view the Connector logs.

Tip: Creating a new user and API Token for the Connector can help you more easily track which STIX2 objects were created by the Connector.

## Misc.
This Connector can only import from a single TAXII2 server. To import from multiple servers, simply spin up multiple instances of this connector, with unique names and UUIDs
