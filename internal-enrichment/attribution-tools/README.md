# OpenCTI Attribution Tools Connector
The attribution tools connector developed by WithSecure provides incident attribution capability for OpenCTI. The tool is trained from OpenCTI intrusion-set data and can be launched as an enrichment for OpenCTI incidents.

The tool will assess the best matching intrusion-sets for the incident based on the collection of related objects within it.
## Configuration
|                Parameter               |                      Docker envvar                      | Value | Mandatory | Description |
|:---|:---|---|:---:|---|
| `opencti.opencti_url` | `OPENCTI_URL` | string | true | The URL of the OpenCTI platform. |
| `opencti.opencti_token` | `OPENCTI_TOKEN` | string | true | The default admin token configured in the OpenCTI platform parameters file. |
| `connector.id` | `CONNECTOR_ID` | uuidv4 string | true |  A valid arbitrary UUIDv4 that must be unique for this connector. |
| `connector.type` | `CONNECTOR_TYPE` | string=`INTERNAL_ENRICHMENT` | true | Must be `INTERNAL_ENRICHMENT` |
| `connector.name` | `CONNECTOR_NAME` | string | true | The name of the connector such as `attribution-tools` |
| `connector.scope` | `CONNECTOR_SCOPE` | string=`Incident` | true | Must be `Incident` |
| `connector.auto` | `CONNECTOR_AUTO` | boolean | true | Whether new Incident entities should be automatically enriched. Either `true` or `false`. |
| `connector.log_level` | `CONNECTOR_LOG_LEVEL` | string | true | The log level for this connector, could be debug, info, warn or error (less verbose). |
| `attributiontools.model_training_cron_utc`                | `ATTRIBUTIONTOOLS_MODEL_TRAINING_CRON_UTC`          |   A valid cron expression such as: `"0 0 * * *"`   | true      |A cron expression which dictates the model retraining schedule. The schedule uses UTC. |
| `attributiontools.n_training_query_threads`               | `ATTRIBUTIONTOOLS_N_TRAINING_QUERY_THREADS`       |    An integer `> 0`    | true      |The number of threads used when fetching training data from the OpenCTI platform in parallel.|
| `attributiontools.default_relation_confidence`            | `ATTRIBUTIONTOOLS_DEFAULT_RELATION_CONFIDENCE`     | An integer between `[0,100]` | true      |The confidence number for automatically created relations.|
| `attributiontools.automatic_relation_creation`            | `ATTRIBUTIONTOOLS_AUTOMATIC_RELATION_CREATION`     | `boolean` | true      |A boolean which dictates whether relations should be created automatically or not.|
| `attributiontools.relation_creation_probability_treshold` | `ATTRIBUTIONTOOLS_RELATION_CREATION_PROBABILITY_TRESHOLD` | A decimal number between `[0,1]`| true      |The minimum probability of a prediction that is considered good enough to warrant automatic attribution relation creation. |
| `attributiontools.creator_org_identity_id`                | `ATTRIBUTIONTOOLS_CREATOR_ORG_IDENTITY_ID`      | A Stix Standard ID | true      |The `standard_id` (Stix ID) of the identity object that the connector should set as creator when creating relations or note objects. This should be the ID of your organization object.|

## Model Persistence
In order to save the model (actually just training data) and have it persist over container restarts, persistent storage needs to be mounted to the container. A storage volume should be mounted to the path `/opt/opencti-connector-attribution-tools/data/training_data` inside the container. The connector will store 3 of the latest models that it has used and deletes the older ones once new ones are fetched and trained.

The connector will initiate a training data fetch sequence on startup if it does not find a pre-existing model within the `training_data` directory.

### CC-Driver
This package was developed as a part of [CC-Driver project](https://www.ccdriver-h2020.com/), funded by the European Union’s Horizon 2020 Research and Innovation Programme under Grant Agreement No. 883543