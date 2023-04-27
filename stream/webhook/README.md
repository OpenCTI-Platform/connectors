# Webhook Connector

This connector allows for GraphQL queries to OpenCTI to trigger webhook calls. To test out GraphQL queries, use the [GraphQL Playground](https://filigran.notion.site/GraphQL-API-cfe267386c66492eb73924ef059d6d59) at `http://<your_opencti_instance>/graphql`

## Example Configurations

### Make a webhook calls to localhost server with...
#### a work process's connector name and associated messages when a work process completes
| Key                                       | Value |
| ----------------------------------------- | ----- |
| WEBHOOK_GRAPHQL_QUERY                     | `{{works(filters:[{{key:completed_time,operator:"gt",values:["LAST_POLL_TIME"]}}]){{edges{{node{{connector{{name}}messages{{message}}}}}}}}}}` |
| WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION    | `['data']['works']['edges']` |
| WEBHOOK_URL                               | `http://localhost?connector_name={item['node']['connector']['name']}&messages={item['node']['messages']}` |

#### the OpenCTI event UUID when a work process that has been processing for over 3 minutes completes
Successful completion:
| Key                                       | Value |
| ----------------------------------------- | ----- |
| WEBHOOK_GRAPHQL_QUERY                     | `{{works(filters:[{{key:completed_time,operator:"gt",values:["LAST_POLL_TIME"]}},{{key:received_time,operator:"lt",values:["{LAST_POLL_TIME-60000*3}"]}}],filterMode:and){{edges{{node{{event_source_id}}}}}}}}` |
| WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION    | `['data']['works']['edges']` |
| WEBHOOK_URL                               | `http://localhost?event_id={item['node']['event_source_id']}` |
Completion (success or failure):
| Key                                       | Value |
| ----------------------------------------- | ----- |
| WEBHOOK_GRAPHQL_QUERY                     | `{{works(filters:[{{key:processed_time,operator:"gt",values:["LAST_POLL_TIME"]}},{{key:received_time,operator:"lt",values:["{LAST_POLL_TIME-60000*3}"]}}],filterMode:and){{edges{{node{{event_source_id}}}}}}}}` |
| WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION    | `['data']['works']['edges']` |
| WEBHOOK_URL                               | `http://localhost?event_id={item['node']['event_source_id']}` |

#### a new user's email when the new user is added to the system
| Key                                       | Value |
| ----------------------------------------- | ----- |
| WEBHOOK_GRAPHQL_QUERY                     | `{{users(filters:[{{key:created_at,operator:"gt",values:["LAST_POLL_TIME"]}}]){{edges{{node{{user_email}}}}}}}}` |
| WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION    | `['data']['users']['edges']` |
| WEBHOOK_URL                               | `http://localhost?email={item['node']['user_email']}` |

#### a specific threat actor's confidence level when the threat actor is updated
| Key                                       | Value |
| ----------------------------------------- | ----- |
| WEBHOOK_GRAPHQL_QUERY                     | `{{threatActors(filters:[{{key:updated_at,operator:"gt",values:["LAST_POLL_TIME"]}}],search:"<unique threat actor identifier>"){{edges{{node{{confidence}}}}}}}}` |
| WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION    | `['data']['threatActors']['edges']` |
| WEBHOOK_URL                               | `http://localhost?confidence={item['node']['confidence']}` |

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

## Installation

### Requirements

- OpenCTI Platform >= 5.5.0

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform. |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file. |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector. |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `Template_Type` (this is the connector type). |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Option `Template` |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Template Scope (MIME Type or Stix Object) |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4). |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `webhook_graphql_polling_interval`   | `WEBHOOK_GRAPHQL_POLLING_INTERVAL`  | Yes          | In seconds. How often the connector polls the GraphQL API to look for changes. |
| `webhook_graphql_query`              | `WEBHOOK_GRAPHQL_QUERY`             | Yes          | The query made to the GraphQL endpoint. The GraphQL query should include a time filter aspect to it to ensure that results coming back are only new since the last poll. The variable `LAST_POLL_TIME` in the query string will be replaced with the time of the last successfully executed poll in epoch milliseconds. The query is evaluated as a python format string before being queried so that complex logic can be included in the query; because of this, use single curly braces ( `{` ) for python interpretation and double curly braces for GraphQL interpretation ( `{{` ). GraphQL also requires double quotes ( `"` ) be used for declarations. |
| `webhook_graphql_returned_data_location` | `WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION` | Yes | Where to look for data in a successfully returned query. If the data does not exist or returns an empty array/string, the connector will ignore it. Use single quotes ( `'` ) for string declarations. |
| `webhook_url`                        | `WEBHOOK_URL`                       | Yes          | The URL to call when returned data is successfully found. The connector will iterate through a returned data array or single piece of data from the WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION variable with callable data variable named `item`. The url is evaluated as a python format string before being called so that complex logic can be included in the call; because of this, use single curly braces ( `{` ) for python interpretation and double curly braces ( `{{` ) for a single curly brace literal ( `{` ). Use single quotes ( `'` ) for string declarations. |
| `webhook_unsuccessful_retry_interval` | `WEBHOOK_UNSUCCESSFUL_RETRY_INTERVAL` | Yes       | In seconds. If the webhook call is unsuccessful, retry after this many seconds |
| `webhook_unsuccessful_retry_attempts` | `WEBHOOK_UNSUCCESSFUL_RETRY_ATTEMPTS` | Yes       | If the webhook call is unsuccessful, retry no more than this many times. |
| `webhook_ignore_duplicates`          | `WEBHOOK_IGNORE_DUPLICATES`         | Yes          | `true` or `false` If duplicate webhook calls exist in the poll, only call each once. |

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->

