# Sekoia CTI Connector

## Objective
Collect Sekoia.io CTI data in an existing self-managed OpenCTI instance for any operational purpose (such as CTI aggregation, dissemination, hunting...).

## Prerequisites
- An operational OpenCTI instance with administrator privileges
- An active Sekoia.io subscription. It could be a CTI-only subscription ([Sekoia Intelligence](https://www.sekoia.io/en/product/cti/)) or a XDR/SOC platform subscription ([Sekoia Defend](https://www.sekoia.io/en/product/xdr/)) which natively includes Sekoia CTI
- [Creating a Sekoia.io API KEY](https://docs.sekoia.io/getting_started/manage_api_keys/) with the "View intelligence" premission (at least)

## Configuration

1. Add the following code to the end of docker-compose.yml file in the OpenCTI docker repository

```
connector-sekoia:
    image: opencti/connector-sekoia:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=SEKOIA.IO
      - CONNECTOR_SCOPE=identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report,location,vulnerability,indicator,campaign,infrastructure,relationship
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=error
      - SEKOIA_BASE_URL=ChangeMe # by default 'https://api.sekoia.io'
      - SEKOIA_API_KEY=<Replace_by_Sekoia_API_key>
      - SEKOIA_COLLECTION=d6092c37-d8d7-45c3-8aff-c4dc26030608
      - SEKOIA_START_DATE=2022-01-01    # Optional, the date to start consuming data from. Maybe in the formats YYYY-MM-DD or YYYY-MM-DDT00:00:00
      - SEKOIA_CREATE_OBSERVABLES=true  # Create observables from indicators
    restart: always
    depends_on:
      - opencti

volumes:
  esdata:
  s3data:
  redisdata:
  amqpdata:
```

2. Replace the following parameters:

- CONNECTOR_ID = Replace_by_email or an UUID4
- CONNECTOR_SCOPE = identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report,location,vulnerability,indicator,campaign,infrastructure,relationship => Sekoia Intelligence elements set to be exported in OpenCTI that can be chosen from this list
- SEKOIA_API_KEY = Sekoia API key with CTI_Permissions
- SEKOIA_START_DATE = e.g. 2023-05-01

3. Build and launch Sekoia connector

- Build `docker-compose pull connector-sekoia`
- Run `docker-compose up -d connector-sekoia`

Note:Sekoia connector should be named **connector-sekoia** as described in the previous section. To check all connectors available and set in the server, type `docker-compose ps`.

4. Check if Sekoia connector is running

`docker-compose ps connector-sekoia`

## Sekoia Intelligence in OpenCTI

1. First of all, check if the connector is running and up to date. Go to Sekoia connector Data > Ingestion > Connectors > Sekoia.io
On this page, you can find the following information:
- Update date: Last update date of the connector in OpenCTI
- Status: Status of the connector in OpenCTI
- Perimeter: Sekoia Intelligence feed set for import in docker-compose.yml file under CONNECTOR_SCOPE
- Last cursor: SEKOIA_START_DATE set in docker-compose.yml file in base64 format
![image](https://github.com/OpenCTI-Platform/connectors/assets/104078945/6b01a85d-464e-4e6c-a2f5-86bd6d9d6cda)

2. Navigate the Sekoia Intelligence Feed
Here are the elements of the Sekoia feed that can be found on OpenCTI after export:

| **OpenCTI**   |	**Sekoia.io**  |
|---------------|----------------|
| Reports       | Threat-reports |
| Observables   | Sightings      |
| Malwares	    | Malwares       |
| Intrusion Set	| Intrusion-sets |
| Indicators	  | Indicators     |

## Troubleshoot

| Issue	                   | Action	                   | Linux command      |
|--------------------------|---------------------------|--------------------|
| Space disk full	         | check the logs	           | docker logs        |
| Conflict with containers | list containers on server | docker-compose ps  |

## Other resources

- [OpenCTI documentation - Connectors](https://docs.opencti.io/latest/deployment/connectors/)
