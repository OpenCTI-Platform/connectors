# OpenCTI Zscaler Connector

This connector integrates **OpenCTI** threat intelligence into the **Zscaler** environment.

## Overview

- **Scope**  
  - The connector focuses on indicators of type `domain-name`.
  - It listens to events from the OpenCTI stream (creation and deletion of STIX indicators).
  - Whenever a domain indicator is created or deleted in OpenCTI, the connector updates the Zscaler configuration accordingly.

- **Key Features**  
  1. **Authentication and Classification Retrieval**:  
     The connector authenticates with the Zscaler API using a username, password, and API key. It can also query Zscaler to retrieve the classification of a domain (e.g., the labels/categories Zscaler applies to this domain).  
  2. **Blacklist Management**:  
     By default, the connector manages the `BLACK_LIST_DYNDNS` category in Zscaler:
     - **Indicator Creation**: If the domain is not already in the blacklist, the connector adds it to `BLACK_LIST_DYNDNS` and activates the changes to make them effective.  
     - **Indicator Deletion**: If the domain exists in `BLACK_LIST_DYNDNS`, the connector can remove it from this category and activate the changes.  
  3. **Customizing the Category**:  
     You can change the category name (e.g., `Black-list` or any other category name you use) in the code or configuration variables to manage the list that best suits your needs.  
  4. **Specific Event Handling**:  
     The connector only processes events of type `create` and `delete` (no updates).

## Installation

### Requirements

- **OpenCTI Platform >= 6.0.0**

### Configuration

| Parameter                               | Docker Env Variable                             | Mandatory  | Description                                                                                     |
|-----------------------------------------|-------------------------------------------------|------------|-------------------------------------------------------------------------------------------------|
| `OPENCTI_URL`                           | `OPENCTI_URL`                                   | Yes        | The URL of the OpenCTI platform.                                                               |
| `OPENCTI_TOKEN`                         | `OPENCTI_TOKEN`                                 | Yes        | The API token for OpenCTI.                                                                     |
| `CONNECTOR_ID`                          | `CONNECTOR_ID`                                  | Yes        | A unique UUIDv4 for this connector.                                                            |
| `CONNECTOR_TYPE`                        | `CONNECTOR_TYPE`                                | Yes        | Must be set to `STREAM` for this connector.                                                    |
| `CONNECTOR_NAME`                        | `CONNECTOR_NAME`                                | Yes        | Name of the connector, e.g., `ZscalerConnector`.                                               |
| `CONNECTOR_SCOPE`                       | `CONNECTOR_SCOPE`                               | Yes        | Set to `domain-name` to focus on domain indicators.                                            |
| `CONNECTOR_LOG_LEVEL`                   | `CONNECTOR_LOG_LEVEL`                           | No         | Logging level (`debug`, `info`, `warn`, or `error`).                                           |
| `CONNECTOR_LIVE_STREAM_ID`              | `CONNECTOR_LIVE_STREAM_ID`                      | Yes        | The ID of the OpenCTI Live Stream.                                                             |
| `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`           | Yes        | Whether to listen for deletions (`true` or `false`).                                           |
| `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES`         | Yes        | Disable dependency processing (`true` or `false`).                                             |
| `ZSCALER_API_KEY`                       | `ZSCALER_API_KEY`                               | Yes        | Zscaler API key.                                                                               |
| `ZSCALER_USERNAME`                      | `ZSCALER_USERNAME`                              | Yes        | Zscaler username.                                                                              |
| `ZSCALER_PASSWORD`                      | `ZSCALER_PASSWORD`                              | Yes        | Zscaler password.                                                                              |



## Usage

1. **Set Environment Variables**:  
   Configure the OpenCTI URL and token, as well as your Zscaler credentials (`ZSCALER_USERNAME`, `ZSCALER_PASSWORD`, and `ZSCALER_API_KEY`) as shown in the table above.  
2. **Configure the Category**:  
   By default, the connector uses the `BLACK_LIST_DYNDNS` category. If you want to use another list, modify the reference in the code (or environment variables depending on your implementation) to point to the Zscaler category that suits you (e.g., `'Black-list').  
   For use another list, you need to going in "connector.py" and modifiy the function "get_zscaler_blocked_domains" in end of the resquest API "https://zsapi.zscalertwo.net/api/v1/urlCategories/CUSTOM_07" replace "CUSTOM_O7" to your another list and you need also to replace request and the configure name in the function "send_to_zscaler" 
3. **Run the Connector**:  
   Once the Docker image is built or retrieved, run `docker-compose up -d` or an equivalent command. The connector will then connect to OpenCTI and, for every creation or deletion of a `domain-name` indicator, add or remove it from the specified list in Zscaler and activate the changes.

## Example Docker Compose

```yaml
version: '3'
services:
  connector-zscaler:
    image: opencti/connector-zscaler:latest
    environment:
      OPENCTI_URL: "https://your-opencti-instance.com"
      OPENCTI_TOKEN: "YOUR_OPENCTI_TOKEN"
      CONNECTOR_ID: "YOUR_CONNECTOR_UUID"
      CONNECTOR_TYPE: "STREAM"
      CONNECTOR_NAME: "ZscalerConnector"
      CONNECTOR_SCOPE: "domain-name"
      CONNECTOR_LOG_LEVEL: "info"
      CONNECTOR_LIVE_STREAM_ID: "YOUR_LIVE_STREAM_ID"
      CONNECTOR_LIVE_STREAM_LISTEN_DELETE: "true"
      CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES: "true"

      ZSCALER_USERNAME: "YOUR_ZSCALER_USERNAME"
      ZSCALER_PASSWORD: "YOUR_ZSCALER_PASSWORD"
      ZSCALER_API_KEY: "YOUR_ZSCALER_API_KEY"
    networks:
      - opencti_network

networks:
  opencti_network:
    external: true