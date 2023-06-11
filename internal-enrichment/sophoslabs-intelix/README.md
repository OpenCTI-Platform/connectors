# SophosLabs Intelix OpenCTI Connector
This is an OpenCTI Connector for Data Enrichment for IP, SHA256 and Domain Lookup, powered by [SophosLabs Intelix](https://api.labs.sophos.com/doc/index.html). 
Before a pull request is submitted to the [OpenCTI Project](https://github.com/OpenCTI-Platform/connectors) we're looking for public beta testers, any issues, or desired changes please log an issue.

## Setup

 1. Register for the API Credentials in the AWS Market Place, instructions can be found [here](https://api.labs.sophos.com/doc/index.html#registration-howto).
 2. If you're using Portainer to manage your OpenCTI Stack add the container to the docker-compose stack using [this](https://gist.github.com/0xbennyv/d53a770658cb53ea3b3fd2d429d82a3b).
	 - INTELIX_CLIENT_ID=From_Step_1
	 - INTELIX_CLIENT_SECRET=From_Step_1
	 - INTELIX_REGION_URI=https://us.api.labs.sophos.com
	 - INTELIX_SCOPE=Url,IPv4-Addr,Artifact
 3. If you're using docker-compose without portainer to manage the OpenCTI Stack the process is the same however, instead of adding the environment variables replace the below values with the required information.
	 - ${INTELIX_CLIENT_ID}
	 - ${INTELIX_CLIENT_SECRET}
	 - ${INTELIX_REGION_URI}
	 - ${INTELIX_SCOPE}

# Additional Information
SophosLabs Intelix has a generous free tier for data lookup, as such the connector has auto lookup enabled by default. You can change CONNECTOR_AUTO=False to make it a manual process.
