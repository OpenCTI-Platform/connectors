# OpenCTI DomainTools Connector

The OpenCTI DomainTools connector can be used to import knowledge from the [DomainTools API](https://www.domaintools.com/). This connector uses the [Domain Tools Official Python API](https://github.com/DomainTools/python_api).

The connector enrich the domain and ip with other domains, ips, email addresses and autonomous systems. 

## Configuration

The connector can be configured with the following variables: 

| Config Parameter          | Docker env var                        | Default    | Description                                                      |
|---------------------------|---------------------------------------|------------|------------------------------------------------------------------|
| `api_username`            | `DOMAINTOOLS_API_USERNAME`            | `ChangeMe` | The username required for the authentication on DomainTools API. |
| `api_key`                 | `DOMAINTOOLS_API_KEY`                 | `ChangeMe` | The password required for the authentication on DomainTools API. |
