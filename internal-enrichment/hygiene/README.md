# OpenCTI Hygiene Connector

This is an internal enrichment connector that uses the following external
projects to look for observable values in the database that you might want to
delete / decay because they are known to lead to false-positives when used for
detection:

* [misp-warninglists](https://github.com/MISP/misp-warninglists)

The connector works for the following OpenCTI observable types:

* IPv4-Addr
* IPv6-Addr
* Domain-Name
* StixFile
* Artifact

And works also for the Indicators based on these observables types.

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-hygiene:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

| Parameter            	      | Docker envvar                      | Mandatory | Description                                                                                                                                                                 |
|-----------------------------|------------------------------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `warninglists_slow_search`  | `HYGIENE_WARNINGLISTS_SLOW_SEARCH` | No        | Enable slow search mode for the warning lists. If true, uses the most appropriate search method. Can be slower. Default: exact match.                                       |
| `label_name`                | `HYGIENE_LABEL_NAME`               | No        | Set the label name. The default is`hygiene`.                                                                                                                                |
| `label_parent_name`         | `HYGIENE_LABEL_PARENT_NAME`        | No        | Label name to be used when enriching sub-domains, by default `hygiene_parent`.                                                                                              |
| `label_color`               | `HYGIENE_LABEL_COLOR`              | No        | Color to use for the label, by default `#fc0341`.                                                                                                                           |
| `label_parent_color`        | `HYGIENE_LABEL_PARENT_COLOR`       | No        | Color to use for the label when enriching subdomains, by default `#fc0341`.                                                                                                 |                                                                                                                                            |
| `enrich_subdomains`         | `HYGIENE_ENRICH_SUBDOMAINS`        | No        | Enable enrichment of sub-domains, This option will add "hygiene_parent" label and ext refs of the parent domain to the subdomain, if sub-domain is not found but parent is. |

## Behavior

1. Adds a `hygiene` or `hygiene_parent` label by default on items that correspond to a warning list entry. These are configurable(both color and label name)
2. Sets the score of all related indicators to a value based on the number of
   reported entries (1:15, >=3:10, >=5:5, default:20).
