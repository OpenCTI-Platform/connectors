# OpenCTI Hygiene Connector

this is an internal enrichment connector that uses the following external
projects to look for oberservable values in the database that you might want to
delete / decay because they are known to lead to alse-positives when used for
detection:

* [misp-warninglists](https://github.com/MISP/misp-warninglists)

The connector works for the following OpenCTI observable types:

* IPv4-Addr
* IPv6-Addr
* Domain-Name
* StixFile
* Artifact

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-hygiene:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

| Parameter            	     | Docker envvar                      | Mandatory | Description                                                                                                                           |
| -------------------------- | ---------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `warninglists_slow_search` | `HYGIENE_WARNINGLISTS_SLOW_SEARCH` | No        | Enable slow search mode for the warning lists. If true, uses the most appropriate search method. Can be slower. Default: exact match. |

## Behavior

1. Adds a `Hygiene` label on items that correspond to a warning list entry.
2. Adds an external reference for every matching warning list.
3. Sets the score of all related indicators to a value based on the number of
   reported entries (1:15, >=3:10, >=5:5, default:20).
