# OpenCTI ShadowTrackr Connector

This internal enrichment connector lowers the score for IP addresses that are 
false positives, and changes the valid until date for sources
that are known to change function regularly, like CDNs, Clouds and VPNs. 

If a newly ingested IP address is a CDN, Cloud or VPN it might still be a valid, 
ongoing attack that you'll want to detect or block. But chances are very high 
that the same IP is used for something different, legitimate purpose the next 
day. For this reason, this connector limits the valid to period instead of 
lowering the score. Notice that this check is done in context, together with 
the information on the false positive estimate: a GMail server will be detected
as a cloud server, but gets a lowered score immediately. You don't want to block
 GMail just because you got one spammy email.    

The score reduction is based on the false positive estimate produced by the 
ShadowTrackr API. Likewise, the CDN, Cloud and VPN information comes from 
the ShadowTrackr API. You'll need an API key to access the API.

The connector works for the following OpenCTI observable types:

* IPv4-Addr
* IPv6-Addr
* Indicator

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-shadowtrackr:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

| Parameter            	     | Docker envvar                           | Mandatory | Description                                                             |
|----------------------------|-----------------------------------------|-----------|-------------------------------------------------------------------------|
| `replace_with_lower_score` | `SHADOWTRACKR_REPLACE_WITH_LOWER_SCORE` | Yes       | Lower the score based on the ShadowTrackr false positive estimate value |
| `api_key`                  | `SHADOWTRACKR_API_KEY`                  | Yes       | Get one here: https://shadowtrackr.com/usr/                             |                                                                   |
| `replace_valid_to_date`    | `SHADOWTRACKR_REPLACE_VALID_TO_DATE`    | Yes       | Set the valid to date to tomorrow for CDNs, Clouds and VPNs             |
| `max_tlp`                  | `SHADOWTRACKR_MAX_TLP`                  | No        | Don't send anything above this TLP to ShadowTrackr                      |

## Behavior

1. Adds labels to items if applicable: "cdn", "cloud", "vpn", "tor", "public dns server", "bogon"
2. Lowers the score on likely false positives, and adds the reason to the description field
3. Sets the valid_to time to tomorrow for items that are known CDNs, Clouds or VPNs (with a notice in the description)

This connector works on both Observables and Indicators, but only if they are ip addresses. In its most basic form, 
you run this connector with replace_with_lower_score=False and replace_valid_to_date=False. It will then only add labels
to your Observables and Indicators. If you use OpenCTI for detection or blocking and  want to automagically reduce 
the number of false positives, you should set both to True.
