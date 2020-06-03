# Connector: CYBERCRIME-TRACKER.NET for OpenCTI

The connector uses the RSS feed of the tracker under: http://cybercrime-tracker.net/rss.xml

It will parse all entries and:

* generate an indicator for each entry, indicating the related malware.
* add domain, url, IP address as observables into OpenCTI and create the corresponding relationships.
