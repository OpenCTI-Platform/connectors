# OpenCTI CrowdStrike Connector

OpenCTI CrowdStrike connector will use the CrowdStrike Intel APIs in following order:

1. Actors API

   Actors are imported as intrusion sets.

   Targeted industries are imported as sectors with intrusion set targets sector relationship.

   Targeted countries are imported as regions and countries (if *slug* > 2 then region) with intrusion set targets region or country relationship.

1. Reports API

   Reports are imported reports (*Threat Report* by default).

   Reported actors are imported as intrusion sets.

   Targeted industries are imported as sectors with intrusion set targets sector relationship.

   Targeted countries are imported as regions and countries (if *slug* > 2 then region) with intrusion set targets region or country relationship.

   **NB!** *STIX 2* does not allow an empty report object (i.e., if the report does not contain any object refereces) therefore a dummy organization "CS EMPTY REPORT" is added to the report in order import it to the OpenCTI.

1. Indicators API

   Indicators are imported as indicators.

   Associated actors are imported as intrusion sets.

   Associated malwares are imported as malwares with intrusion set uses malware relationship.

   Associated vulnerabilities are imported as vulnerabilities with intrusion set or malware uses vulnerability relationship.

   Targets are imported as sectors with intrusion set or malware targets sector relationship.

   Indicator indicates relationships is created between intrusion sets and malwares.

   Related reports are imported as reports (*Threat Report* by default).
