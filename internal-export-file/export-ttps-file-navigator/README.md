# OpenCTI Export MITRE ATT&CK Navigator

This connector allows exporting in the MITRE ATT&CK® format TTPs associated to STIX domain objects (SDOs) present in OpenCTI.
This connector export files according to version 4.5 of MITRE ATT&CK® layer model (see: https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md).


## How to use it

On any OpenCTI entity (SDO) associated to attack pattern objects, click on 'Generate Export' and select 'application/vnd.mitre.navigator+json' as export format.
Once the file is exported, download it and open it in MITRE ATT&CK® Navigator web-based tool.

## Current limitations

This Connector currently only export TTPs associated to the 'Enterprise Matrix' (kill chain name == 'mitre-attack' in OpenCTI). 
To manage Mobile and ICS matrices, an additional argument must be handled (at user or connector level).


