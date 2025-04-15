![CrowdSec Logo](images/logo_crowdsec.png)
# OpenCTI CrowdSec internal enrichment connector

## Developer guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Local installation](#local-installation)
  - [Prepare local environment](#prepare-local-environment)
  - [Update OpenCTI `docker-compose.yml`](#update-opencti-docker-composeyml)
  - [Start Docker environment](#start-docker-environment)
  - [Stop Docker environment](#stop-docker-environment)
- [Unit tests](#unit-tests)
- [Update documentation table of contents](#update-documentation-table-of-contents)
- [Release process](#release-process)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Local installation



### Prepare local environment

The final structure of the project will look like below.

```markdown
crowdsec-opencti (choose the name you want for this folder)
│       
│
└───docker
│   │   
│   │ (Clone of https://github.com/OpenCTI-Platform/docker)
│   
└───cs-opencti-internal-enrichment-connector (do not change this folder name)
    │   
    │ (Clone of this repo)

```

- Create an empty folder that will contain all necessary sources:
```bash
mkdir crowdsec-opencti && cd crowdsec-opencti
```

- Clone the OpenCTI docker repository:

```bash
git clone git@github.com:OpenCTI-Platform/docker.git
```

- Clone this repository:

``` bash
git clone git@github.com:crowdsecurity/cs-opencti-internal-enrichment-connector.git
```



### Update OpenCTI `docker-compose.yml`

Copy the content of `dev/docker-compose-dev.yml` (start at `connector-crowdsec` and omit the `services` keyword) at the end of `docker/docker-compose.yml` and edit all `ChangeMe` values.

To generate a UUID, you may use `uuidgen` command if available.



### Start Docker environment

```
cd docker && docker-compose up -d --build
```

Once all the containers have been started, you can enter the CrowdSec connector container to launch the python process responsible for enriching observables: 

```bash
docker exec -ti docker_connector-crowdsec_1 /bin/sh
```

(The name of container may vary and you can find it by running the `docker ps` command)

Then: 

```bash
cd /opt/opencti-crowdsec/ && python3 main.py
```

You should see log messages, one of which contains `CrowdSec enrichment connector started`.

**N.B:** In development, we are using a specific Docker file that will not launch the main python process `main.py` on container start. 

That's why you have to launch it manually with `python3 main.py`.

Thanks to this, you can test any code modification by stopping the process (`CTRL+C` or similar), then restarting it (`python3 main.py`).



### Stop Docker environment

To stop all containers: 

```bash
docker-compose down
```

To stop all containers and remove all data (if you want to come back to a fresh OpenCTI installation): 

```
docker-compose down -v
```



## Unit tests

First, prepare your virtual environment:

```bash
source src/env/bin/activate
python -m pip install --upgrade pip
python -m pip install -r tests/test-requirements.txt
```

Then, run tests: 

```bash
python -m pytest -v
```

## Update documentation table of contents

To update the table of contents in the documentation, you can use [the `doctoc` tool](https://github.com/thlorenz/doctoc).

First, install it:

```bash
npm install -g doctoc
```

Then, run it in the documentation folder:

```bash
doctoc docs/*
```



## Release process



 
