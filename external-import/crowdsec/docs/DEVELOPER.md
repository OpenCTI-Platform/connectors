![CrowdSec Logo](images/logo_crowdsec.png)
# OpenCTI CrowdSec external import connector

## Developer guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Local installation](#local-installation)
  - [Prepare local environment](#prepare-local-environment)
  - [Update OpenCTI `docker-compose.yml`](#update-opencti-docker-composeyml)
  - [Start Docker environment](#start-docker-environment)
  - [Stop Docker environment](#stop-docker-environment)
- [Unit tests](#unit-tests)
- [Update documentation table of contents](#update-documentation-table-of-contents)
- [OpenCTI Pull Request](#opencti-pull-request)
  - [Sync fork with upstream](#sync-fork-with-upstream)
  - [Update fork sources](#update-fork-sources)
    - [Create a release](#create-a-release)
    - [Retrieve zip for release](#retrieve-zip-for-release)
    - [Create a branch for the Pull Request](#create-a-branch-for-the-pull-request)
    - [Update sources](#update-sources)
    - [Test locally before pull request](#test-locally-before-pull-request)
    - [Open a Pull request](#open-a-pull-request)
  - [During the pull request review](#during-the-pull-request-review)
  - [Once pull request is merged](#once-pull-request-is-merged)
    - [Sync fork with upstream](#sync-fork-with-upstream-1)
    - [Retrieve last version](#retrieve-last-version)
    - [Create a new minor release](#create-a-new-minor-release)

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
└───connectors (do not change this folder name; Only needed for OpenCTI Pull Request process)
│   │
│   │ (Clone of https://github.com/crowdsecurity/connectors)
│
└───cs-opencti-external-import-connector (do not change this folder name)
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
git clone git@github.com:crowdsecurity/cs-opencti-external-import-connector.git
```



### Update OpenCTI `docker-compose.yml`

Copy the content of `dev/docker-compose-dev.yml` (start at `connector-crowdsec-import` and omit the `services` keyword) at the end of `docker/docker-compose.yml` and edit all `ChangeMe` values.

To generate a UUID, you may use `uuidgen` command if available.



### Start Docker environment

```
cd docker && docker compose up -d --build
```

Once all the containers have been started, you can enter the CrowdSec connector container to launch the python process responsible for enriching observables: 

```bash
docker exec -ti docker-connector-crowdsec-import-1 /bin/sh
```

(The name of container may vary, and you can find it by running the `docker ps` command)

Then: 

```bash
cd /opt/opencti-crowdsec-import/ && python3 main.py
```

You should see log messages, one of which contains `CrowdSec external import running ...`.

**N.B:** In development, we are using a specific Docker file that will not launch the main python process `main.py` on container start. 

That's why you have to launch it manually with `python3 main.py`.

Thanks to this, you can test any code modification by stopping the process (`CTRL+C` or similar), then restarting it (`python3 main.py`).



### Stop Docker environment

To stop all containers: 

```bash
docker compose down
```

To stop all containers and remove all data (if you want to come back to a fresh OpenCTI installation): 

```
docker compose down -v
```



## Unit tests

First, prepare your virtual environment:

```bash
source env/bin/activate
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



## OpenCTI Pull Request

To make an update publicly available, we need to submit a pull request to the [OpenCTI connectors repository](https://github.com/OpenCTI-Platform/connectors), and to submit a pull request, we use the CrowdSec [connectors fork](https://github.com/crowdsecurity/connectors).

### Sync fork with upstream

Before modifying the code of our fork, we need to sync it from the upstream repo. There are many way to do it. Below is what you can do locally.

Using your local connectors folder defined [above](#prepare-local-environment), you should define two Git remote: origin (the fork) and upstream (the OpenCTI repo).
You can check that with the following command: 

```shell
cd connectors
git remote -v
```

You should see the following result:

```
origin	git@github.com:crowdsecurity/connectors.git (fetch)
origin	git@github.com:crowdsecurity/connectors.git (push)
upstream	git@github.com:OpenCTI-Platform/connectors.git (fetch)
upstream	git@github.com:OpenCTI-Platform/connectors.git (push)
```



Once you have this, you can force update the fork master branch :

```shell
git checkout master
git fetch upstream
git reset --hard upstream/master
git push origin master --force 
```



### Update fork sources

#### Create a release

Before creating a release, ensure to format correctly the `CHANGELOG.md` file and to update the `src/crowdsec/client.py` to update the user agent with the next version number. Then, you can use the [Create Release action](https://github.com/crowdsecurity/cs-opencti-external-import-connector/actions/workflows/release.yml).

#### Retrieve zip for release

At the end of the Create Release action run, you can download a zip containing the relevant files.  

#### Create a branch for the Pull Request

If your release is `vX.Y.Z`, you can create a `feat/release-X-Y-Z` branch:

```shell
cd connectors
git checkout -b feat/release-X-Y-Z
```

#### Update sources

 Before all, remove all files in the CrowdSec connector folder:

```shell
cd connectors
rm -rf external-import/crowdsec/* external-import/crowdsec/.*
```

Then, unzip the `crowdsec-opencti-external-import-connector-X.Y.Z.zip` archive in the CrowdSec connector folder:

```shell
unzip /path/to/crowdsec-opencti-external-import-connector-X.Y.Z.zip -d external-import/crowdsec
```

Now, you can verify the diff and you will probably need to update OpenCTI version in `docker-compose.yml` and `src/requirements.txt` files.

Once all seems fine, add and commit your modifications:

```shell
git add .
git commit -m "[crowdsec] Update internal enrichment connector (vX.Y.Z)"
```

#### Test locally before pull request 

You can test with the docker local stack by using this kind of snippet in the `docker-compose.yml` file of your docker folder defined [above](#prepare-local-environment):

```yaml
connector-crowdsec-import:
    build:
      context: ../connectors/external-import/crowdsec/
      dockerfile: Dockerfile
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=35f117d3-508f-4306-ac18-01b8c3e741fd
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - "CONNECTOR_NAME=CrowdSec Import"
      - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr # MIME type or Stix Object
      - CONNECTOR_CONFIDENCE_LEVEL=100 # From 0 (Unknown) to 100 (Fully trusted)
      - CONNECTOR_LOG_LEVEL=debug
      - CROWDSEC_KEY=**************************** # Api Key
      - CROWDSEC_VERSION=v2 #v2 is the only supported version for now
    restart: always
    depends_on:
      - opencti
```

#### Open a Pull request

Push your modification 

```shell
git push origin git push origin feat/release-X.Y.Z
```

Now you can use the `feat/release-X.Y.Z` branch to open a pull request in the OpenCTI repository.
For the pull request description, you could use the release version description that you wrote in the `CHANGELOG.md` file.



### During the pull request review

As long as the pull request is in review state, we should not create a new release. 
If there are modifications to do, we can do it directly on the `feat/release-X.Y.Z`. 
All changes made to pass the pull request review must be back ported to a `feat/pr-review-X-Y-Z` branch created in this repository:

```shell
cd cs-opencti-external-import-connector
git checkout main
git checkout -b feat/pr-review-X.Y.Z
```


### Once pull request is merged

Once the connectors repository has merged our updates, and once OpenCTI has published a new release of connectors with the updates, 
we need to sync the merged `external-import/crowdsec` sources with this repo.

#### Sync fork with upstream

First, sync the connector fork like we did [here](#sync-fork-with-upstream). 

#### Retrieve last version

After this, you should have the last version of the CrowdSec internal enrichment connector in `connectors/external-import/crowdsec` folder.

You need to retrieve it and commit the differences.

```shell
cd cs-opencti-external-import-connector
git checkout feat/pr-review-X.Y.Z
```

Delete all folders except `.git` and `.github` folders (this 2 specific folders did not belongs to the release zip archive)

Copy all files from the connector's fork: 

```
cp -r ../connectors/external-import/crowdsec/. ./
```

Add and commit the result. Push the `feat/pr-review-X-Y-Z` and merge it into `main` with a pull request.


#### Create a new minor release

Once the `main` branch is updated, you can create a new minor `X.Y+1.0` release with the following CHANGELOG content:

```
## Changed

- Synchronize content with OpenCTI connector's release [A.B.C](https://github.com/OpenCTI-Platform/connectors/releases/tag/A.B.C)

```





 
